use anyhow::{Result, anyhow, bail};
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

use crate::crypto::{AEAD_OVERHEAD, AeadKey, nonce_for_sequence, random_bytes, random_range};

pub const RECORD_HANDSHAKE: u8 = 0x16;
pub const RECORD_APPDATA: u8 = 0x17;
pub const RECORD_HEADER_SIZE: usize = 5;
pub const FRAME_HEADER_SIZE: usize = 3;
pub const MAX_FRAME_PAYLOAD: usize = 16384 - 1;
pub const MAX_RECORD_BODY: usize = 16384 + 256;

pub const FRAME_READY: u8 = 0;
pub const FRAME_DATA: u8 = 1;
pub const FRAME_CLOSE: u8 = 2;

pub const HANDLER_CLIENT_HELLO: u8 = 0x01;
pub const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

pub const fn max_record_body() -> usize {
    MAX_RECORD_BODY
}

pub fn valid_record_header(header: &[u8], length: usize) -> bool {
    header.len() == RECORD_HEADER_SIZE
        && (0x14..=RECORD_APPDATA).contains(&header[0])
        && header[1] == 0x03
        && (0x01..=0x04).contains(&header[2])
        && length <= MAX_RECORD_BODY
}

pub fn record_length(header: &[u8]) -> Option<usize> {
    if header.len() < RECORD_HEADER_SIZE
        || !(0x14..=RECORD_APPDATA).contains(&header[0])
        || header[1] != 0x03
        || !(0x01..=0x04).contains(&header[2])
    {
        return None;
    }
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    (length <= MAX_RECORD_BODY).then_some(RECORD_HEADER_SIZE + length)
}

pub fn is_possible_record_prefix(prefix: &[u8]) -> bool {
    if prefix.is_empty() || prefix.len() >= RECORD_HEADER_SIZE {
        return false;
    }
    if !(0x14..=RECORD_APPDATA).contains(&prefix[0]) {
        return false;
    }
    if prefix.len() >= 2 && prefix[1] != 0x03 {
        return false;
    }
    if prefix.len() >= 3 && !(0x01..=0x04).contains(&prefix[2]) {
        return false;
    }
    true
}

fn frame_padding(
    payload_length: usize,
    data_frame: u64,
    ready: bool,
    data: bool,
    max_padding: usize,
) -> Result<Vec<u8>> {
    let (minimum, maximum) = match () {
        _ if ready => (0, max_padding.min(1024)),
        _ if data && data_frame < 8 && payload_length < 900 => {
            let minimum = (900 - FRAME_HEADER_SIZE).saturating_sub(payload_length);
            let maximum = (1400 - FRAME_HEADER_SIZE).saturating_sub(payload_length);
            (
                minimum.min(max_padding),
                maximum.max(minimum).min(max_padding),
            )
        }
        _ if data && data_frame < 8 => (0, max_padding.min(255)),
        _ => (0, 0),
    };
    if maximum < minimum {
        return Ok(Vec::new());
    }
    Ok(random_bytes(random_range(minimum, maximum)))
}

pub struct EncryptedReader {
    io: BufReader<TcpStream>,
    recv: AeadKey,
    recv_sequence: u64,
    pending: Vec<u8>,
    eof: bool,
}

impl EncryptedReader {
    pub fn read_frame(&mut self, skip_foreign: bool) -> Result<(u8, Vec<u8>)> {
        loop {
            let mut header = [0_u8; RECORD_HEADER_SIZE];
            self.io
                .read_exact(&mut header)
                .map_err(|error| anyhow!("read TLS record header: {error}"))?;
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            if !valid_record_header(&header, length) {
                bail!("invalid TLS record header");
            }
            let mut body = vec![0_u8; length];
            self.io
                .read_exact(&mut body)
                .map_err(|error| anyhow!("read TLS record body: {error}"))?;

            let nonce = nonce_for_sequence(self.recv_sequence);
            match self.recv.open(&nonce, &body, &header) {
                Ok(plain) => {
                    self.recv_sequence += 1;
                    if plain.len() < FRAME_HEADER_SIZE {
                        bail!("short encrypted frame");
                    }
                    let payload_length = u16::from_be_bytes([plain[1], plain[2]]) as usize;
                    if payload_length > plain.len() - FRAME_HEADER_SIZE {
                        bail!("invalid frame payload length");
                    }
                    let payload =
                        plain[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_length].to_vec();
                    return Ok((plain[0], payload));
                }
                Err(error) => {
                    if skip_foreign {
                        // Destination TLS records, such as NewSessionTicket, can
                        // appear between the real handshake and the mio ready frame.
                        continue;
                    }
                    return Err(error);
                }
            }
        }
    }

    pub fn wait_ready(&mut self) -> Result<Vec<u8>> {
        let (kind, payload) = self.read_frame(true)?;
        if kind != FRAME_READY {
            bail!("unexpected frame before ready");
        }
        Ok(payload)
    }

    pub fn rekey(&mut self, recv: AeadKey) {
        self.recv = recv;
        self.recv_sequence = 0;
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.io.get_ref().set_read_timeout(timeout)
    }
}

impl Read for EncryptedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        while self.pending.is_empty() {
            if self.eof {
                return Ok(0);
            }
            let (kind, payload) = self.read_frame(false).map_err(io::Error::other)?;
            match kind {
                FRAME_DATA => self.pending = payload,
                FRAME_CLOSE => self.eof = true,
                _ => continue,
            }
        }
        let length = self.pending.len().min(buffer.len());
        buffer[..length].copy_from_slice(&self.pending[..length]);
        self.pending.drain(..length);
        Ok(length)
    }
}

pub struct EncryptedWriter {
    stream: TcpStream,
    send: AeadKey,
    send_sequence: u64,
    send_data_frames: u64,
    write_pending: Vec<u8>,
    next_padding: Option<(usize, usize)>,
}

impl EncryptedWriter {
    pub fn write_frame(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_FRAME_PAYLOAD {
            bail!("frame payload too large");
        }
        let max_padding =
            MAX_RECORD_BODY.saturating_sub(AEAD_OVERHEAD + FRAME_HEADER_SIZE + payload.len());
        let padding = if kind == FRAME_DATA {
            if let Some((minimum, maximum)) = self.next_padding.take() {
                let minimum = minimum.min(max_padding);
                let maximum = maximum.min(max_padding).max(minimum);
                random_bytes(random_range(minimum, maximum))
            } else {
                frame_padding(
                    payload.len(),
                    self.send_data_frames,
                    false,
                    true,
                    max_padding,
                )?
            }
        } else {
            frame_padding(
                payload.len(),
                self.send_data_frames,
                kind == FRAME_READY,
                false,
                max_padding,
            )?
        };

        let mut plain = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len() + padding.len());
        plain.push(kind);
        plain.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        plain.extend_from_slice(payload);
        plain.extend_from_slice(&padding);

        let body_length = plain.len() + AEAD_OVERHEAD;
        if body_length > u16::MAX as usize {
            bail!("encrypted record body too large");
        }
        let header = [
            RECORD_APPDATA,
            0x03,
            0x03,
            (body_length >> 8) as u8,
            body_length as u8,
        ];
        let nonce = nonce_for_sequence(self.send_sequence);
        let body = self.send.seal(&nonce, &plain, &header);
        self.send_sequence += 1;
        if kind == FRAME_DATA {
            self.send_data_frames += 1;
        }

        let mut record = Vec::with_capacity(RECORD_HEADER_SIZE + body.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&body);
        write_all(&mut self.stream, &record)?;
        Ok(())
    }

    pub fn flush_write_buffer(&mut self, closing: bool) -> io::Result<()> {
        while !self.write_pending.is_empty() {
            if self.write_pending.len() < RECORD_HEADER_SIZE {
                if !closing && is_possible_record_prefix(&self.write_pending) {
                    return Ok(());
                }
                let length = self.write_pending.len();
                self.write_encrypted_pending(length)?;
                continue;
            }

            if let Some(record_length) = record_length(&self.write_pending) {
                if self.write_pending.len() < record_length {
                    if !closing {
                        return Ok(());
                    }
                    let length = self.write_pending.len();
                    self.write_encrypted_pending(length)?;
                    continue;
                }
                self.write_encrypted_pending(record_length)?;
                continue;
            }

            let length = self.write_pending.len().min(MAX_FRAME_PAYLOAD);
            self.write_encrypted_pending(length)?;
        }
        Ok(())
    }

    fn write_encrypted_pending(&mut self, length: usize) -> io::Result<()> {
        let chunk: Vec<u8> = self.write_pending.drain(..length).collect();
        for part in chunk.chunks(MAX_FRAME_PAYLOAD) {
            self.write_frame(FRAME_DATA, part)
                .map_err(io::Error::other)?;
        }
        Ok(())
    }

    pub fn close_write(&mut self) -> io::Result<()> {
        self.flush_write_buffer(true)?;
        self.write_frame(FRAME_CLOSE, &[])
            .map_err(io::Error::other)?;
        self.stream.shutdown(Shutdown::Write)
    }

    pub fn rekey(&mut self, send: AeadKey) {
        self.send = send;
        self.send_sequence = 0;
    }

    pub fn set_next_padding(&mut self, minimum: usize, maximum: usize) {
        self.next_padding = Some((minimum, maximum));
    }
}

impl Write for EncryptedWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.write_pending.extend_from_slice(buffer);
        self.flush_write_buffer(false)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_write_buffer(true)?;
        self.stream.flush()
    }
}

pub struct EncryptedStream {
    reader: EncryptedReader,
    writer: EncryptedWriter,
}

impl EncryptedStream {
    pub fn new(stream: TcpStream, send: AeadKey, recv: AeadKey) -> io::Result<Self> {
        let writer_stream = stream.try_clone()?;
        Ok(Self::from_reader(
            BufReader::new(stream),
            writer_stream,
            send,
            recv,
        ))
    }

    pub fn from_reader(
        reader: BufReader<TcpStream>,
        writer_stream: TcpStream,
        send: AeadKey,
        recv: AeadKey,
    ) -> Self {
        Self {
            reader: EncryptedReader {
                io: reader,
                recv,
                recv_sequence: 0,
                pending: Vec::new(),
                eof: false,
            },
            writer: EncryptedWriter {
                stream: writer_stream,
                send,
                send_sequence: 0,
                send_data_frames: 0,
                write_pending: Vec::new(),
                next_padding: None,
            },
        }
    }

    pub fn wait_ready(&mut self) -> Result<Vec<u8>> {
        self.reader.wait_ready()
    }

    pub fn write_frame(&mut self, kind: u8, payload: &[u8]) -> Result<()> {
        self.writer.write_frame(kind, payload)
    }

    pub fn set_next_padding(&mut self, minimum: usize, maximum: usize) {
        self.writer.set_next_padding(minimum, maximum);
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.reader.set_read_timeout(timeout)
    }

    pub fn rekey(&mut self, send: AeadKey, recv: AeadKey) {
        self.writer.rekey(send);
        self.reader.rekey(recv);
    }

    pub fn split(self) -> (EncryptedReader, EncryptedWriter) {
        (self.reader, self.writer)
    }
}

impl Read for EncryptedStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer)
    }
}

impl Write for EncryptedStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writer.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub fn write_all<W: Write>(writer: &mut W, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = writer.write(bytes)?;
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write returned 0"));
        }
        bytes = &bytes[written..];
    }
    Ok(())
}

/// Forward raw TLS records until the callback consumes one as a mio authentication record.
pub fn copy_records<R: Read, W: Write, F: FnMut(&[u8], &[u8]) -> bool>(
    destination: &mut W,
    source: &mut BufReader<R>,
    mut inspect: F,
) -> io::Result<bool> {
    let mut header = [0_u8; RECORD_HEADER_SIZE];
    loop {
        match source.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(error) => return Err(error),
        }
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if !valid_record_header(&header, length) {
            destination.write_all(&header)?;
            io::copy(source, destination)?;
            return Ok(false);
        }

        let mut record = vec![0_u8; RECORD_HEADER_SIZE + length];
        record[..RECORD_HEADER_SIZE].copy_from_slice(&header);
        let mut read = 0;
        while read < length {
            match source.read(&mut record[RECORD_HEADER_SIZE + read..]) {
                Ok(0) => {
                    destination.write_all(&record[..RECORD_HEADER_SIZE + read])?;
                    return Ok(false);
                }
                Ok(count) => read += count,
                Err(error) => {
                    destination.write_all(&record[..RECORD_HEADER_SIZE + read])?;
                    return Err(error);
                }
            }
        }
        if inspect(&header, &record[RECORD_HEADER_SIZE..]) {
            return Ok(true);
        }
        destination.write_all(&record)?;
    }
}

pub trait CloseWrite {
    fn close_write(&mut self) -> io::Result<()>;
}

impl CloseWrite for TcpStream {
    fn close_write(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
}

impl CloseWrite for EncryptedWriter {
    fn close_write(&mut self) -> io::Result<()> {
        EncryptedWriter::close_write(self)
    }
}

pub fn relay(left: TcpStream, right: EncryptedStream) -> io::Result<()> {
    let (reader, writer) = right.split();
    relay_halves(left, reader, writer)
}

pub fn relay_halves<R, W>(
    left: TcpStream,
    mut right_reader: R,
    mut right_writer: W,
) -> io::Result<()>
where
    R: Read + Send,
    W: Write + CloseWrite + Send,
{
    let left_read = left.try_clone()?;
    std::thread::scope(|scope| {
        let left_to_right = scope.spawn(move || {
            let mut source = left_read;
            copy_half(&mut source, &mut right_writer)
        });
        let mut left_write = left;
        let right_to_left = scope.spawn(move || copy_half(&mut right_reader, &mut left_write));
        let first = left_to_right.join().unwrap();
        let second = right_to_left.join().unwrap();
        first.and(second)
    })
}

fn copy_half<R: Read, W: Write + CloseWrite>(
    source: &mut R,
    destination: &mut W,
) -> io::Result<()> {
    match io::copy(source, destination) {
        Ok(_) => destination.close_write(),
        Err(error) => Err(error),
    }
}

pub const ADDR_IPV4: u8 = 1;
pub const ADDR_DOMAIN: u8 = 3;
pub const ADDR_IPV6: u8 = 4;
pub const REPLY_OK: u8 = 0;
pub const REPLY_FAIL: u8 = 1;

pub fn write_request<W: Write>(writer: &mut W, target: &str) -> Result<()> {
    let (host, port) = split_host_port(target)?;
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow!("invalid target port {port:?}"))?;
    let mut bytes = Vec::with_capacity(1 + host.len() + 3);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        match ip {
            std::net::IpAddr::V4(ip) => {
                bytes.push(ADDR_IPV4);
                bytes.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                bytes.push(ADDR_IPV6);
                bytes.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if host.is_empty() || host.len() > 255 {
            bail!("invalid target host");
        }
        bytes.push(ADDR_DOMAIN);
        bytes.push(host.len() as u8);
        bytes.extend_from_slice(host.as_bytes());
    }
    bytes.extend_from_slice(&port.to_be_bytes());
    writer.write_all(&bytes)?;
    Ok(())
}

pub fn read_request<R: Read>(reader: &mut R) -> Result<String> {
    let mut kind = [0_u8; 1];
    reader.read_exact(&mut kind)?;
    let host = match kind[0] {
        ADDR_IPV4 => {
            let mut octets = [0_u8; 4];
            reader.read_exact(&mut octets)?;
            std::net::Ipv4Addr::from(octets).to_string()
        }
        ADDR_IPV6 => {
            let mut octets = [0_u8; 16];
            reader.read_exact(&mut octets)?;
            std::net::Ipv6Addr::from(octets).to_string()
        }
        ADDR_DOMAIN => {
            let mut length = [0_u8; 1];
            reader.read_exact(&mut length)?;
            if length[0] == 0 {
                bail!("empty target domain");
            }
            let mut name = vec![0_u8; length[0] as usize];
            reader.read_exact(&mut name)?;
            String::from_utf8(name).map_err(|_| anyhow!("target domain is not UTF-8"))?
        }
        other => bail!("unknown target address type {other}"),
    };
    let mut port = [0_u8; 2];
    reader.read_exact(&mut port)?;
    Ok(format!(
        "{}:{}",
        format_host(&host),
        u16::from_be_bytes(port)
    ))
}

pub fn write_reply<W: Write>(writer: &mut W, success: bool) -> io::Result<()> {
    writer.write_all(&[if success { REPLY_OK } else { REPLY_FAIL }])
}

pub fn read_reply<R: Read>(reader: &mut R) -> Result<bool> {
    let mut status = [0_u8; 1];
    reader.read_exact(&mut status)?;
    Ok(status[0] == REPLY_OK)
}

pub fn split_host_port(target: &str) -> Result<(&str, &str)> {
    if let Some(stripped) = target.strip_prefix('[') {
        let (host, rest) = stripped
            .split_once(']')
            .ok_or_else(|| anyhow!("invalid target address"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow!("target address is missing a port"))?;
        return Ok((host, port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("target address is missing a port"))?;
    Ok((host, port))
}

fn format_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::transport_keys;
    use std::net::TcpListener;
    use std::thread;

    fn keys(is_client: bool) -> (AeadKey, AeadKey) {
        transport_keys(&[3_u8; 32], None, &[1_u8; 32], &[2_u8; 32], is_client).unwrap()
    }

    #[test]
    fn encrypted_stream_round_trip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (client_send, client_recv) = keys(true);
        let (server_send, server_recv) = keys(false);

        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut encrypted = EncryptedStream::new(stream, server_send, server_recv).unwrap();
            let mut received = [0_u8; 5];
            encrypted.read_exact(&mut received).unwrap();
            assert_eq!(&received, b"hello");
            encrypted.write_all(b"world").unwrap();
            encrypted.flush().unwrap();
        });

        let stream = TcpStream::connect(addr).unwrap();
        let mut encrypted = EncryptedStream::new(stream, client_send, client_recv).unwrap();
        encrypted.write_all(b"hello").unwrap();
        encrypted.flush().unwrap();
        let mut received = [0_u8; 5];
        encrypted.read_exact(&mut received).unwrap();
        assert_eq!(&received, b"world");
        server.join().unwrap();
    }

    #[test]
    fn request_round_trip() {
        for target in ["example.com:443", "127.0.0.1:80", "[2001:db8::1]:8443"] {
            let mut bytes = Vec::new();
            write_request(&mut bytes, target).unwrap();
            assert_eq!(read_request(&mut bytes.as_slice()).unwrap(), target);
        }
    }

    #[test]
    fn record_helpers() {
        let mut record = vec![RECORD_APPDATA, 3, 3, 0, 4, 1, 2, 3, 4];
        assert_eq!(record_length(&record), Some(9));
        record[3..5].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(record_length(&record), None);
    }
}
