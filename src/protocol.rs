use anyhow::{Result, anyhow, bail};
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};

pub const RECORD_HANDSHAKE: u8 = 0x16;
pub const RECORD_APPDATA: u8 = 0x17;
pub const RECORD_HEADER_SIZE: usize = 5;
pub const MAX_RECORD_BODY: usize = 16384 + 256;

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

/// How a relay should handle one TLS record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordAction {
    /// Forward the record and keep parsing later records.
    Forward,
    /// Consume the record as a mio authentication record and stop relaying.
    Claim,
    /// Forward the record and relay the remaining bytes without parsing.
    Passthrough,
}

/// Why `copy_records` stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CopyOutcome {
    /// The source ended cleanly (including after a partial final record).
    EndOfStream,
    /// The callback claimed a record as mio authentication.
    Claimed,
}

/// Forward raw TLS records until the callback consumes one as a mio authentication record.
pub fn copy_records<R: Read, W: Write, F: FnMut(&[u8], &[u8]) -> RecordAction>(
    destination: &mut W,
    source: &mut BufReader<R>,
    inspect: F,
) -> io::Result<CopyOutcome> {
    copy_records_cancellable(destination, source, inspect, None)
}

/// Like [`copy_records`], but a locally-initiated close suppresses forwarding of a
/// partial final record. Peer EOF still forwards those bytes so a legitimate truncated
/// tail is propagated.
pub fn copy_records_cancellable<R: Read, W: Write, F: FnMut(&[u8], &[u8]) -> RecordAction>(
    destination: &mut W,
    source: &mut BufReader<R>,
    mut inspect: F,
    locally_closed: Option<&AtomicBool>,
) -> io::Result<CopyOutcome> {
    let mut header = [0_u8; RECORD_HEADER_SIZE];
    loop {
        let (read, error) = read_up_to(source, &mut header);
        if read != header.len() {
            if read > 0
                && error.is_none()
                && !locally_closed.is_some_and(|closed| closed.load(Ordering::Acquire))
            {
                destination.write_all(&header[..read])?;
            }
            return match error {
                Some(error) => Err(error),
                None => Ok(CopyOutcome::EndOfStream),
            };
        }
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        if !valid_record_header(&header, length) {
            destination.write_all(&header)?;
            io::copy(source, destination)?;
            return Ok(CopyOutcome::EndOfStream);
        }

        let mut record = vec![0_u8; RECORD_HEADER_SIZE + length];
        record[..RECORD_HEADER_SIZE].copy_from_slice(&header);
        let (read, error) = read_up_to(source, &mut record[RECORD_HEADER_SIZE..]);
        if read != length {
            if error.is_none()
                && !locally_closed.is_some_and(|closed| closed.load(Ordering::Acquire))
            {
                destination.write_all(&record[..RECORD_HEADER_SIZE + read])?;
            }
            return match error {
                Some(error) => Err(error),
                None => Ok(CopyOutcome::EndOfStream),
            };
        }
        let action = inspect(&header, &record[RECORD_HEADER_SIZE..]);
        if action == RecordAction::Claim {
            return Ok(CopyOutcome::Claimed);
        }
        destination.write_all(&record)?;
        if action == RecordAction::Passthrough {
            io::copy(source, destination)?;
            return Ok(CopyOutcome::EndOfStream);
        }
    }
}

fn read_up_to<R: Read>(source: &mut R, buffer: &mut [u8]) -> (usize, Option<io::Error>) {
    let mut read = 0;
    while read < buffer.len() {
        match source.read(&mut buffer[read..]) {
            Ok(0) => break,
            Ok(count) => read += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return (read, None),
            Err(error) => return (read, Some(error)),
        }
    }
    (read, None)
}

pub trait CloseWrite {
    fn close_write(&mut self) -> io::Result<()>;
}

impl CloseWrite for TcpStream {
    fn close_write(&mut self) -> io::Result<()> {
        self.shutdown(Shutdown::Write)
    }
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

pub const ADDR_UDP_ASSOCIATE: u8 = 0;
pub const ADDR_IPV4: u8 = 1;
pub const ADDR_DOMAIN: u8 = 3;
pub const ADDR_IPV6: u8 = 4;
pub const REPLY_OK: u8 = 0;
pub const REPLY_FAIL: u8 = 1;
pub const MAX_DATAGRAM_SIZE: usize = 65_504;
const MIN_DATAGRAM_SIZE: usize = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamRequest {
    Tcp(String),
    UdpAssociate,
}

impl StreamRequest {
    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Self::Tcp(target) => write_request(writer, target),
            Self::UdpAssociate => {
                writer.write_all(&[ADDR_UDP_ASSOCIATE])?;
                Ok(())
            }
        }
    }
}

pub fn read_stream_request<R: Read>(reader: &mut R) -> Result<StreamRequest> {
    let mut kind = [0_u8; 1];
    reader.read_exact(&mut kind)?;
    match kind[0] {
        ADDR_UDP_ASSOCIATE => Ok(StreamRequest::UdpAssociate),
        other => Ok(StreamRequest::Tcp(read_target(reader, other)?)),
    }
}

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
    read_target(reader, kind[0])
}

fn read_target<R: Read>(reader: &mut R, kind: u8) -> Result<String> {
    let host = match kind {
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

pub fn write_datagram<W: Write>(writer: &mut W, datagram: &[u8]) -> Result<()> {
    if !(MIN_DATAGRAM_SIZE..=MAX_DATAGRAM_SIZE).contains(&datagram.len()) {
        bail!("invalid mio UDP datagram size");
    }
    let mut header = [0_u8; 2];
    header.copy_from_slice(&(datagram.len() as u16).to_be_bytes());
    writer.write_all(&header)?;
    writer.write_all(datagram)?;
    Ok(())
}

pub fn read_datagram<'a, R: Read>(reader: &mut R, buffer: &'a mut [u8]) -> Result<&'a [u8]> {
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header)?;
    let size = u16::from_be_bytes(header) as usize;
    if !(MIN_DATAGRAM_SIZE..=MAX_DATAGRAM_SIZE).contains(&size) || size > buffer.len() {
        bail!("invalid mio UDP datagram size");
    }
    reader.read_exact(&mut buffer[..size])?;
    Ok(&buffer[..size])
}

pub fn parse_datagram(datagram: &[u8]) -> Result<(String, &[u8])> {
    let mut cursor = std::io::Cursor::new(datagram);
    let mut kind = [0_u8; 1];
    cursor.read_exact(&mut kind)?;
    if kind[0] == ADDR_UDP_ASSOCIATE {
        bail!("invalid UDP datagram address type");
    }
    let endpoint = read_target(&mut cursor, kind[0])?;
    let consumed = cursor.position() as usize;
    Ok((endpoint, &datagram[consumed..]))
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

    #[test]
    fn request_round_trip() {
        for target in ["example.com:443", "127.0.0.1:80", "[2001:db8::1]:8443"] {
            let mut bytes = Vec::new();
            write_request(&mut bytes, target).unwrap();
            assert_eq!(read_request(&mut bytes.as_slice()).unwrap(), target);
        }
    }

    #[test]
    fn stream_request_and_datagram_round_trip() {
        let request = StreamRequest::Tcp("example.com:53".to_string());
        let mut bytes = Vec::new();
        request.write_to(&mut bytes).unwrap();
        assert_eq!(read_stream_request(&mut bytes.as_slice()).unwrap(), request);

        let mut udp = Vec::new();
        StreamRequest::UdpAssociate.write_to(&mut udp).unwrap();
        assert_eq!(
            read_stream_request(&mut udp.as_slice()).unwrap(),
            StreamRequest::UdpAssociate
        );

        let datagram = {
            let mut bytes = Vec::new();
            write_request(&mut bytes, "1.1.1.1:53").unwrap();
            bytes.extend_from_slice(b"dns payload");
            bytes
        };
        let mut framed = Vec::new();
        write_datagram(&mut framed, &datagram).unwrap();
        let mut buffer = [0_u8; MAX_DATAGRAM_SIZE];
        let decoded = read_datagram(&mut framed.as_slice(), &mut buffer).unwrap();
        let (target, payload) = parse_datagram(decoded).unwrap();
        assert_eq!(target, "1.1.1.1:53");
        assert_eq!(payload, b"dns payload");
    }

    #[test]
    fn record_helpers() {
        let mut record = vec![RECORD_APPDATA, 3, 3, 0, 4, 1, 2, 3, 4];
        assert_eq!(record_length(&record), Some(9));
        record[3..5].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(record_length(&record), None);
    }

    #[test]
    fn copy_records_claim_and_passthrough() {
        let claimed = vec![RECORD_APPDATA, 3, 3, 0, 1, 9];
        let mut output = Vec::new();
        let outcome = copy_records(
            &mut output,
            &mut BufReader::new(claimed.as_slice()),
            |_, _| RecordAction::Claim,
        )
        .unwrap();
        assert_eq!(outcome, CopyOutcome::Claimed);
        assert!(output.is_empty());

        let records = [
            RECORD_APPDATA,
            3,
            3,
            0,
            1,
            1,
            RECORD_APPDATA,
            3,
            3,
            0,
            2,
            2,
            3,
        ];
        let mut output = Vec::new();
        let outcome = copy_records(
            &mut output,
            &mut BufReader::new(records.as_slice()),
            |_, _| RecordAction::Passthrough,
        )
        .unwrap();
        assert_eq!(outcome, CopyOutcome::EndOfStream);
        assert_eq!(output, records);
    }

    struct FailingReader {
        bytes: Vec<u8>,
        fail_after: usize,
    }

    impl Read for FailingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.bytes.is_empty() {
                return Err(io::Error::other("injected read error"));
            }
            let count = buffer.len().min(self.bytes.len()).min(self.fail_after);
            if count == 0 {
                return Err(io::Error::other("injected read error"));
            }
            buffer[..count].copy_from_slice(&self.bytes[..count]);
            self.bytes.drain(..count);
            self.fail_after -= count;
            Ok(count)
        }
    }

    #[test]
    fn copy_records_discards_partial_record_on_error() {
        let source = FailingReader {
            bytes: vec![RECORD_APPDATA, 3, 3, 0, 8, 1, 2],
            fail_after: 7,
        };
        let mut output = Vec::new();
        let result = copy_records(&mut output, &mut BufReader::new(source), |_, _| {
            RecordAction::Forward
        });
        assert!(result.is_err());
        assert!(output.is_empty());
    }

    #[test]
    fn copy_records_discards_partial_record_after_local_close() {
        let partial = [RECORD_APPDATA, 3, 3, 0, 8, 1, 2];
        let locally_closed = AtomicBool::new(true);
        let mut output = Vec::new();
        let outcome = copy_records_cancellable(
            &mut output,
            &mut BufReader::new(partial.as_slice()),
            |_, _| RecordAction::Forward,
            Some(&locally_closed),
        )
        .unwrap();
        assert_eq!(outcome, CopyOutcome::EndOfStream);
        assert!(output.is_empty());
    }

    #[test]
    fn copy_records_preserves_partial_final_record() {
        let partial = [RECORD_APPDATA, 3, 3, 0, 8, 1, 2];
        let mut output = Vec::new();
        let outcome = copy_records(
            &mut output,
            &mut BufReader::new(partial.as_slice()),
            |_, _| RecordAction::Forward,
        )
        .unwrap();
        assert_eq!(outcome, CopyOutcome::EndOfStream);
        assert_eq!(output, partial);
    }
}
