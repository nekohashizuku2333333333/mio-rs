use anyhow::{Result, anyhow, bail};
use std::collections::HashMap;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::crypto::{AEAD_OVERHEAD, AeadKey, nonce_for_sequence, random_bytes, random_range};
use crate::protocol::{RECORD_APPDATA, RECORD_HEADER_SIZE, valid_record_header};

pub const FRAME_READY: u8 = 0;
pub const FRAME_DATA: u8 = 1;
pub const FRAME_CLOSE: u8 = 2;
pub const FRAME_RESET: u8 = 3;
pub const FRAME_WINDOW: u8 = 4;
pub const FRAME_HEADER_SIZE: usize = 7;
pub const MAX_FRAME_PAYLOAD: usize = 16384 + 1 + 16 - AEAD_OVERHEAD - FRAME_HEADER_SIZE;
pub const STREAM_WINDOW: usize = 16 << 20;
const ACCEPT_BACKLOG: usize = 256;

pub struct Session {
    inner: Arc<SessionInner>,
}

impl Clone for Session {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

struct SessionInner {
    conn: TcpStream,
    reader: Mutex<Option<BufReader<TcpStream>>>,
    send: Mutex<SendState>,
    recv: Mutex<RecvState>,
    session_state: Mutex<SessionState>,
    accept_tx: SyncSender<Arc<StreamState>>,
    accept_rx: Mutex<mpsc::Receiver<Arc<StreamState>>>,
    started: AtomicBool,
    last_recv: AtomicI64,
    open_mu: Mutex<()>,
    client: bool,
}

struct SendState {
    key: AeadKey,
    sequence: u64,
}

struct RecvState {
    key: AeadKey,
    sequence: u64,
    buffer: Vec<u8>,
}

#[derive(Default)]
struct SessionState {
    streams: HashMap<u32, Arc<StreamState>>,
    next_id: u32,
    last_peer_id: u32,
    unopened: usize,
    error: Option<String>,
}

struct StreamState {
    state: Mutex<StreamData>,
    ready: Condvar,
}

#[derive(Default)]
struct StreamData {
    id: u32,
    buffer: Vec<u8>,
    recv_credit: usize,
    unacked: usize,
    recv_closed: bool,
    reset: bool,
    closed: bool,
    send_credit: usize,
    send_closed: bool,
    sent_data: u64,
    next_padding: Option<(usize, usize)>,
    read_deadline: Option<Instant>,
    write_deadline: Option<Instant>,
}

pub struct Stream {
    session: Arc<SessionInner>,
    stream: Arc<StreamState>,
}

impl Clone for Stream {
    fn clone(&self) -> Self {
        Self {
            session: self.session.clone(),
            stream: self.stream.clone(),
        }
    }
}

impl crate::protocol::CloseWrite for Stream {
    fn close_write(&mut self) -> io::Result<()> {
        Stream::close_write(self).map_err(io::Error::other)
    }
}

impl Session {
    pub fn new(
        conn: TcpStream,
        reader: BufReader<TcpStream>,
        send: AeadKey,
        recv: AeadKey,
        client: bool,
    ) -> Self {
        let (accept_tx, accept_rx) = mpsc::sync_channel(ACCEPT_BACKLOG);
        let inner = Arc::new(SessionInner {
            conn,
            reader: Mutex::new(Some(reader)),
            send: Mutex::new(SendState {
                key: send,
                sequence: 0,
            }),
            recv: Mutex::new(RecvState {
                key: recv,
                sequence: 0,
                buffer: Vec::new(),
            }),
            session_state: Mutex::new(SessionState {
                next_id: 1,
                ..SessionState::default()
            }),
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
            started: AtomicBool::new(false),
            last_recv: AtomicI64::new(0),
            open_mu: Mutex::new(()),
            client,
        });
        Self { inner }
    }

    pub fn rekey(&self, send: AeadKey, recv: AeadKey) {
        self.inner.send.lock().unwrap().key = send;
        self.inner.send.lock().unwrap().sequence = 0;
        let mut recv_state = self.inner.recv.lock().unwrap();
        recv_state.key = recv;
        recv_state.sequence = 0;
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.conn.set_read_timeout(timeout)
    }

    pub fn write_ready(&self, payload: &[u8]) -> Result<()> {
        let limit = MAX_FRAME_PAYLOAD.saturating_sub(payload.len());
        let padding = random_range(0, limit.min(1024));
        self.inner.write_frame(FRAME_READY, 0, payload, padding)
    }

    pub fn wait_ready(&self) -> Result<Vec<u8>> {
        let (kind, _, payload) = self.inner.read_frame(true)?;
        if kind != FRAME_READY {
            bail!("unexpected frame before ready");
        }
        Ok(payload)
    }

    pub fn start(&self) {
        if self.inner.started.swap(true, Ordering::SeqCst) {
            return;
        }
        let reader = self.inner.reader.lock().unwrap().take();
        if let Some(reader) = reader {
            let inner = self.inner.clone();
            std::thread::spawn(move || read_loop(inner, reader));
        }
    }

    pub fn open(&self) -> Result<Stream> {
        if !self.inner.client {
            bail!("only the client can open streams");
        }
        let mut state = self.inner.session_state.lock().unwrap();
        if state.error.is_some() {
            bail!("session closed");
        }
        state.unopened += 1;
        let stream = Stream {
            session: self.inner.clone(),
            stream: Arc::new(StreamState {
                state: Mutex::new(StreamData {
                    recv_credit: STREAM_WINDOW,
                    send_credit: STREAM_WINDOW,
                    ..StreamData::default()
                }),
                ready: Condvar::new(),
            }),
        };
        Ok(stream)
    }

    pub fn accept(&self) -> Result<Stream> {
        let receiver = self.inner.accept_rx.lock().unwrap();
        loop {
            match receiver.try_recv() {
                Ok(stream) => {
                    return Ok(Stream {
                        session: self.inner.clone(),
                        stream,
                    });
                }
                Err(mpsc::TryRecvError::Disconnected) => bail!("session closed"),
                Err(mpsc::TryRecvError::Empty) => {}
            }
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(stream) => {
                    return Ok(Stream {
                        session: self.inner.clone(),
                        stream,
                    });
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if let Some(error) = self.inner.session_state.lock().unwrap().error.clone() {
                        return Err(anyhow!(error));
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => bail!("session closed"),
            }
        }
    }

    pub fn is_closed(&self) -> bool {
        self.inner.session_state.lock().unwrap().error.is_some()
    }

    pub fn num_streams(&self) -> usize {
        let state = self.inner.session_state.lock().unwrap();
        state.streams.len() + state.unopened
    }

    pub fn last_recv_nanos(&self) -> i64 {
        self.inner.last_recv.load(Ordering::Acquire)
    }

    pub fn close(&self) {
        self.inner.close_with_error("session closed");
    }

    pub fn same_session(&self, other: &Session) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Drop for Session {
    fn drop(&mut self) {}
}

impl SessionInner {
    fn read_frame(&self, skip_foreign: bool) -> Result<(u8, u32, Vec<u8>)> {
        let mut reader = self.reader.lock().unwrap();
        let reader = reader
            .as_mut()
            .ok_or_else(|| anyhow!("session reader unavailable"))?;
        let mut recv = self.recv.lock().unwrap();
        loop {
            let mut header = [0_u8; RECORD_HEADER_SIZE];
            reader.read_exact(&mut header)?;
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            if !valid_record_header(&header, length) {
                bail!("invalid TLS record header");
            }
            if recv.buffer.len() < length {
                recv.buffer.resize(length, 0);
            }
            reader.read_exact(&mut recv.buffer[..length])?;
            let plain = match recv.key.open(
                &nonce_for_sequence(recv.sequence),
                &recv.buffer[..length],
                &header,
            ) {
                Ok(plain) => plain,
                Err(error) => {
                    if skip_foreign {
                        continue;
                    }
                    return Err(error);
                }
            };
            recv.sequence += 1;
            self.last_recv.store(monotonic_nanos(), Ordering::Release);
            if plain.len() < FRAME_HEADER_SIZE {
                bail!("short encrypted frame");
            }
            let stream_id = u32::from_be_bytes([plain[1], plain[2], plain[3], plain[4]]);
            let payload_length = u16::from_be_bytes([plain[5], plain[6]]) as usize;
            if payload_length > plain.len() - FRAME_HEADER_SIZE {
                bail!("invalid frame payload length");
            }
            return Ok((
                plain[0],
                stream_id,
                plain[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_length].to_vec(),
            ));
        }
    }

    fn write_frame(&self, kind: u8, stream_id: u32, payload: &[u8], padding: usize) -> Result<()> {
        if payload.len() > MAX_FRAME_PAYLOAD {
            bail!("frame payload too large");
        }
        let padding = padding.min(MAX_FRAME_PAYLOAD - payload.len());
        let mut plain = Vec::with_capacity(FRAME_HEADER_SIZE + payload.len() + padding);
        plain.push(kind);
        plain.extend_from_slice(&stream_id.to_be_bytes());
        plain.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        plain.extend_from_slice(payload);
        plain.extend_from_slice(&random_bytes(padding));

        let mut send = self.send.lock().unwrap();
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
        let body = send
            .key
            .seal(&nonce_for_sequence(send.sequence), &plain, &header);
        send.sequence += 1;
        let mut record = Vec::with_capacity(RECORD_HEADER_SIZE + body.len());
        record.extend_from_slice(&header);
        record.extend_from_slice(&body);
        (&self.conn).write_all(&record)?;
        Ok(())
    }

    fn close_with_error(&self, message: &str) {
        let streams = {
            let mut state = self.session_state.lock().unwrap();
            if state.error.is_some() {
                return;
            }
            state.error = Some(message.to_string());
            state.streams.values().cloned().collect::<Vec<_>>()
        };
        for stream in streams {
            let mut data = stream.state.lock().unwrap();
            data.closed = true;
            stream.ready.notify_all();
        }
        let _ = self.conn.shutdown(Shutdown::Both);
    }

    fn remove_stream(&self, stream_id: u32) {
        let mut state = self.session_state.lock().unwrap();
        if stream_id == 0 {
            state.unopened = state.unopened.saturating_sub(1);
        } else {
            state.streams.remove(&stream_id);
        }
    }

    fn lookup(self: &Arc<Self>, stream_id: u32, open: bool) -> Option<Stream> {
        let mut state = self.session_state.lock().unwrap();
        if let Some(existing) = state.streams.get(&stream_id) {
            return Some(Stream {
                session: self.clone(),
                stream: existing.clone(),
            });
        }
        if !open || self.client || stream_id <= state.last_peer_id || state.error.is_some() {
            return None;
        }
        state.last_peer_id = stream_id;
        let stream_state = Arc::new(StreamState {
            state: Mutex::new(StreamData {
                id: stream_id,
                recv_credit: STREAM_WINDOW,
                send_credit: STREAM_WINDOW,
                ..StreamData::default()
            }),
            ready: Condvar::new(),
        });
        state.streams.insert(stream_id, stream_state.clone());
        match self.accept_tx.try_send(stream_state.clone()) {
            Ok(()) => Some(Stream {
                session: self.clone(),
                stream: stream_state,
            }),
            Err(TrySendError::Full(_)) => {
                state.streams.remove(&stream_id);
                None
            }
            Err(TrySendError::Disconnected(_)) => None,
        }
    }
}

impl Stream {
    pub fn set_next_padding(&self, minimum: usize, maximum: usize) {
        if maximum >= minimum {
            self.stream.state.lock().unwrap().next_padding = Some((minimum, maximum));
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) {
        self.stream.state.lock().unwrap().read_deadline = timeout.map(|d| Instant::now() + d);
    }

    pub fn shutdown_session(&self) {
        self.session.close_with_error("session closed");
    }

    pub fn close(&self) -> Result<()> {
        let mut data = self.stream.state.lock().unwrap();
        if data.closed {
            return Ok(());
        }
        data.closed = true;
        let id = data.id;
        let known = id != 0;
        let send_close = known && !data.send_closed && !data.reset;
        let send_reset = known && !data.recv_closed && !data.reset;
        data.send_closed = true;
        drop(data);
        self.stream.ready.notify_all();
        self.session.remove_stream(id);
        if send_close {
            self.session.write_frame(FRAME_CLOSE, id, &[], 0)?;
        }
        if send_reset {
            self.session.write_frame(FRAME_RESET, id, &[], 0)?;
        }
        Ok(())
    }

    pub fn close_write(&self) -> Result<()> {
        let mut data = self.stream.state.lock().unwrap();
        if data.send_closed || data.closed {
            return Ok(());
        }
        data.send_closed = true;
        let id = data.id;
        let reset = data.reset;
        drop(data);
        if id != 0 && !reset {
            self.session.write_frame(FRAME_CLOSE, id, &[], 0)?;
        }
        Ok(())
    }

    fn write_data(&self, payload: &[u8], padding: usize) -> Result<()> {
        let mut data = self.stream.state.lock().unwrap();
        let mut id = data.id;
        if id == 0 {
            let _open_guard = self.session.open_mu.lock().unwrap();
            let mut state = self.session.session_state.lock().unwrap();
            if state.error.is_some() {
                bail!("session closed");
            }
            id = state.next_id;
            state.next_id += 1;
            state.unopened = state.unopened.saturating_sub(1);
            state.streams.insert(id, self.stream.clone());
            data.id = id;
        }
        drop(data);
        self.session.write_frame(FRAME_DATA, id, payload, padding)
    }
}

impl Read for Stream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        loop {
            let mut data = self.stream.state.lock().unwrap();
            if data.closed {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
            }
            if !data.buffer.is_empty() {
                let n = buffer.len().min(data.buffer.len());
                buffer[..n].copy_from_slice(&data.buffer[..n]);
                data.buffer.drain(..n);
                data.unacked += n;
                let mut increment = 0;
                if data.unacked >= STREAM_WINDOW / 2 && !data.recv_closed && !data.reset {
                    increment = data.unacked;
                    data.unacked = 0;
                    data.recv_credit += increment;
                }
                let id = data.id;
                drop(data);
                if increment > 0 {
                    let _ = self.session.write_frame(
                        FRAME_WINDOW,
                        id,
                        &(increment as u32).to_be_bytes(),
                        0,
                    );
                }
                return Ok(n);
            }
            if data.recv_closed {
                return Ok(0);
            }
            if data.reset {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "stream reset",
                ));
            }
            let deadline = data.read_deadline;
            data = self
                .stream
                .ready
                .wait_timeout(data, Duration::from_millis(100))
                .unwrap()
                .0;
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "stream read timeout",
                ));
            }
            drop(data);
            if self.session.session_state.lock().unwrap().error.is_some() {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
            }
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        let mut total = 0;
        while total < buffer.len() {
            let (n, data_frames, next_padding) = {
                let mut data = self.stream.state.lock().unwrap();
                if data.closed || data.send_closed {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stream closed"));
                }
                if data.reset {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        "stream reset",
                    ));
                }
                let n = (buffer.len() - total)
                    .min(data.send_credit)
                    .min(MAX_FRAME_PAYLOAD);
                if n == 0 {
                    let deadline = data.write_deadline;
                    data = self
                        .stream
                        .ready
                        .wait_timeout(data, Duration::from_millis(100))
                        .unwrap()
                        .0;
                    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "stream write timeout",
                        ));
                    }
                    continue;
                }
                data.send_credit -= n;
                let data_frames = data.sent_data;
                data.sent_data += 1;
                let next = data.next_padding.take();
                (n, data_frames, next)
            };
            let padding = next_padding
                .map(|(minimum, maximum)| random_range(minimum, maximum))
                .unwrap_or_else(|| default_padding(data_frames, n));
            self.write_data(&buffer[total..total + n], padding)
                .map_err(io::Error::other)?;
            total += n;
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn monotonic_nanos() -> i64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos() as i64
}

fn default_padding(data_frames: u64, payload: usize) -> usize {
    if data_frames < 8 && payload < 900 {
        let minimum = 900usize.saturating_sub(FRAME_HEADER_SIZE + payload);
        let maximum = 1400usize.saturating_sub(FRAME_HEADER_SIZE + payload);
        random_range(minimum, maximum.max(minimum))
    } else if data_frames < 8 {
        random_range(0, 255)
    } else {
        0
    }
}

fn read_loop(inner: Arc<SessionInner>, reader: BufReader<TcpStream>) {
    let mut reader = reader;
    loop {
        let result = inner.read_frame_with(&mut reader, false);
        match result {
            Ok((kind, id, payload)) => match kind {
                FRAME_DATA => {
                    if let Some(stream) = inner.lookup(id, true) {
                        let mut data = stream.stream.state.lock().unwrap();
                        if payload.len() > data.recv_credit {
                            drop(data);
                            inner.close_with_error("peer exceeded the stream window");
                            return;
                        }
                        data.recv_credit -= payload.len();
                        data.buffer.extend_from_slice(&payload);
                        stream.stream.ready.notify_all();
                    }
                }
                FRAME_CLOSE => {
                    if let Some(stream) = inner.lookup(id, false) {
                        stream.stream.state.lock().unwrap().recv_closed = true;
                        stream.stream.ready.notify_all();
                    }
                }
                FRAME_RESET => {
                    if let Some(stream) = inner.lookup(id, false) {
                        stream.stream.state.lock().unwrap().reset = true;
                        stream.stream.ready.notify_all();
                    }
                }
                FRAME_WINDOW if payload.len() == 4 => {
                    if let Some(stream) = inner.lookup(id, false) {
                        let increment =
                            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                        stream.stream.state.lock().unwrap().send_credit += increment as usize;
                        stream.stream.ready.notify_all();
                    }
                }
                _ => {}
            },
            Err(error) => {
                inner.close_with_error(&error.to_string());
                return;
            }
        }
    }
}

impl SessionInner {
    fn read_frame_with(
        &self,
        reader: &mut BufReader<TcpStream>,
        skip_foreign: bool,
    ) -> Result<(u8, u32, Vec<u8>)> {
        let mut recv = self.recv.lock().unwrap();
        loop {
            let mut header = [0_u8; RECORD_HEADER_SIZE];
            reader.read_exact(&mut header)?;
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            if !valid_record_header(&header, length) {
                bail!("invalid TLS record header");
            }
            if recv.buffer.len() < length {
                recv.buffer.resize(length, 0);
            }
            reader.read_exact(&mut recv.buffer[..length])?;
            let plain = match recv.key.open(
                &nonce_for_sequence(recv.sequence),
                &recv.buffer[..length],
                &header,
            ) {
                Ok(plain) => plain,
                Err(error) => {
                    if skip_foreign {
                        continue;
                    }
                    return Err(error);
                }
            };
            recv.sequence += 1;
            self.last_recv.store(monotonic_nanos(), Ordering::Release);
            if plain.len() < FRAME_HEADER_SIZE {
                bail!("short encrypted frame");
            }
            let stream_id = u32::from_be_bytes([plain[1], plain[2], plain[3], plain[4]]);
            let payload_length = u16::from_be_bytes([plain[5], plain[6]]) as usize;
            if payload_length > plain.len() - FRAME_HEADER_SIZE {
                bail!("invalid frame payload length");
            }
            return Ok((
                plain[0],
                stream_id,
                plain[FRAME_HEADER_SIZE..FRAME_HEADER_SIZE + payload_length].to_vec(),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_window_is_16_mib() {
        assert_eq!(STREAM_WINDOW, 16 * 1024 * 1024);
    }
}
