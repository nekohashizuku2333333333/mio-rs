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
pub const SESSION_WINDOW: usize = 32 << 20;
pub const MAX_SESSION_STREAMS: usize = 100;
const ACCEPT_BACKLOG: usize = MAX_SESSION_STREAMS;
const SESSION_WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const SESSION_WINDOW_BATCH: Duration = Duration::from_millis(5);

#[derive(Debug, thiserror::Error)]
#[error("session stream limit reached")]
pub struct StreamLimitReached;

enum ControlCommand {
    Window,
    Reset(u32),
    Close,
}

#[derive(Default)]
struct WriteGate {
    busy: Mutex<bool>,
    ready: Condvar,
    closed: AtomicBool,
}

struct WriteGateGuard<'a>(&'a WriteGate);

impl Drop for WriteGateGuard<'_> {
    fn drop(&mut self) {
        *self.0.busy.lock().unwrap() = false;
        self.0.ready.notify_one();
    }
}

impl WriteGate {
    fn acquire(&self, deadline: Option<Instant>) -> io::Result<WriteGateGuard<'_>> {
        let mut busy = self.busy.lock().unwrap();
        loop {
            if self.closed.load(Ordering::Acquire) {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "session closed"));
            }
            if !*busy {
                *busy = true;
                return Ok(WriteGateGuard(self));
            }
            if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "stream write timeout",
                    ));
                }
                let (next, _) = self
                    .ready
                    .wait_timeout(busy, deadline.saturating_duration_since(now))
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                busy = next;
            } else {
                busy = self
                    .ready
                    .wait(busy)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        }
    }

    fn notify_deadline_change(&self) {
        self.ready.notify_all();
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.ready.notify_all();
    }
}

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
    credit_ready: Condvar,
    control_tx: mpsc::Sender<ControlCommand>,
    control_rx: Mutex<Option<mpsc::Receiver<ControlCommand>>>,
    window_pending: AtomicBool,
    accept_tx: SyncSender<Arc<StreamState>>,
    accept_rx: Mutex<mpsc::Receiver<Arc<StreamState>>>,
    started: AtomicBool,
    last_recv: AtomicI64,
    write_gate: WriteGate,
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
    send_credit: usize,
    recv_credit: usize,
    recv_consumed: usize,
    error: Option<String>,
}

struct StreamState {
    state: Mutex<StreamData>,
    ready: Condvar,
    write_lock: Mutex<()>,
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
        let (control_tx, control_rx) = mpsc::channel();
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
                send_credit: SESSION_WINDOW,
                recv_credit: SESSION_WINDOW,
                ..SessionState::default()
            }),
            credit_ready: Condvar::new(),
            control_tx,
            control_rx: Mutex::new(Some(control_rx)),
            window_pending: AtomicBool::new(false),
            accept_tx,
            accept_rx: Mutex::new(accept_rx),
            started: AtomicBool::new(false),
            last_recv: AtomicI64::new(0),
            write_gate: WriteGate::default(),
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
        self.inner
            .write_frame(FRAME_READY, 0, payload, padding, None)
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
        if let Some(control_rx) = self.inner.control_rx.lock().unwrap().take() {
            let inner = self.inner.clone();
            std::thread::spawn(move || control_loop(inner, control_rx));
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
        if state.streams.len() + state.unopened >= MAX_SESSION_STREAMS {
            return Err(StreamLimitReached.into());
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
                write_lock: Mutex::new(()),
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

    fn take_send_credit(&self, limit: usize) -> usize {
        let mut state = self.session_state.lock().unwrap();
        let credit = limit.min(state.send_credit);
        state.send_credit -= credit;
        credit
    }

    fn add_send_credit(&self, credit: usize) -> bool {
        let mut state = self.session_state.lock().unwrap();
        if credit > SESSION_WINDOW.saturating_sub(state.send_credit) {
            return false;
        }
        state.send_credit += credit;
        self.credit_ready.notify_all();
        true
    }

    fn restore_send_credit(&self, credit: usize) {
        let mut state = self.session_state.lock().unwrap();
        state.send_credit += credit;
        self.credit_ready.notify_all();
    }

    fn wait_send_credit(&self, deadline: Option<Instant>) -> Result<()> {
        let mut state = self.session_state.lock().unwrap();
        loop {
            if state.error.is_some() {
                bail!("session closed");
            }
            if state.send_credit > 0 {
                return Ok(());
            }
            let next = if let Some(deadline) = deadline {
                let now = Instant::now();
                if now >= deadline {
                    return Err(
                        io::Error::new(io::ErrorKind::TimedOut, "stream write timeout").into(),
                    );
                }
                let (next, _) = self
                    .credit_ready
                    .wait_timeout(state, deadline.saturating_duration_since(now))
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                next
            } else {
                self.credit_ready
                    .wait(state)
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
            };
            state = next;
        }
    }

    fn take_receive_credit(&self, amount: usize) -> bool {
        let mut state = self.session_state.lock().unwrap();
        if amount > state.recv_credit {
            return false;
        }
        state.recv_credit -= amount;
        true
    }

    fn release_receive_credit(&self, amount: usize) {
        if amount == 0 {
            return;
        }
        self.session_state.lock().unwrap().recv_consumed += amount;
        if !self.window_pending.swap(true, Ordering::AcqRel) {
            let _ = self.control_tx.send(ControlCommand::Window);
        }
    }

    fn write_frame(
        &self,
        kind: u8,
        stream_id: u32,
        payload: &[u8],
        padding: usize,
        deadline: Option<Instant>,
    ) -> Result<()> {
        let _writer = self.write_gate.acquire(deadline)?;
        self.write_frame_locked(kind, stream_id, payload, padding, deadline)
    }

    fn write_frame_locked(
        &self,
        kind: u8,
        stream_id: u32,
        payload: &[u8],
        padding: usize,
        deadline: Option<Instant>,
    ) -> Result<()> {
        if self.session_state.lock().unwrap().error.is_some() {
            bail!("session closed");
        }
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

        let timeout = deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
            .unwrap_or(SESSION_WRITE_TIMEOUT)
            .min(SESSION_WRITE_TIMEOUT);
        if timeout.is_zero() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "stream write timeout").into());
        }
        self.conn
            .set_write_timeout(Some(timeout))
            .map_err(anyhow::Error::from)?;

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
        let result = (&self.conn).write_all(&record);
        drop(send);
        if let Err(error) = result {
            self.close_with_error(&error.to_string());
            return Err(error.into());
        }
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
        self.credit_ready.notify_all();
        let _ = self.control_tx.send(ControlCommand::Close);
        self.write_gate.close();
        let _ = self.conn.shutdown(Shutdown::Both);
    }

    fn receive_data_frame(self: &Arc<Self>, stream_id: u32, payload: &[u8]) -> Result<()> {
        let amount = payload.len();
        if !self.take_receive_credit(amount) {
            bail!("peer exceeded the session window");
        }
        if let Some(stream) = self.lookup(stream_id, true) {
            let mut data = stream.stream.state.lock().unwrap();
            if data.closed {
                drop(data);
                self.release_receive_credit(amount);
            } else if amount > data.recv_credit {
                drop(data);
                bail!("peer exceeded the stream window");
            } else {
                data.recv_credit -= amount;
                data.buffer.extend_from_slice(payload);
                stream.stream.ready.notify_all();
            }
        } else {
            self.release_receive_credit(amount);
        }
        Ok(())
    }

    fn receive_window_frame(self: &Arc<Self>, stream_id: u32, payload: &[u8]) -> Result<()> {
        if payload.len() != 4 {
            bail!("invalid window frame");
        }
        let increment =
            u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
        if stream_id == 0 {
            if increment == 0 || increment > SESSION_WINDOW || !self.add_send_credit(increment) {
                bail!("invalid session window increment");
            }
            return Ok(());
        }
        if let Some(stream) = self.lookup(stream_id, false) {
            let mut data = stream.stream.state.lock().unwrap();
            if increment == 0
                || increment > STREAM_WINDOW
                || increment > STREAM_WINDOW.saturating_sub(data.send_credit)
            {
                bail!("invalid stream window increment");
            }
            data.send_credit += increment;
            stream.stream.ready.notify_all();
        }
        Ok(())
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
        if state.streams.len() >= MAX_SESSION_STREAMS {
            drop(state);
            let _ = self.control_tx.send(ControlCommand::Reset(stream_id));
            return None;
        }
        let stream_state = Arc::new(StreamState {
            state: Mutex::new(StreamData {
                id: stream_id,
                recv_credit: STREAM_WINDOW,
                send_credit: STREAM_WINDOW,
                ..StreamData::default()
            }),
            ready: Condvar::new(),
            write_lock: Mutex::new(()),
        });
        state.streams.insert(stream_id, stream_state.clone());
        match self.accept_tx.try_send(stream_state.clone()) {
            Ok(()) => Some(Stream {
                session: self.clone(),
                stream: stream_state,
            }),
            Err(TrySendError::Full(_)) => {
                state.streams.remove(&stream_id);
                drop(state);
                let _ = self.control_tx.send(ControlCommand::Reset(stream_id));
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

    pub fn set_write_timeout(&self, timeout: Option<Duration>) {
        self.stream.state.lock().unwrap().write_deadline = timeout.map(|d| Instant::now() + d);
        self.session.write_gate.notify_deadline_change();
    }

    pub fn shutdown_session(&self) {
        self.session.close_with_error("session closed");
    }

    pub fn close(&self) -> Result<()> {
        let _write = self.stream.write_lock.lock().unwrap();
        let mut data = self.stream.state.lock().unwrap();
        if data.closed {
            return Ok(());
        }
        data.closed = true;
        let discarded = data.buffer.len();
        data.buffer.clear();
        let id = data.id;
        let known = id != 0;
        let send_close = known && !data.send_closed && !data.reset;
        let send_reset = known && !data.recv_closed && !data.reset;
        data.send_closed = true;
        drop(data);
        self.session.release_receive_credit(discarded);
        self.stream.ready.notify_all();
        self.session.remove_stream(id);
        if send_close {
            self.session.write_frame(FRAME_CLOSE, id, &[], 0, None)?;
        }
        if send_reset {
            self.session.write_frame(FRAME_RESET, id, &[], 0, None)?;
        }
        Ok(())
    }

    pub fn close_write(&self) -> Result<()> {
        let _write = self.stream.write_lock.lock().unwrap();
        let mut data = self.stream.state.lock().unwrap();
        if data.send_closed || data.closed {
            return Ok(());
        }
        data.send_closed = true;
        let id = data.id;
        let reset = data.reset;
        drop(data);
        if id != 0 && !reset {
            self.session.write_frame(FRAME_CLOSE, id, &[], 0, None)?;
        }
        Ok(())
    }

    fn write_data(&self, payload: &[u8], padding: usize, deadline: Option<Instant>) -> Result<()> {
        let _writer = self.session.write_gate.acquire(deadline)?;
        let id = {
            let mut data = self.stream.state.lock().unwrap();
            if data.id == 0 {
                let mut state = self.session.session_state.lock().unwrap();
                if state.error.is_some() {
                    bail!("session closed");
                }
                data.id = state.next_id;
                state.next_id += 1;
                state.unopened = state.unopened.saturating_sub(1);
                state.streams.insert(data.id, self.stream.clone());
            }
            data.id
        };
        self.session
            .write_frame_locked(FRAME_DATA, id, payload, padding, deadline)
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
                self.session.release_receive_credit(n);
                if increment > 0 {
                    let _ = self.session.write_frame(
                        FRAME_WINDOW,
                        id,
                        &(increment as u32).to_be_bytes(),
                        0,
                        None,
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
        let _write = self.stream.write_lock.lock().unwrap();
        let mut total = 0;
        while total < buffer.len() {
            let (n, data_frames, next_padding, deadline) = {
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
                let deadline = data.write_deadline;
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "stream write timeout",
                    ));
                }
                let available = (buffer.len() - total)
                    .min(data.send_credit)
                    .min(MAX_FRAME_PAYLOAD);
                if available == 0 {
                    data = self
                        .stream
                        .ready
                        .wait_timeout(data, Duration::from_millis(100))
                        .unwrap()
                        .0;
                    continue;
                }
                let n = self.session.take_send_credit(available);
                if n == 0 {
                    drop(data);
                    self.session
                        .wait_send_credit(deadline)
                        .map_err(write_io_error)?;
                    continue;
                }
                data.send_credit -= n;
                let data_frames = data.sent_data;
                data.sent_data += 1;
                let next = data.next_padding.take();
                (n, data_frames, next, deadline)
            };
            let padding = next_padding
                .map(|(minimum, maximum)| random_range(minimum, maximum))
                .unwrap_or_else(|| default_padding(data_frames, n));
            if let Err(error) = self.write_data(&buffer[total..total + n], padding, deadline) {
                self.session.restore_send_credit(n);
                let mut data = self.stream.state.lock().unwrap();
                data.send_credit += n;
                data.sent_data = data.sent_data.saturating_sub(1);
                if data.next_padding.is_none() {
                    data.next_padding = next_padding;
                }
                return Err(write_io_error(error));
            }
            total += n;
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn write_io_error(error: anyhow::Error) -> io::Error {
    let kind = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>().map(io::Error::kind))
        .unwrap_or(io::ErrorKind::Other);
    io::Error::new(kind, format!("{error:#}"))
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

fn control_loop(inner: Arc<SessionInner>, receiver: mpsc::Receiver<ControlCommand>) {
    while let Ok(command) = receiver.recv() {
        let result = match command {
            ControlCommand::Close => return,
            ControlCommand::Reset(id) => inner.write_frame(FRAME_RESET, id, &[], 0, None),
            ControlCommand::Window => {
                std::thread::sleep(SESSION_WINDOW_BATCH);
                let increment = {
                    let mut state = inner.session_state.lock().unwrap();
                    // Clear pending before taking the snapshot so a read racing
                    // with this batch queues another window update.
                    inner.window_pending.store(false, Ordering::Release);
                    let increment = state.recv_consumed;
                    state.recv_consumed = 0;
                    state.recv_credit += increment;
                    increment
                };
                if increment == 0 {
                    Ok(())
                } else {
                    inner.write_frame(FRAME_WINDOW, 0, &(increment as u32).to_be_bytes(), 0, None)
                }
            }
        };
        if let Err(error) = result {
            inner.close_with_error(&error.to_string());
            return;
        }
    }
}

fn read_loop(inner: Arc<SessionInner>, reader: BufReader<TcpStream>) {
    let mut reader = reader;
    loop {
        let result = inner.read_frame_with(&mut reader, false);
        match result {
            Ok((kind, id, payload)) => match kind {
                FRAME_DATA => {
                    if let Err(error) = inner.receive_data_frame(id, &payload) {
                        inner.close_with_error(&error.to_string());
                        return;
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
                FRAME_WINDOW => {
                    if let Err(error) = inner.receive_window_frame(id, &payload) {
                        inner.close_with_error(&error.to_string());
                        return;
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

    fn test_session() -> Session {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let connector = std::thread::spawn(move || std::net::TcpStream::connect(address).unwrap());
        let (server, _) = listener.accept().unwrap();
        let mut peer = connector.join().unwrap();
        let _ = peer.set_read_timeout(Some(Duration::from_secs(5)));
        std::thread::spawn(move || {
            use std::io::Read;
            let mut buffer = [0_u8; 8192];
            while peer.read(&mut buffer).is_ok_and(|count| count > 0) {}
        });
        let reader = BufReader::new(server.try_clone().unwrap());
        Session::new(
            server,
            reader,
            AeadKey::new(&[7_u8; 32]),
            AeadKey::new(&[9_u8; 32]),
            true,
        )
    }

    #[test]
    fn stream_window_is_16_mib() {
        assert_eq!(STREAM_WINDOW, 16 * 1024 * 1024);
    }

    #[test]
    fn blocked_stream_write_observes_deadline_and_rolls_back() {
        let session = test_session();
        let mut stream = session.open().unwrap();
        stream.set_next_padding(1024, 1024);
        stream.set_write_timeout(Some(Duration::from_millis(50)));
        let state = stream.stream.clone();
        let gate = session.inner.write_gate.acquire(None).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            tx.send(stream.write(b"deadline-test")).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        let data = state.state.lock().unwrap();
        assert_eq!(data.send_credit, STREAM_WINDOW);
        assert_eq!(data.sent_data, 0);
        assert_eq!(data.next_padding, Some((1024, 1024)));
        drop(data);
        drop(gate);
    }

    #[test]
    fn session_close_wakes_blocked_writer_and_rolls_back() {
        let session = test_session();
        let mut stream = session.open().unwrap();
        stream.set_next_padding(512, 512);
        let state = stream.stream.clone();
        let gate = session.inner.write_gate.acquire(None).unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            tx.send(stream.write(b"close-test")).unwrap();
        });
        session.close();
        let result = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(result.is_err());
        let data = state.state.lock().unwrap();
        assert_eq!(data.send_credit, STREAM_WINDOW);
        assert_eq!(data.sent_data, 0);
        assert_eq!(data.next_padding, Some((512, 512)));
        drop(data);
        drop(gate);
    }

    #[test]
    fn session_window_is_32_mib() {
        assert_eq!(SESSION_WINDOW, 32 * 1024 * 1024);
    }

    #[test]
    fn session_and_stream_send_credit_are_charged() {
        let session = test_session();
        let mut stream = session.open().unwrap();
        stream.write_all(&[7_u8; 100]).unwrap();
        assert_eq!(
            session.inner.session_state.lock().unwrap().send_credit,
            SESSION_WINDOW - 100
        );
        assert_eq!(
            stream.stream.state.lock().unwrap().send_credit,
            STREAM_WINDOW - 100
        );
    }

    #[test]
    fn unknown_and_closed_stream_data_returns_session_credit() {
        let session = test_session();
        session.inner.receive_data_frame(99, &[1_u8; 10]).unwrap();
        let stream = session.open().unwrap();
        {
            let mut data = stream.stream.state.lock().unwrap();
            data.id = 1;
            data.closed = true;
        }
        session
            .inner
            .session_state
            .lock()
            .unwrap()
            .streams
            .insert(1, stream.stream.clone());
        session.inner.receive_data_frame(1, &[2_u8; 7]).unwrap();
        let state = session.inner.session_state.lock().unwrap();
        assert_eq!(state.recv_credit, SESSION_WINDOW - 17);
        assert_eq!(state.recv_consumed, 17);
    }

    #[test]
    fn stream_close_returns_unread_session_credit() {
        let session = test_session();
        let stream = session.open().unwrap();
        {
            let mut data = stream.stream.state.lock().unwrap();
            data.id = 1;
        }
        session
            .inner
            .session_state
            .lock()
            .unwrap()
            .streams
            .insert(1, stream.stream.clone());
        session.inner.receive_data_frame(1, &[3_u8; 64]).unwrap();
        stream.close().unwrap();
        let state = session.inner.session_state.lock().unwrap();
        assert_eq!(state.recv_consumed, 64);
        assert_eq!(state.recv_credit, SESSION_WINDOW - 64);
        assert!(stream.stream.state.lock().unwrap().buffer.is_empty());
    }

    #[test]
    fn invalid_window_increments_are_rejected() {
        let session = test_session();
        assert!(
            session
                .inner
                .receive_window_frame(0, &0_u32.to_be_bytes())
                .is_err()
        );
        assert!(
            session
                .inner
                .receive_window_frame(0, &(SESSION_WINDOW as u32).to_be_bytes())
                .is_err()
        );
        session.inner.take_send_credit(8);
        assert!(
            session
                .inner
                .receive_window_frame(0, &(SESSION_WINDOW as u32).to_be_bytes())
                .is_err()
        );
        assert!(session.inner.receive_window_frame(7, &[0_u8; 3]).is_err());
    }

    #[test]
    fn open_rejects_after_one_hundred_streams() {
        let session = test_session();
        let mut streams = Vec::new();
        for _ in 0..MAX_SESSION_STREAMS {
            streams.push(session.open().unwrap());
        }
        let error = match session.open() {
            Ok(_) => panic!("opening a 101st stream must fail"),
            Err(error) => error,
        };
        assert!(error.downcast_ref::<StreamLimitReached>().is_some());
        streams[0].close().unwrap();
        assert!(session.open().is_ok());
    }
}
