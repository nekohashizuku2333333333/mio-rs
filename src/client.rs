use anyhow::{Context, Result, anyhow, bail};
use log::{debug, info, warn};
use rand::Rng;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::OutboundConfig;
use crate::crypto::{ClientKeys, auth_records, parse_public_key, transport_keys, x25519_shared};
use crate::protocol;
use crate::quic::{QuicSession, QuicStream, TargetConnectFailed};
use crate::session::{MAX_SESSION_STREAMS, Session, Stream, StreamLimitReached};
use crate::tls;
use x25519_dalek::StaticSecret;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(3);
const MIN_FIRST_PROBE_DELAY: Duration = Duration::from_secs(1);
const MAX_FIRST_PROBE_DELAY: Duration = Duration::from_secs(10);
const MIN_PROBE_INTERVAL: Duration = Duration::from_secs(10 * 60);
const MAX_PROBE_INTERVAL: Duration = Duration::from_secs(30 * 60);
const DIAL_TIME_LIMIT: Duration = Duration::from_secs(25);
const MIN_FALLBACK_DELAY: Duration = Duration::from_millis(250);
const MAX_FALLBACK_DELAY: Duration = Duration::from_secs(1);
const PROBE_HEAD_START: Duration = Duration::from_millis(25);

#[derive(Debug, Clone)]
enum SocksRequest {
    Connect(String),
    UdpAssociate { port: u16 },
}

enum ProxyConnection {
    Tcp(Stream),
    Quic(QuicStream),
}

#[derive(Debug, thiserror::Error)]
#[error("server could not connect to target")]
struct TcpTargetConnectFailed;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportChoice {
    Tcp,
    Quic,
}

struct DialerState {
    preferred: TransportChoice,
    latency: Duration,
    next_probe: Option<Instant>,
    generation: u64,
    quic: Option<Arc<QuicSession>>,
    quic_dial: Option<Arc<QuicDialAttempt>>,
}

struct Dialer {
    peer: OutboundConfig,
    tcp_pool: Mutex<TcpPoolState>,
    state: Mutex<DialerState>,
    stop: Arc<AtomicBool>,
    enable_quic: bool,
}

#[derive(Default)]
struct TcpPoolState {
    sessions: Vec<Session>,
    attempt: Option<Arc<TcpDialAttempt>>,
}

struct TcpDialAttempt {
    result: Mutex<Option<Result<(), Arc<anyhow::Error>>>>,
    ready: Condvar,
}

enum TcpPoolClaim {
    Ready(Session),
    Wait(Arc<TcpDialAttempt>),
    Lead,
}

fn claim_tcp_pool(pool: &mut TcpPoolState) -> TcpPoolClaim {
    pool.sessions.retain(|session| !session.is_closed());
    if let Some(session) = pool
        .sessions
        .iter()
        .rev()
        .find(|session| session.num_streams() < MAX_SESSION_STREAMS)
    {
        return TcpPoolClaim::Ready(session.clone());
    }
    if let Some(attempt) = pool.attempt.as_ref() {
        return TcpPoolClaim::Wait(attempt.clone());
    }
    pool.attempt = Some(Arc::new(TcpDialAttempt::new()));
    TcpPoolClaim::Lead
}

impl TcpDialAttempt {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn finish(&self, result: Result<(), Arc<anyhow::Error>>) {
        *self.result.lock().unwrap() = Some(result);
        self.ready.notify_all();
    }

    fn wait(&self, stop: &AtomicBool) -> Result<(), Arc<anyhow::Error>> {
        let mut result = self.result.lock().unwrap();
        while result.is_none() {
            if stop.load(Ordering::Acquire) {
                return Err(Arc::new(anyhow!("dialer stopped")));
            }
            let (next, _) = self
                .ready
                .wait_timeout(result, Duration::from_millis(100))
                .unwrap();
            result = next;
        }
        match result.as_ref().expect("dial result initialized") {
            Ok(()) => Ok(()),
            Err(error) => Err(error.clone()),
        }
    }
}

struct QuicDialAttempt {
    result: Mutex<Option<Result<Arc<QuicSession>, Arc<anyhow::Error>>>>,
    ready: Condvar,
}

impl QuicDialAttempt {
    fn new() -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
        }
    }

    fn finish(&self, result: Result<Arc<QuicSession>, Arc<anyhow::Error>>) {
        *self.result.lock().unwrap() = Some(result);
        self.ready.notify_all();
    }

    fn wait(&self, stop: &AtomicBool) -> Result<Arc<QuicSession>> {
        let mut result = self.result.lock().unwrap();
        while result.is_none() {
            if stop.load(Ordering::Acquire) {
                bail!("dialer stopped");
            }
            let (next, _) = self
                .ready
                .wait_timeout(result, Duration::from_millis(100))
                .unwrap();
            result = next;
        }
        match result.as_ref().expect("QUIC dial result initialized") {
            Ok(session) => Ok(session.clone()),
            Err(error) => Err(anyhow!("QUIC session dial failed: {error:#}")),
        }
    }
}

struct DialResult {
    transport: TransportChoice,
    connection: Option<ProxyConnection>,
    elapsed: Duration,
    error: Option<anyhow::Error>,
}

impl DialResult {
    fn close(mut self) {
        if let Some(connection) = self.connection.take() {
            connection.close();
        }
    }
}

impl ProxyConnection {
    fn close(self) {
        match self {
            Self::Tcp(stream) => {
                let _ = stream.close();
            }
            Self::Quic(stream) => drop(stream),
        }
    }
}

impl Dialer {
    fn new(peer: OutboundConfig, stop: Arc<AtomicBool>, enable_quic: bool) -> Self {
        Self {
            peer,
            tcp_pool: Mutex::new(TcpPoolState::default()),
            state: Mutex::new(DialerState {
                preferred: TransportChoice::Tcp,
                latency: Duration::ZERO,
                next_probe: None,
                generation: 0,
                quic: None,
                quic_dial: None,
            }),
            stop,
            enable_quic,
        }
    }

    fn dial(self: &Arc<Self>, target: &str) -> Result<ProxyConnection> {
        if self.stop.load(Ordering::Acquire) {
            bail!("dialer stopped");
        }
        if !self.enable_quic {
            return self.dial_tcp(target).map(ProxyConnection::Tcp);
        }
        let (preferred, generation, delay) = {
            let mut state = self.state.lock().unwrap();
            let now = Instant::now();
            let mut delay = if state.latency.is_zero() {
                MIN_FALLBACK_DELAY
            } else {
                (state.latency * 2).clamp(MIN_FALLBACK_DELAY, MAX_FALLBACK_DELAY)
            };
            if state.next_probe.is_some_and(|next| now >= next) {
                delay = PROBE_HEAD_START;
                state.next_probe =
                    Some(now + random_duration(MIN_PROBE_INTERVAL, MAX_PROBE_INTERVAL));
            }
            (state.preferred, state.generation, delay)
        };

        let backup = match preferred {
            TransportChoice::Tcp => TransportChoice::Quic,
            TransportChoice::Quic => TransportChoice::Tcp,
        };
        let (sender, receiver) = std::sync::mpsc::channel();
        self.start_dial(&sender, preferred, target);

        let deadline = Instant::now() + DIAL_TIME_LIMIT;
        let mut backup_started = false;
        let mut pending = 1usize;
        let mut errors = Vec::new();
        let mut current_delay = delay;

        while pending > 0 {
            let now = Instant::now();
            if now >= deadline {
                drain_results(receiver);
                return Err(anyhow!("mio dial timed out: {}", errors.join("; ")));
            }
            let wait = if backup_started {
                deadline.saturating_duration_since(now)
            } else {
                current_delay.min(deadline.saturating_duration_since(now))
            };
            match receiver.recv_timeout(wait) {
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) if !backup_started => {
                    backup_started = true;
                    self.start_dial(&sender, backup, target);
                    pending += 1;
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    drain_results(receiver);
                    return Err(anyhow!("mio dial timed out: {}", errors.join("; ")));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(anyhow!("dial result channel closed: {}", errors.join("; ")));
                }
                Ok(mut result) => {
                    pending -= 1;
                    if let Some(error) = result.error.take() {
                        let target_failure = is_target_failure(&error);
                        let transport = result.transport;
                        result.close();
                        if transport == preferred && target_failure {
                            if pending > 0 {
                                drain_results(receiver);
                            }
                            return Err(error);
                        }
                        errors.push(format!("{error:#}"));
                        if !backup_started {
                            backup_started = true;
                            self.start_dial(&sender, backup, target);
                            pending += 1;
                        }
                        continue;
                    }
                    let transport = result.transport;
                    let elapsed = result.elapsed;
                    let connection = result
                        .connection
                        .take()
                        .ok_or_else(|| anyhow!("successful dial has no connection"))?;
                    self.record_success(generation, transport, elapsed);
                    if pending > 0 {
                        drain_results(receiver);
                    }
                    return Ok(connection);
                }
            }
            current_delay = Duration::ZERO;
        }
        Err(anyhow!("all transports failed: {}", errors.join("; ")))
    }

    fn start_dial(
        self: &Arc<Self>,
        sender: &std::sync::mpsc::Sender<DialResult>,
        transport: TransportChoice,
        target: &str,
    ) {
        let dialer = self.clone();
        let target = target.to_string();
        let sender = sender.clone();
        std::thread::spawn(move || {
            let started = Instant::now();
            let result = match dialer.dial_transport(transport, &target) {
                Ok(connection) => DialResult {
                    transport,
                    connection: Some(connection),
                    elapsed: started.elapsed(),
                    error: None,
                },
                Err(error) => DialResult {
                    transport,
                    connection: None,
                    elapsed: started.elapsed(),
                    error: Some(error),
                },
            };
            if let Err(result) = sender.send(result) {
                result.0.close();
            }
        });
    }

    fn dial_transport(
        self: &Arc<Self>,
        transport: TransportChoice,
        target: &str,
    ) -> Result<ProxyConnection> {
        match transport {
            TransportChoice::Tcp => self.dial_tcp(target).map(ProxyConnection::Tcp),
            TransportChoice::Quic => self
                .quic_session()?
                .dial_stream_timeout(target, DIAL_TIME_LIMIT)
                .map(ProxyConnection::Quic),
        }
    }

    fn quic_session(self: &Arc<Self>) -> Result<Arc<QuicSession>> {
        if self.stop.load(Ordering::Acquire) {
            bail!("dialer stopped");
        }
        let attempt = {
            let mut state = self.state.lock().unwrap();
            if let Some(session) = state.quic.as_ref().filter(|session| !session.is_closed()) {
                return Ok(session.clone());
            }
            state.quic = None;
            if let Some(attempt) = state.quic_dial.as_ref() {
                attempt.clone()
            } else {
                let attempt = Arc::new(QuicDialAttempt::new());
                state.quic_dial = Some(attempt.clone());
                let dialer = self.clone();
                let connect_attempt = attempt.clone();
                std::thread::spawn(move || dialer.connect_quic(connect_attempt));
                attempt
            }
        };
        attempt.wait(&self.stop)
    }

    fn connect_quic(self: &Arc<Self>, attempt: Arc<QuicDialAttempt>) {
        let result = QuicSession::connect(&self.peer).map(Arc::new);
        let result = if self.stop.load(Ordering::Acquire) {
            if let Ok(session) = &result {
                session.close();
            }
            Err(anyhow!("dialer stopped"))
        } else {
            result
        };
        {
            let mut state = self.state.lock().unwrap();
            if state
                .quic_dial
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &attempt))
            {
                state.quic_dial = None;
            }
            if let Ok(session) = &result {
                state.quic = Some(session.clone());
            }
        }
        attempt.finish(result.map_err(|error| Arc::new(anyhow!("{error:#}"))));
    }

    fn record_success(&self, generation: u64, transport: TransportChoice, elapsed: Duration) {
        let mut state = self.state.lock().unwrap();
        if generation != state.generation || self.stop.load(Ordering::Acquire) {
            return;
        }
        if state.preferred != transport {
            state.preferred = transport;
            state.generation += 1;
            state.latency = elapsed;
            state.next_probe =
                Some(Instant::now() + random_duration(MIN_PROBE_INTERVAL, MAX_PROBE_INTERVAL));
        } else if state.latency.is_zero() {
            state.latency = elapsed;
            state.next_probe = Some(
                Instant::now() + random_duration(MIN_FIRST_PROBE_DELAY, MAX_FIRST_PROBE_DELAY),
            );
        } else {
            state.latency = state.latency * 3 / 4 + elapsed / 4;
        }
    }

    fn tcp_session(&self) -> Result<Session> {
        loop {
            if self.stop.load(Ordering::Acquire) {
                bail!("dialer stopped");
            }
            let claim = {
                let mut pool = self.tcp_pool.lock().unwrap();
                claim_tcp_pool(&mut pool)
            };
            match claim {
                TcpPoolClaim::Ready(session) => return Ok(session),
                TcpPoolClaim::Wait(attempt) => match attempt.wait(&self.stop) {
                    Ok(()) => continue,
                    Err(error) => return Err(anyhow!("TCP session dial failed: {error:#}")),
                },
                TcpPoolClaim::Lead => {}
            }

            let result = connect_tcp_session(&self.peer);
            let result = if self.stop.load(Ordering::Acquire) {
                if let Ok(session) = &result {
                    session.close();
                }
                Err(anyhow!("dialer stopped"))
            } else {
                result
            };
            let attempt = {
                let mut pool = self.tcp_pool.lock().unwrap();
                let attempt = pool.attempt.take();
                if let Ok(session) = &result {
                    pool.sessions.push(session.clone());
                }
                attempt
            };
            if let Some(attempt) = attempt {
                attempt.finish(match &result {
                    Ok(_) => Ok(()),
                    Err(error) => Err(Arc::new(anyhow!("{error:#}"))),
                });
            }
            return result;
        }
    }

    fn dial_tcp(&self, target: &str) -> Result<Stream> {
        for _ in 0..2 {
            let session = self.tcp_session()?;
            match open_tcp_stream(&session, target) {
                Ok(stream) => return Ok(stream),
                Err(error) if is_stream_limit(&error) => continue,
                Err(error) => {
                    if session.is_closed() {
                        self.tcp_pool
                            .lock()
                            .unwrap()
                            .sessions
                            .retain(|current| !current.same_session(&session));
                    }
                    return Err(error);
                }
            }
        }
        bail!("all TCP sessions reached the stream limit")
    }

    fn dial_udp_associate(&self) -> Result<Stream> {
        for _ in 0..2 {
            let session = self.tcp_session()?;
            match open_tcp_request(&session, &protocol::StreamRequest::UdpAssociate) {
                Ok(stream) => return Ok(stream),
                Err(error) if is_stream_limit(&error) => continue,
                Err(error) => return Err(error),
            }
        }
        bail!("all TCP sessions reached the stream limit")
    }

    fn close(&self) {
        let quic = {
            let mut state = self.state.lock().unwrap();
            state.next_probe = None;
            state.quic.take()
        };
        if let Some(session) = quic {
            session.close();
        }
        let sessions = {
            let mut pool = self.tcp_pool.lock().unwrap();
            std::mem::take(&mut pool.sessions)
        };
        for session in sessions {
            session.close();
        }
    }
}

fn drain_results(receiver: std::sync::mpsc::Receiver<DialResult>) {
    std::thread::spawn(move || {
        for result in receiver {
            result.close();
        }
    });
}
fn is_target_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<TargetConnectFailed>().is_some()
            || cause.downcast_ref::<TcpTargetConnectFailed>().is_some()
    })
}

fn is_stream_limit(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<StreamLimitReached>().is_some())
}

fn random_duration(minimum: Duration, maximum: Duration) -> Duration {
    let min_ms = minimum.as_millis() as u64;
    let max_ms = maximum.as_millis() as u64;
    Duration::from_millis(rand::thread_rng().gen_range(min_ms..=max_ms))
}

pub fn run(outbound: OutboundConfig, stop: Arc<AtomicBool>) -> Result<()> {
    let address = format!("{}:{}", outbound.socks_listen, outbound.socks_listen_port);
    let listener = TcpListener::bind(&address)
        .with_context(|| format!("listen on SOCKS5 address {address}"))?;
    listener
        .set_nonblocking(true)
        .context("configure SOCKS5 listener")?;
    info!("SOCKS5 listening on {}", listener.local_addr()?);
    let enable_quic = outbound.udp_enabled();
    let socks5_udp = outbound.socks5_udp;
    let dialer = Arc::new(Dialer::new(outbound, stop.clone(), enable_quic));

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, remote)) => {
                let dialer = dialer.clone();
                std::thread::spawn(move || {
                    if let Err(error) = handle_client(stream, &dialer, socks5_udp) {
                        debug!("SOCKS5 connection from {remote} ended: {error:#}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error).context("accept SOCKS5 connection"),
        }
    }
    dialer.close();
    Ok(())
}

fn handle_client(mut client: TcpStream, dialer: &Arc<Dialer>, socks5_udp: bool) -> Result<()> {
    client.set_nodelay(true).ok();
    let remote = client.peer_addr()?;
    debug!("accepted SOCKS5 connection from {remote}");
    let request = socks_handshake(&mut client, socks5_udp)?;
    match request {
        SocksRequest::Connect(target) => {
            info!("new connection from {remote} dest {target}");
            let connection = match dialer.dial(&target) {
                Ok(connection) => connection,
                Err(error) => {
                    warn!("dial failed for {target}: {error:#}");
                    let _ = socks_reply(&mut client, false);
                    return Err(error);
                }
            };
            socks_reply(&mut client, true)?;
            match connection {
                ProxyConnection::Tcp(stream) => {
                    let reader = stream.clone();
                    let writer = stream.clone();
                    let result = protocol::relay_halves(client, reader, writer)
                        .context("relay SOCKS5 TCP traffic");
                    let _ = stream.close();
                    result
                }
                ProxyConnection::Quic(stream) => {
                    let (reader, writer) = stream.split();
                    protocol::relay_halves(client, reader, writer)
                        .context("relay SOCKS5 QUIC traffic")
                }
            }
        }
        SocksRequest::UdpAssociate { port } => {
            info!("UDP associate from {remote} requested port {port}");
            handle_udp_associate(client, dialer, remote, port)
        }
    }
}

fn socks_handshake(client: &mut TcpStream, socks5_udp: bool) -> Result<SocksRequest> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting)?;
    if greeting[0] != 5 {
        bail!("unsupported SOCKS version {}", greeting[0]);
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff])?;
        bail!("client does not offer SOCKS5 no-authentication");
    }
    client.write_all(&[5, 0])?;

    let mut header = [0_u8; 4];
    client.read_exact(&mut header)?;
    if header[0] != 5 || !matches!(header[1], 1 | 3) || header[2] != 0 {
        client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        bail!("unsupported SOCKS5 request");
    }
    if header[1] == 3 && !socks5_udp {
        client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        bail!("SOCKS5 UDP ASSOCIATE is disabled");
    }
    let host = match header[3] {
        1 => {
            let mut ip = [0_u8; 4];
            client.read_exact(&mut ip)?;
            IpAddr::V4(Ipv4Addr::from(ip)).to_string()
        }
        3 => {
            let mut length = [0_u8; 1];
            client.read_exact(&mut length)?;
            if length[0] == 0 {
                bail!("empty SOCKS5 destination");
            }
            let mut name = vec![0_u8; length[0] as usize];
            client.read_exact(&mut name)?;
            String::from_utf8(name).map_err(|_| anyhow!("SOCKS5 domain is not UTF-8"))?
        }
        4 => {
            let mut ip = [0_u8; 16];
            client.read_exact(&mut ip)?;
            IpAddr::V6(ip.into()).to_string()
        }
        other => bail!("unsupported SOCKS5 address type {other}"),
    };
    let mut port = [0_u8; 2];
    client.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
    if header[1] == 3 {
        Ok(SocksRequest::UdpAssociate { port })
    } else {
        Ok(SocksRequest::Connect(format_target(&host, port)))
    }
}

fn handle_udp_associate(
    mut client: TcpStream,
    dialer: &Arc<Dialer>,
    remote: SocketAddr,
    requested_port: u16,
) -> Result<()> {
    let local_ip = client.local_addr()?.ip();
    let relay = UdpSocket::bind(SocketAddr::new(local_ip, 0))?;
    relay.set_read_timeout(Some(Duration::from_millis(100)))?;
    let tunnel = match dialer.dial_udp_associate() {
        Ok(tunnel) => tunnel,
        Err(error) => {
            let _ = socks_reply(&mut client, false);
            return Err(error);
        }
    };
    socks_reply_addr(&mut client, relay.local_addr()?)?;
    run_socks_udp(client, relay, tunnel, remote.ip(), requested_port)
}

fn run_socks_udp(
    mut control: TcpStream,
    relay: UdpSocket,
    tunnel: Stream,
    peer_ip: IpAddr,
    requested_port: u16,
) -> Result<()> {
    let done = Arc::new(AtomicBool::new(false));
    let client_addr = Arc::new(Mutex::new(None::<SocketAddr>));
    let writer = Arc::new(Mutex::new(tunnel.clone()));

    let mut tunnel_reader = tunnel.clone();
    let relay_for_replies = relay.try_clone()?;
    let reply_done = done.clone();
    let reply_client = client_addr.clone();
    let reply_thread = std::thread::spawn(move || {
        let mut buffer = vec![0_u8; protocol::MAX_DATAGRAM_SIZE];
        while !reply_done.load(Ordering::Acquire) {
            let datagram = match protocol::read_datagram(&mut tunnel_reader, &mut buffer) {
                Ok(datagram) => datagram,
                Err(_) => break,
            };
            let Some(address) = *reply_client.lock().unwrap() else {
                continue;
            };
            let mut packet = Vec::with_capacity(3 + datagram.len());
            packet.extend_from_slice(&[0, 0, 0]);
            packet.extend_from_slice(datagram);
            if relay_for_replies.send_to(&packet, address).is_err() {
                break;
            }
        }
        reply_done.store(true, Ordering::Release);
    });

    let control_done = done.clone();
    let control_shutdown = control.try_clone()?;
    let control_thread = std::thread::spawn(move || {
        let mut byte = [0_u8; 1];
        let _ = control.read(&mut byte);
        control_done.store(true, Ordering::Release);
    });

    let mut packet = vec![0_u8; protocol::MAX_DATAGRAM_SIZE + 3];
    while !done.load(Ordering::Acquire) {
        let (length, address) = match relay.recv_from(&mut packet) {
            Ok(value) => value,
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => {
                done.store(true, Ordering::Release);
                return Err(error.into());
            }
        };
        if address.ip() != peer_ip || (requested_port != 0 && address.port() != requested_port) {
            continue;
        }
        if length <= 3 || packet[..3] != [0, 0, 0] {
            continue;
        }
        let datagram = &packet[3..length];
        if protocol::parse_datagram(datagram).is_err() {
            continue;
        }
        {
            let mut client_addr = client_addr.lock().unwrap();
            if let Some(current) = *client_addr {
                if current != address {
                    continue;
                }
            } else {
                *client_addr = Some(address);
            }
        }
        let mut writer = writer.lock().unwrap();
        if protocol::write_datagram(&mut *writer, datagram).is_err() {
            done.store(true, Ordering::Release);
            break;
        }
    }

    done.store(true, Ordering::Release);
    let _ = control_shutdown.shutdown(Shutdown::Both);
    let _ = writer.lock().unwrap().close();
    let _ = reply_thread.join();
    let _ = control_thread.join();
    Ok(())
}

fn socks_reply_addr(client: &mut TcpStream, address: SocketAddr) -> Result<()> {
    let mut reply = vec![5, 0, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            reply.push(1);
            reply.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            reply.push(4);
            reply.extend_from_slice(&ip.octets());
        }
    }
    reply.extend_from_slice(&address.port().to_be_bytes());
    client.write_all(&reply)?;
    Ok(())
}

fn socks_reply(client: &mut TcpStream, success: bool) -> Result<()> {
    let status = if success { 0 } else { 1 };
    client.write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0])?;
    Ok(())
}

fn format_target(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn connect_tcp_session(peer: &OutboundConfig) -> Result<Session> {
    let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
    let server = format_target(&peer.server, peer.server_port);
    let handshake = tls::connect_chrome_until(&server, &peer.dest, peer.insecure, deadline)
        .with_context(|| format!("outer TLS handshake through {server}"))?;

    let server_public = parse_public_key(&peer.public_key)?;
    let client_private = StaticSecret::from(handshake.x25519_private);
    let shared = x25519_shared(&client_private, &server_public);
    let keys = ClientKeys::generate();
    let records = auth_records(
        &shared,
        &handshake.client_random,
        &handshake.server_random,
        &keys.share(),
    )?;
    let mut stream = handshake.stream;
    stream
        .set_write_timeout(Some(remaining_handshake(
            deadline,
            "send authentication records",
        )?))
        .context("set authentication write timeout")?;
    protocol::write_all(&mut stream, &records).context("send mio authentication records")?;

    let (send, recv) = transport_keys(
        &shared,
        None,
        &handshake.client_random,
        &handshake.server_random,
        true,
    )?;
    let reader = BufReader::new(stream.try_clone()?);
    let secure = Session::new(stream, reader, send, recv, true);
    let ready_timeout = READY_TIMEOUT.min(remaining_handshake(deadline, "wait for server ready")?);
    secure
        .set_read_timeout(Some(ready_timeout))
        .context("set ready timeout")?;
    let ready = secure.wait_ready().context("wait for server ready")?;
    let secret = keys.finish(&ready).context("derive hybrid secret")?;
    let (send, recv) = transport_keys(
        &shared,
        Some(&secret),
        &handshake.client_random,
        &handshake.server_random,
        true,
    )?;
    secure.rekey(send, recv);
    secure.set_read_timeout(None).ok();
    secure.start();
    Ok(secure)
}

fn remaining_handshake(deadline: Instant, phase: &str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        bail!("{phase} timed out");
    }
    Ok(remaining)
}

fn open_tcp_stream(session: &Session, target: &str) -> Result<Stream> {
    open_tcp_request(session, &protocol::StreamRequest::Tcp(target.to_string()))
}

fn open_tcp_request(session: &Session, request: &protocol::StreamRequest) -> Result<Stream> {
    let mut stream = session.open().context("open TCP target stream")?;
    stream.set_next_padding(16, 512);
    if let Err(error) = request.write_to(&mut stream) {
        let _ = stream.close();
        return Err(error);
    }
    let started = session.last_recv_nanos();
    stream.set_read_timeout(Some(REPLY_TIMEOUT));
    let connected = match protocol::read_reply(&mut stream) {
        Ok(connected) => connected,
        Err(error) => {
            let _ = stream.close();
            if error.chain().any(|cause| {
                cause
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
            }) && session.last_recv_nanos() <= started
            {
                session.close();
            }
            return Err(error);
        }
    };
    stream.set_read_timeout(None);
    if !connected {
        let _ = stream.close();
        return Err(TcpTargetConnectFailed.into());
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn tcp_pool_claims_only_one_leader() {
        let mut pool = TcpPoolState::default();
        let first = claim_tcp_pool(&mut pool);
        let second = claim_tcp_pool(&mut pool);
        assert!(matches!(first, TcpPoolClaim::Lead));
        assert!(matches!(second, TcpPoolClaim::Wait(_)));
        if let TcpPoolClaim::Wait(wait) = second {
            assert!(Arc::ptr_eq(&wait, pool.attempt.as_ref().unwrap()));
        }
    }

    #[test]
    fn initial_transport_is_tcp() {
        let config: OutboundConfig = toml::from_str(
            r#"
            socks_listen = "127.0.0.1"
            socks_listen_port = 1080
            server = "example.com"
            dest = "www.example.com"
            public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "#,
        )
        .unwrap();
        let dialer = Dialer::new(config, Arc::new(AtomicBool::new(false)), true);
        let state = dialer.state.lock().unwrap();
        assert_eq!(state.preferred, TransportChoice::Tcp);
        assert!(state.quic.is_none());
        assert!(state.next_probe.is_none());
    }

    #[test]
    fn probe_delays_have_expected_bounds() {
        for _ in 0..20 {
            let first = random_duration(MIN_FIRST_PROBE_DELAY, MAX_FIRST_PROBE_DELAY);
            assert!(first >= MIN_FIRST_PROBE_DELAY && first <= MAX_FIRST_PROBE_DELAY);
            let periodic = random_duration(MIN_PROBE_INTERVAL, MAX_PROBE_INTERVAL);
            assert!(periodic >= MIN_PROBE_INTERVAL && periodic <= MAX_PROBE_INTERVAL);
        }
    }

    #[test]
    fn tcp_dial_attempt_shares_one_failure() {
        let attempt = Arc::new(TcpDialAttempt::new());
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let attempt = attempt.clone();
                let barrier = barrier.clone();
                let stop = Arc::new(AtomicBool::new(false));
                std::thread::spawn(move || {
                    barrier.wait();
                    attempt.wait(&stop)
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let shared = Arc::new(anyhow!("one shared dial failure"));
        attempt.finish(Err(shared.clone()));
        let errors = handles
            .into_iter()
            .map(|handle| handle.join().unwrap().unwrap_err())
            .collect::<Vec<_>>();
        assert!(Arc::ptr_eq(&errors[0], &shared));
        assert!(Arc::ptr_eq(&errors[1], &shared));
    }
}
