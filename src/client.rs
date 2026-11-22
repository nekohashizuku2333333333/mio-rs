use anyhow::{Context, Result, anyhow, bail};
use log::{debug, info, warn};
use rand::Rng;
use std::io::{BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::OutboundConfig;
use crate::crypto::{ClientKeys, auth_records, parse_public_key, transport_keys, x25519_shared};
use crate::protocol;
use crate::quic::{QuicSession, QuicStream, TargetConnectFailed};
use crate::session::{Session, Stream};
use crate::tls;
use x25519_dalek::StaticSecret;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
struct SocksRequest {
    target: String,
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
    Unknown,
    Tcp,
    Quic,
}

struct DialerState {
    session: Option<Arc<QuicSession>>,
    selected: TransportChoice,
    probing: bool,
    next_probe: Instant,
    tcp_latency: Duration,
    quic_latency: Duration,
}

struct Dialer {
    peer: OutboundConfig,
    tcp_pool: Mutex<TcpPoolState>,
    state: Mutex<DialerState>,
}

#[derive(Default)]
struct TcpPoolState {
    session: Option<Session>,
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
    if let Some(session) = pool.session.as_ref()
        && !session.is_closed()
        && session.num_streams() < 100
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

    fn wait(&self) -> Result<(), Arc<anyhow::Error>> {
        let mut result = self.result.lock().unwrap();
        while result.is_none() {
            result = self.ready.wait(result).unwrap();
        }
        match result.as_ref().expect("dial result initialized") {
            Ok(()) => Ok(()),
            Err(error) => Err(error.clone()),
        }
    }
}

enum DialChoice {
    Probe,
    Tcp,
    Quic(Arc<QuicSession>),
}

struct ProbeResult {
    transport: TransportChoice,
    connection: Result<ProxyConnection>,
    session: Option<Arc<QuicSession>>,
    elapsed: Duration,
}

impl Dialer {
    fn new(peer: OutboundConfig) -> Self {
        Self {
            peer,
            tcp_pool: Mutex::new(TcpPoolState::default()),
            state: Mutex::new(DialerState {
                session: None,
                selected: TransportChoice::Unknown,
                probing: false,
                next_probe: Instant::now(),
                tcp_latency: Duration::ZERO,
                quic_latency: Duration::ZERO,
            }),
        }
    }

    fn warm_up(&self, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            match QuicSession::connect(&self.peer) {
                Ok(session) => {
                    let mut state = self.state.lock().unwrap();
                    if state.session.is_none() {
                        state.session = Some(Arc::new(session));
                        info!("QUIC warm-up succeeded");
                    }
                    return;
                }
                Err(error) => {
                    debug!("QUIC warm-up failed: {error:#}");
                }
            }
            for _ in 0..10 {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    fn dial(self: &Arc<Self>, target: &str) -> Result<ProxyConnection> {
        let choice = {
            let mut state = self.state.lock().unwrap();
            if state.probing {
                match (&state.session, state.selected) {
                    (Some(session), TransportChoice::Quic) => DialChoice::Quic(session.clone()),
                    _ => DialChoice::Tcp,
                }
            } else if state.selected == TransportChoice::Unknown
                || Instant::now() >= state.next_probe
            {
                state.probing = true;
                DialChoice::Probe
            } else {
                match (&state.session, state.selected) {
                    (Some(session), TransportChoice::Quic) => DialChoice::Quic(session.clone()),
                    _ => DialChoice::Tcp,
                }
            }
        };

        match choice {
            DialChoice::Probe => self.probe(target),
            DialChoice::Tcp => {
                match self.dial_tcp(target) {
                    Ok(stream) => Ok(ProxyConnection::Tcp(stream)),
                    Err(tcp_error) => {
                        if is_target_failure(&tcp_error) {
                            return Err(tcp_error);
                        }
                        // A TCP transport failure may still be recoverable over QUIC.
                        let session = self.state.lock().unwrap().session.clone();
                        if let Some(session) = session {
                            match session.dial_stream(target) {
                                Ok(stream) => {
                                    self.install_quic(session);
                                    return Ok(ProxyConnection::Quic(stream));
                                }
                                Err(quic_error) => {
                                    return Err(anyhow!(
                                        "TCP failed: {tcp_error:#}; QUIC fallback failed: {quic_error:#}"
                                    ));
                                }
                            }
                        }
                        Err(tcp_error)
                    }
                }
            }
            DialChoice::Quic(session) => match session.dial_stream(target) {
                Ok(stream) => Ok(ProxyConnection::Quic(stream)),
                Err(error) => {
                    if is_target_failure(&error) {
                        return Err(error);
                    }
                    warn!("QUIC stream failed for {target}, falling back to TCP: {error:#}");
                    session.close();
                    let mut state = self.state.lock().unwrap();
                    if state
                        .session
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, &session))
                    {
                        state.session = None;
                    }
                    state.selected = TransportChoice::Tcp;
                    drop(state);
                    self.dial_tcp(target).map(ProxyConnection::Tcp)
                }
            },
        }
    }

    fn tcp_session(&self) -> Result<Session> {
        loop {
            let claim = {
                let mut pool = self.tcp_pool.lock().unwrap();
                claim_tcp_pool(&mut pool)
            };

            match claim {
                TcpPoolClaim::Ready(session) => return Ok(session),
                TcpPoolClaim::Wait(attempt) => match attempt.wait() {
                    Ok(()) => continue,
                    Err(error) => return Err(anyhow!("TCP session dial failed: {error:#}")),
                },
                TcpPoolClaim::Lead => {}
            }

            let result = connect_tcp_session(&self.peer);
            let attempt = {
                let mut pool = self.tcp_pool.lock().unwrap();
                let attempt = pool.attempt.take();
                if let Ok(session) = &result {
                    pool.session = Some(session.clone());
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
        let session = self.tcp_session()?;
        let result = open_tcp_stream(&session, target);
        if result.is_err() && session.is_closed() {
            let mut pool = self.tcp_pool.lock().unwrap();
            if pool
                .session
                .as_ref()
                .is_some_and(|current| current.same_session(&session))
            {
                pool.session = None;
            }
        }
        result
    }

    fn probe(self: &Arc<Self>, target: &str) -> Result<ProxyConnection> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let tcp_sender = sender.clone();
        let tcp_peer = self.peer.clone();
        let tcp_target = target.to_string();
        std::thread::spawn(move || {
            let started = Instant::now();
            let connection = dial_tcp_once(&tcp_peer, &tcp_target).map(ProxyConnection::Tcp);
            let _ = tcp_sender.send(ProbeResult {
                transport: TransportChoice::Tcp,
                connection,
                session: None,
                elapsed: started.elapsed(),
            });
        });

        let quic_dialer = self.clone();
        let quic_target = target.to_string();
        std::thread::spawn(move || {
            let started = Instant::now();
            let session = quic_dialer.state.lock().unwrap().session.clone();
            let (connection, owning_session) = match session {
                Some(session) => {
                    let connection = session.dial_stream(&quic_target).map(ProxyConnection::Quic);
                    (connection, None)
                }
                None => match QuicSession::connect(&quic_dialer.peer) {
                    Ok(session) => {
                        let session = Arc::new(session);
                        let connection =
                            session.dial_stream(&quic_target).map(ProxyConnection::Quic);
                        (connection, Some(session))
                    }
                    Err(error) => (Err(error), None),
                },
            };
            let _ = sender.send(ProbeResult {
                transport: TransportChoice::Quic,
                connection,
                session: owning_session,
                elapsed: started.elapsed(),
            });
        });

        let mut first_error = None;
        for _ in 0..2 {
            let result = match receiver.recv() {
                Ok(result) => result,
                Err(error) => {
                    self.finish_probe_failure();
                    return Err(anyhow!("transport probe channel failed: {error}"));
                }
            };
            let ProbeResult {
                transport,
                connection,
                session,
                elapsed,
            } = result;
            match connection {
                Ok(connection) => {
                    self.finish_probe_winner(transport, session.as_ref(), elapsed);
                    return Ok(connection);
                }
                Err(error) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
        }
        self.finish_probe_failure();
        Err(first_error.unwrap_or_else(|| anyhow!("both transport probes failed")))
    }

    fn finish_probe_winner(
        &self,
        transport: TransportChoice,
        session: Option<&Arc<QuicSession>>,
        elapsed: Duration,
    ) {
        let mut state = self.state.lock().unwrap();
        state.probing = false;
        state.selected = transport;
        state.next_probe = Instant::now() + random_probe_interval();
        match transport {
            TransportChoice::Tcp => {
                state.tcp_latency = smooth_latency(state.tcp_latency, elapsed);
            }
            TransportChoice::Quic => {
                state.quic_latency = smooth_latency(state.quic_latency, elapsed);
                if let Some(session) = session {
                    state.session = Some(session.clone());
                }
            }
            TransportChoice::Unknown => {}
        }
        info!(
            "transport selected: {:?} (tcp={:?}, quic={:?})",
            transport, state.tcp_latency, state.quic_latency
        );
    }

    fn finish_probe_failure(&self) {
        let mut state = self.state.lock().unwrap();
        state.probing = false;
        state.selected = TransportChoice::Tcp;
        state.next_probe = Instant::now() + random_probe_interval();
    }

    fn install_quic(&self, session: Arc<QuicSession>) {
        let mut state = self.state.lock().unwrap();
        state.session = Some(session);
        state.selected = TransportChoice::Quic;
    }
}

fn smooth_latency(previous: Duration, sample: Duration) -> Duration {
    if previous.is_zero() {
        sample
    } else {
        (previous * 3 + sample) / 4
    }
}

fn is_target_failure(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.downcast_ref::<TargetConnectFailed>().is_some()
            || cause.downcast_ref::<TcpTargetConnectFailed>().is_some()
    })
}

fn random_probe_interval() -> Duration {
    let seconds = rand::thread_rng().gen_range(10 * 60..=30 * 60);
    Duration::from_secs(seconds)
}

pub fn run(outbound: OutboundConfig, stop: Arc<AtomicBool>) -> Result<()> {
    let address = format!("{}:{}", outbound.socks_listen, outbound.socks_listen_port);
    let listener = TcpListener::bind(&address)
        .with_context(|| format!("listen on SOCKS5 address {address}"))?;
    listener
        .set_nonblocking(true)
        .context("configure SOCKS5 listener")?;
    info!("SOCKS5 listening on {}", listener.local_addr()?);
    let dialer = Arc::new(Dialer::new(outbound));
    let warmup_dialer = dialer.clone();
    let warmup_stop = stop.clone();
    std::thread::spawn(move || warmup_dialer.warm_up(&warmup_stop));

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, remote)) => {
                let dialer = dialer.clone();
                std::thread::spawn(move || {
                    if let Err(error) = handle_client(stream, &dialer) {
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
    Ok(())
}

fn handle_client(mut client: TcpStream, dialer: &Arc<Dialer>) -> Result<()> {
    client.set_nodelay(true).ok();
    let remote = client.peer_addr()?;
    debug!("accepted SOCKS5 connection from {remote}");
    let request = socks_handshake(&mut client)?;
    info!("new connection from {} dest {}", remote, request.target);

    let connection = match dialer.dial(&request.target) {
        Ok(connection) => connection,
        Err(error) => {
            warn!("dial failed for {}: {error:#}", request.target);
            let _ = socks_reply(&mut client, false);
            return Err(error);
        }
    };
    socks_reply(&mut client, true)?;
    match connection {
        ProxyConnection::Tcp(stream) => {
            let reader = stream.clone();
            let writer = stream.clone();
            let result =
                protocol::relay_halves(client, reader, writer).context("relay SOCKS5 TCP traffic");
            let _ = stream.close();
            result
        }
        ProxyConnection::Quic(stream) => {
            let (reader, writer) = stream.split();
            protocol::relay_halves(client, reader, writer).context("relay SOCKS5 QUIC traffic")
        }
    }
}

fn socks_handshake(client: &mut TcpStream) -> Result<SocksRequest> {
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
    if header[0] != 5 || header[1] != 1 || header[2] != 0 {
        client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        bail!("unsupported SOCKS5 request");
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
    let target = format_target(&host, port);
    Ok(SocksRequest { target })
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
    let mut stream = session.open().context("open TCP target stream")?;
    stream.set_next_padding(16, 512);
    if let Err(error) = protocol::write_request(&mut stream, target) {
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

fn dial_tcp_once(peer: &OutboundConfig, target: &str) -> Result<Stream> {
    let session = connect_tcp_session(peer)?;
    open_tcp_stream(&session, target)
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
    fn tcp_dial_attempt_shares_one_failure() {
        let attempt = Arc::new(TcpDialAttempt::new());
        let barrier = Arc::new(Barrier::new(3));
        let handles = (0..2)
            .map(|_| {
                let attempt = attempt.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    attempt.wait()
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
