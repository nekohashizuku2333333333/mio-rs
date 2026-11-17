use anyhow::{Context, Result, anyhow};
use log::{debug, info, warn};
use std::io::BufReader;
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::config::InboundConfig;
use crate::crypto::{parse_private_key, read_share, server_exchange, transport_keys, verify_auth};
use crate::protocol::{
    self, CopyOutcome, HANDSHAKE_SERVER_HELLO, RECORD_APPDATA, RECORD_HANDSHAKE, RecordAction,
};
use crate::quic;
use crate::session::{Session, Stream};
use crate::tls;
use x25519_dalek::StaticSecret;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const SHARE_TIMEOUT: Duration = Duration::from_secs(5);
/// Client Application Data records inspected for authentication after the handshake.
const MAX_AUTH_ATTEMPTS: usize = 8;

#[derive(Default)]
struct RelayState {
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    client_key_share: Option<[u8; 32]>,
    auth_shared: Option<[u8; 32]>,
    destination_done: bool,
}

struct SharedState {
    state: Mutex<RelayState>,
    changed: Condvar,
    authenticated: AtomicBool,
}

impl SharedState {
    fn new() -> Self {
        Self {
            state: Mutex::new(RelayState::default()),
            changed: Condvar::new(),
            authenticated: AtomicBool::new(false),
        }
    }

    fn set_server_random(&self, random: [u8; 32]) {
        let mut state = self.state.lock().unwrap();
        state.server_random = Some(random);
        self.changed.notify_all();
    }

    fn set_client_hello(&self, random: [u8; 32], key_share: [u8; 32]) {
        let mut state = self.state.lock().unwrap();
        state.client_random = Some(random);
        state.client_key_share = Some(key_share);
    }

    fn set_authenticated(&self, shared: [u8; 32]) {
        let mut state = self.state.lock().unwrap();
        state.auth_shared = Some(shared);
        self.authenticated.store(true, Ordering::Release);
        self.changed.notify_all();
    }

    fn is_authenticated(&self) -> bool {
        self.authenticated.load(Ordering::Acquire)
    }

    fn mark_destination_done(&self) {
        let mut state = self.state.lock().unwrap();
        state.destination_done = true;
        self.changed.notify_all();
    }

    fn wait_destination_done(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut state = self.state.lock().unwrap();
        while !state.destination_done {
            let now = Instant::now();
            if now >= deadline {
                return;
            }
            let remaining = deadline - now;
            let (next, _) = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
        }
    }
}

pub fn run(config: InboundConfig, stop: Arc<AtomicBool>) -> Result<()> {
    let private_key = Arc::new(parse_private_key(&config.private_key)?);
    let address = format!("{}:{}", config.listen, config.listen_port);
    let listener =
        TcpListener::bind(&address).with_context(|| format!("listen on mio address {address}"))?;
    listener
        .set_nonblocking(true)
        .context("configure mio listener")?;
    info!("mio TCP listening on {}", listener.local_addr()?);
    let quic_config = config.clone();
    let quic_stop = stop.clone();
    std::thread::spawn(move || {
        if let Err(error) = quic::run_server(quic_config, quic_stop) {
            warn!("QUIC disabled: {error:#}");
        }
    });

    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, remote)) => {
                let config = config.clone();
                let private_key = private_key.clone();
                std::thread::spawn(move || {
                    if let Err(error) = serve_connection(stream, &config, &private_key) {
                        debug!("connection from {remote} ended: {error:#}");
                    }
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error).context("accept mio connection"),
        }
    }
    Ok(())
}

fn serve_connection(
    client: TcpStream,
    config: &InboundConfig,
    server_private: &StaticSecret,
) -> Result<()> {
    client.set_nodelay(true).ok();
    let remote = client.peer_addr()?;
    let dest_port = if config.dest_port == 0 {
        config.listen_port
    } else {
        config.dest_port
    };
    let destination_address = format!("{}:{dest_port}", config.dest);
    let mut destination = connect_target(&config.dest, dest_port)
        .with_context(|| format!("connect camouflage destination {destination_address}"))?;

    let state = Arc::new(SharedState::new());
    let destination_reader = destination.try_clone()?;
    let mut client_writer_for_destination = client.try_clone()?;
    let client_reader = BufReader::new(client.try_clone()?);

    let state_for_destination = state.clone();
    let destination_task = std::thread::spawn(move || {
        let mut reader = BufReader::new(destination_reader);
        let result = protocol::copy_records(
            &mut client_writer_for_destination,
            &mut reader,
            |header, body| {
                if header[0] == RECORD_HANDSHAKE
                    && body.len() >= 38
                    && body[0] == HANDSHAKE_SERVER_HELLO
                {
                    let mut random = [0_u8; 32];
                    random.copy_from_slice(&body[6..38]);
                    state_for_destination.set_server_random(random);
                    RecordAction::Forward
                } else if header[0] == RECORD_APPDATA {
                    RecordAction::Passthrough
                } else {
                    RecordAction::Forward
                }
            },
        );
        if !state_for_destination.is_authenticated() {
            if matches!(result, Ok(CopyOutcome::EndOfStream)) {
                let _ = client_writer_for_destination.shutdown(std::net::Shutdown::Write);
            } else {
                let _ = client_writer_for_destination.shutdown(std::net::Shutdown::Both);
            }
        }
        state_for_destination.mark_destination_done();
        result
    });

    let mut client_reader = client_reader;
    let state_for_client = state.clone();
    let mut auth_attempts = 0;
    let outcome = protocol::copy_records(&mut destination, &mut client_reader, |header, body| {
        if header[0] == RECORD_HANDSHAKE {
            let client_random = {
                let state = state_for_client.state.lock().unwrap();
                state.client_random
            };
            if client_random.is_none() {
                let mut record = Vec::with_capacity(header.len() + body.len());
                record.extend_from_slice(header);
                record.extend_from_slice(body);
                if let Ok((random, key_share)) = tls::parse_client_hello_security(&record) {
                    state_for_client.set_client_hello(random, key_share);
                }
            }
            return RecordAction::Forward;
        }
        if header[0] != RECORD_APPDATA {
            return RecordAction::Forward;
        }
        let (client_random, client_key_share, server_random) = {
            let state = state_for_client.state.lock().unwrap();
            (
                state.client_random,
                state.client_key_share,
                state.server_random,
            )
        };
        let (Some(client_random), Some(client_key_share), Some(server_random)) =
            (client_random, client_key_share, server_random)
        else {
            return RecordAction::Passthrough;
        };
        if let Some(shared) = verify_auth(
            server_private,
            &client_key_share,
            &client_random,
            &server_random,
            header,
            body,
        ) {
            debug!("static-key authentication verified");
            state_for_client.set_authenticated(shared);
            return RecordAction::Claim;
        }
        auth_attempts += 1;
        if auth_attempts >= MAX_AUTH_ATTEMPTS {
            debug!("authentication attempt limit reached; passing through");
            return RecordAction::Passthrough;
        }
        debug!("application-data record is not mio authentication");
        RecordAction::Forward
    });

    if !matches!(outcome, Ok(CopyOutcome::Claimed)) {
        if matches!(outcome, Ok(CopyOutcome::EndOfStream)) {
            let _ = destination.shutdown(std::net::Shutdown::Write);
            let _ = destination_task.join();
        } else {
            let _ = destination.shutdown(std::net::Shutdown::Both);
            let _ = destination_task.join();
        }
        return Ok(());
    }
    let _ = destination.shutdown(std::net::Shutdown::Both);
    state.wait_destination_done(Duration::from_secs(2));
    let _ = destination_task.join();

    let (client_random, server_random, shared) = {
        let state = state.state.lock().unwrap();
        (
            state
                .client_random
                .ok_or_else(|| anyhow!("missing client_random"))?,
            state
                .server_random
                .ok_or_else(|| anyhow!("missing server_random"))?,
            state
                .auth_shared
                .ok_or_else(|| anyhow!("missing authentication shared key"))?,
        )
    };

    client
        .set_read_timeout(Some(SHARE_TIMEOUT))
        .context("set share record timeout")?;
    let shared_key = read_share(&mut client_reader, &shared, &client_random, &server_random)
        .context("read client hybrid share record")?;
    client
        .set_read_timeout(None)
        .context("clear share record timeout")?;
    let (reply, secret) = server_exchange(&shared_key)?;
    let (send, recv) = transport_keys(&shared, None, &client_random, &server_random, false)?;
    let session = Session::new(client, client_reader, send, recv, false);
    session.write_ready(&reply)?;
    let (send, recv) = transport_keys(
        &shared,
        Some(&secret),
        &client_random,
        &server_random,
        false,
    )?;
    session.rekey(send, recv);
    session.start();
    info!("authenticated client from {remote}");
    loop {
        match session.accept() {
            Ok(stream) => {
                std::thread::spawn(move || {
                    if let Err(error) = proxy_stream(stream) {
                        debug!("proxied stream ended: {error:#}");
                    }
                });
            }
            Err(error) => {
                session.close();
                return Err(error);
            }
        }
    }
}

fn proxy_stream(mut stream: Stream) -> Result<()> {
    stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let target = protocol::read_request(&mut stream).context("read target request")?;
    stream.set_read_timeout(None);

    let remote = match connect_target_from_authority(&target) {
        Ok(remote) => remote,
        Err(error) => {
            warn!("connect target {target} failed: {error:#}");
            stream.set_next_padding(16, 512);
            protocol::write_reply(&mut stream, false)?;
            stream.close()?;
            return Ok(());
        }
    };

    stream.set_next_padding(16, 512);
    protocol::write_reply(&mut stream, true)?;
    info!("proxy target {target}");
    let reader = stream.clone();
    let writer = stream.clone();
    protocol::relay_halves(remote, reader, writer).context("relay target traffic")?;
    stream.close()?;
    Ok(())
}

fn connect_target_from_authority(target: &str) -> Result<TcpStream> {
    let (host, port) = protocol::split_host_port(target)?;
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow!("invalid target port"))?;
    connect_target(host, port)
}

fn connect_target(host: &str, port: u16) -> Result<TcpStream> {
    let mut last_error = None;
    for address in (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?
    {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                stream.set_nodelay(true).ok();
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("{host}:{port} resolved to no addresses")))
}
