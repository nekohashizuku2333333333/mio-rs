use anyhow::{Context, Result, anyhow, bail};
use hmac::{Hmac, Mac};
use log::{debug, info, warn};
use quinn::congestion::BbrConfig;
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{Connection, Endpoint, EndpointConfig, RecvStream, SendStream, TransportConfig};
use rand::{RngCore, rngs::OsRng};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{GetRandomFailed, SecureRandom};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::Sha256;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::runtime::{Builder, Handle, Runtime};

use crate::config::{InboundConfig, OutboundConfig};
use crate::crypto::{hkdf_key, parse_private_key, parse_public_key, x25519_shared};
use crate::protocol::{self, CloseWrite};
use crate::udp_demux::UdpDemuxSocket;
use x25519_dalek::{PublicKey, StaticSecret};

const QUIC_EXPORTER_LABEL: &[u8] = b"mio quic auth";
const QUIC_AUTH_INFO: &[u8] = b"mio quic auth 0.5.3";
const QUIC_MARKER_INFO: &[u8] = b"mio quic marker 0.5.3";
const QUIC_CLIENT_LABEL: &[u8] = b"client";
const QUIC_SERVER_LABEL: &[u8] = b"server";
const QUIC_AUTH_TIMEOUT: Duration = Duration::from_secs(5);
const QUIC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const QUIC_REPLY_TIMEOUT: Duration = Duration::from_secs(10);
const QUIC_READ_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, thiserror::Error)]
#[error("server could not connect to target")]
pub struct TargetConnectFailed;

#[derive(Debug)]
struct MarkerRandom {
    marker: [u8; 32],
    used: AtomicBool,
}

impl MarkerRandom {
    fn new(server_public: &PublicKey) -> Self {
        Self {
            marker: quic_marker(server_public),
            used: AtomicBool::new(false),
        }
    }
}

impl SecureRandom for MarkerRandom {
    fn fill(&self, buffer: &mut [u8]) -> Result<(), GetRandomFailed> {
        if buffer.len() == 32 && !self.used.swap(true, Ordering::SeqCst) {
            buffer.copy_from_slice(&self.marker);
            return Ok(());
        }
        OsRng.try_fill_bytes(buffer).map_err(|_| GetRandomFailed)
    }
}

fn quic_marker(server_public: &PublicKey) -> [u8; 32] {
    let mut marker = [0_u8; 32];
    OsRng.fill_bytes(&mut marker[..16]);
    let minute = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 60;
    let key = hkdf_key(server_public.as_bytes(), &[], QUIC_MARKER_INFO).expect("marker key");
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("HMAC key");
    mac.update(&marker[..16]);
    mac.update(&minute.to_be_bytes());
    let tag = mac.finalize().into_bytes();
    marker[16..].copy_from_slice(&tag[..16]);
    marker
}

fn proof(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(label);
    mac.finalize().into_bytes().into()
}

fn verify_proof(key: &[u8; 32], label: &[u8], proof: &[u8]) -> bool {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(label);
    mac.verify_slice(proof).is_ok()
}

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn client_quic_config(server_public: &PublicKey, initial_mtu: u16) -> Result<quinn::ClientConfig> {
    let mut provider = rustls::crypto::ring::default_provider();
    let random = Box::leak(Box::new(MarkerRandom::new(server_public)));
    provider.secure_random = random;
    let provider = Arc::new(provider);

    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| anyhow!("configure QUIC TLS versions: {error}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let crypto = QuicClientConfig::try_from(tls)
        .map_err(|error| anyhow!("configure QUIC TLS client: {error}"))?;
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    let mut bbr = BbrConfig::default();
    bbr.initial_window(u64::from(initial_mtu) * 32);
    transport
        .initial_mtu(initial_mtu)
        .congestion_controller_factory(Arc::new(bbr))
        .max_idle_timeout(Some(quinn::IdleTimeout::try_from(Duration::from_secs(30))?))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .stream_receive_window(quinn::VarInt::from_u64(16 << 20)?)
        .receive_window(quinn::VarInt::from_u64(32 << 20)?)
        .max_concurrent_bidi_streams(quinn::VarInt::from_u64(100)?)
        .max_concurrent_uni_streams(quinn::VarInt::from_u64(103)?);
    config.transport_config(Arc::new(transport));
    Ok(config)
}

fn server_quic_config(host: &str) -> Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec![host.to_string()])
        .map_err(|error| anyhow!("generate QUIC certificate: {error}"))?;
    let cert_der = cert.cert.der().clone();
    let key_der = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der.into())
        .map_err(|error| anyhow!("configure QUIC TLS server: {error}"))?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = QuicServerConfig::try_from(tls)
        .map_err(|error| anyhow!("configure QUIC TLS server: {error}"))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = TransportConfig::default();
    let mut bbr = BbrConfig::default();
    bbr.initial_window(1200 * 32);
    transport
        .initial_mtu(1200)
        .congestion_controller_factory(Arc::new(bbr))
        .max_idle_timeout(Some(quinn::IdleTimeout::try_from(Duration::from_secs(60))?))
        .keep_alive_interval(Some(Duration::from_secs(15)))
        .stream_receive_window(quinn::VarInt::from_u64(16 << 20)?)
        .receive_window(quinn::VarInt::from_u64(32 << 20)?)
        .max_concurrent_bidi_streams(quinn::VarInt::from_u64(1024)?)
        .max_concurrent_uni_streams(quinn::VarInt::from_u64(103)?)
        .enable_segmentation_offload(false);
    config.transport_config(Arc::new(transport));
    Ok(config)
}

pub struct QuicSession {
    connection: Connection,
    endpoint: Endpoint,
    runtime: Arc<Runtime>,
}

impl QuicSession {
    pub fn connect(peer: &OutboundConfig) -> Result<Self> {
        let server_public = parse_public_key(&peer.public_key)?;
        let address = resolve_udp(&peer.server, peer.server_port)?;
        let runtime = Arc::new(
            Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("create QUIC runtime")?,
        );
        let initial_mtu = if address.is_ipv4() { 1252 } else { 1232 };
        let (endpoint, connection) = runtime.block_on(async {
            let mut endpoint = Endpoint::client(if address.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            })
            .context("create QUIC client endpoint")?;
            endpoint.set_default_client_config(client_quic_config(&server_public, initial_mtu)?);
            let connecting = endpoint
                .connect(address, &peer.dest)
                .with_context(|| format!("start QUIC connection to {address}"))?;
            let connection = tokio::time::timeout(QUIC_CONNECT_TIMEOUT, connecting)
                .await
                .map_err(|_| anyhow!("QUIC handshake timed out"))?
                .context("QUIC handshake failed")?;
            Ok::<_, anyhow::Error>((endpoint, connection))
        })?;
        debug!("QUIC congestion control: Quinn experimental BBR, initial_mtu={initial_mtu}");
        let session = Self {
            runtime,
            endpoint,
            connection,
        };
        session.authenticate(&server_public)?;
        Ok(session)
    }

    fn authenticate(&self, server_public: &PublicKey) -> Result<()> {
        let mut exporter = [0_u8; 32];
        self.connection
            .export_keying_material(&mut exporter, QUIC_EXPORTER_LABEL, &[])
            .map_err(|error| anyhow!("export QUIC keying material: {error:?}"))?;
        let ephemeral = StaticSecret::random_from_rng(OsRng);
        let shared = x25519_shared(&ephemeral, server_public);
        let key = hkdf_key(&shared, &exporter, QUIC_AUTH_INFO)?;
        let mut message = Vec::with_capacity(64);
        message.extend_from_slice(PublicKey::from(&ephemeral).as_bytes());
        message.extend_from_slice(&proof(&key, QUIC_CLIENT_LABEL));

        let (mut send, mut recv) = self
            .runtime
            .block_on(async {
                tokio::time::timeout(QUIC_AUTH_TIMEOUT, self.connection.open_bi()).await
            })
            .map_err(|_| anyhow!("QUIC auth stream timed out"))?
            .context("open QUIC auth stream")?;
        self.runtime
            .block_on(async {
                send.write_all(&message).await?;
                let mut reply = [0_u8; 32];
                recv.read_exact(&mut reply).await?;
                Ok::<_, anyhow::Error>(reply)
            })
            .and_then(|reply| {
                if verify_proof(&key, QUIC_SERVER_LABEL, &reply) {
                    Ok(())
                } else {
                    bail!("QUIC server proof mismatch")
                }
            })?;
        let _ = send.finish();
        Ok(())
    }

    pub fn dial_stream(&self, target: &str) -> Result<QuicStream> {
        let (mut send, mut recv) = self
            .runtime
            .block_on(async {
                tokio::time::timeout(QUIC_CONNECT_TIMEOUT, self.connection.open_bi()).await
            })
            .map_err(|_| anyhow!("open QUIC stream timed out"))?
            .context("open QUIC stream")?;
        let mut request = Vec::new();
        protocol::write_request(&mut request, target)?;
        self.runtime
            .block_on(async { send.write_all(&request).await })
            .context("write target request over QUIC")?;
        let mut reply = [0_u8; 1];
        self.runtime
            .block_on(async {
                tokio::time::timeout(QUIC_REPLY_TIMEOUT, recv.read_exact(&mut reply)).await
            })
            .map_err(|_| anyhow!("QUIC target reply timed out"))?
            .context("read target reply over QUIC")?;
        if reply[0] != protocol::REPLY_OK {
            return Err(TargetConnectFailed.into());
        }
        let handle = self.runtime.handle().clone();
        Ok(QuicStream::new(handle, send, recv))
    }

    pub fn close(&self) {
        self.connection.close(0u32.into(), b"");
        self.endpoint.close(0u32.into(), b"");
    }
}

pub struct QuicReader {
    handle: Handle,
    recv: RecvStream,
    timeout: Option<Duration>,
}

impl QuicReader {
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }
}

impl Read for QuicReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let result = if let Some(timeout) = self.timeout {
            match self
                .handle
                .block_on(async { tokio::time::timeout(timeout, self.recv.read(buffer)).await })
            {
                Ok(result) => result,
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "QUIC read timed out",
                    ));
                }
            }
        } else {
            self.handle.block_on(async { self.recv.read(buffer).await })
        };
        match result {
            Ok(Some(length)) => Ok(length),
            Ok(None) => Ok(0),
            Err(error) => Err(io::Error::other(error.to_string())),
        }
    }
}

pub struct QuicWriter {
    handle: Handle,
    send: SendStream,
}

impl Write for QuicWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.handle
            .block_on(async { self.send.write_all(buffer).await })
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CloseWrite for QuicWriter {
    fn close_write(&mut self) -> io::Result<()> {
        self.send
            .finish()
            .map_err(|error| io::Error::other(error.to_string()))
    }
}

pub struct QuicStream {
    reader: QuicReader,
    writer: QuicWriter,
}

impl QuicStream {
    fn new(handle: Handle, send: SendStream, recv: RecvStream) -> Self {
        Self {
            reader: QuicReader {
                handle: handle.clone(),
                recv,
                timeout: Some(QUIC_READ_TIMEOUT),
            },
            writer: QuicWriter { handle, send },
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) {
        self.reader.set_timeout(timeout);
    }

    pub fn split(self) -> (QuicReader, QuicWriter) {
        (self.reader, self.writer)
    }
}

impl Read for QuicStream {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reader.read(buffer)
    }
}

impl Write for QuicStream {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writer.write(buffer)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

fn resolve_udp(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addresses = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve QUIC address {host}:{port}"))?;
    addresses
        .next()
        .ok_or_else(|| anyhow!("{host}:{port} resolved to no UDP addresses"))
}

pub fn run_server(config: InboundConfig, stop: Arc<AtomicBool>) -> Result<()> {
    let private_key = Arc::new(parse_private_key(&config.private_key)?);
    let public_key = PublicKey::from(private_key.as_ref());
    let address = format!("{}:{}", config.listen, config.listen_port)
        .parse::<SocketAddr>()
        .with_context(|| {
            format!(
                "parse QUIC listen address {}:{}",
                config.listen, config.listen_port
            )
        })?;
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("create QUIC server runtime")?;
    runtime.block_on(async move {
        let destination = resolve_udp(&config.dest, config.dest_port).ok();
        let socket = UdpDemuxSocket::bind(address, public_key, destination, stop.clone())
            .await
            .context("bind UDP demux socket")?;
        let quinn_runtime =
            quinn::default_runtime().ok_or_else(|| anyhow!("no Quinn async runtime available"))?;
        let endpoint = Endpoint::new_with_abstract_socket(
            EndpointConfig::default(),
            Some(server_quic_config(&config.dest)?),
            socket,
            quinn_runtime,
        )
        .context("create QUIC endpoint over UDP demux")?;
        info!("mio QUIC listening on {}", endpoint.local_addr()?);
        while !stop.load(Ordering::Relaxed) {
            let incoming =
                match tokio::time::timeout(Duration::from_millis(500), endpoint.accept()).await {
                    Ok(Some(incoming)) => incoming,
                    Ok(None) => break,
                    Err(_) => continue,
                };
            let private_key = private_key.clone();
            tokio::spawn(async move {
                if let Err(error) = serve_quic_connection(incoming, private_key).await {
                    debug!("QUIC connection ended: {error:#}");
                }
            });
        }
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(())
}

async fn serve_quic_connection(
    incoming: quinn::Incoming,
    server_private: Arc<StaticSecret>,
) -> Result<()> {
    let connection = incoming.await.context("accept QUIC handshake")?;
    let (mut send, mut recv) = tokio::time::timeout(QUIC_AUTH_TIMEOUT, connection.accept_bi())
        .await
        .map_err(|_| anyhow!("QUIC auth stream timed out"))?
        .context("accept QUIC auth stream")?;
    let mut message = [0_u8; 64];
    tokio::time::timeout(QUIC_AUTH_TIMEOUT, recv.read_exact(&mut message))
        .await
        .map_err(|_| anyhow!("QUIC auth message timed out"))?
        .context("read QUIC auth message")?;
    let mut exporter = [0_u8; 32];
    connection
        .export_keying_material(&mut exporter, QUIC_EXPORTER_LABEL, &[])
        .map_err(|error| anyhow!("export QUIC keying material: {error:?}"))?;
    let mut client_public = [0_u8; 32];
    client_public.copy_from_slice(&message[..32]);
    let shared = x25519_shared(server_private.as_ref(), &PublicKey::from(client_public));
    let key = hkdf_key(&shared, &exporter, QUIC_AUTH_INFO)?;
    if !verify_proof(&key, QUIC_CLIENT_LABEL, &message[32..]) {
        bail!("QUIC client proof mismatch");
    }
    send.write_all(&proof(&key, QUIC_SERVER_LABEL))
        .await
        .context("write QUIC server proof")?;
    send.finish()?;
    info!(
        "authenticated QUIC client from {}",
        connection.remote_address()
    );

    loop {
        let (send, recv) = match connection.accept_bi().await {
            Ok(stream) => stream,
            Err(error) => {
                debug!("QUIC connection closed: {error}");
                return Ok(());
            }
        };
        let handle = Handle::current();
        let stream = QuicStream::new(handle, send, recv);
        std::thread::spawn(move || {
            if let Err(error) = proxy_quic(stream) {
                warn!("QUIC proxy failed: {error:#}");
            }
        });
    }
}

fn proxy_quic(mut stream: QuicStream) -> Result<()> {
    stream.set_read_timeout(Some(QUIC_REPLY_TIMEOUT));
    let target = protocol::read_request(&mut stream).context("read QUIC target request")?;
    stream.set_read_timeout(None);
    let remote = match connect_target(&target) {
        Ok(remote) => remote,
        Err(error) => {
            warn!("connect target {target} over QUIC failed: {error:#}");
            protocol::write_reply(&mut stream, false)?;
            stream.flush()?;
            return Ok(());
        }
    };
    protocol::write_reply(&mut stream, true)?;
    stream.flush()?;
    info!("QUIC proxy target {target}");
    let (reader, writer) = stream.split();
    protocol::relay_halves(remote, reader, writer).context("relay QUIC target traffic")
}

fn connect_target(target: &str) -> Result<std::net::TcpStream> {
    let (host, port) = protocol::split_host_port(target)?;
    let port = port
        .parse::<u16>()
        .map_err(|_| anyhow!("invalid target port"))?;
    let mut last_error = None;
    for address in (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?
    {
        match std::net::TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
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
