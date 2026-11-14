use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit as AesKeyInit};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc};
use x25519_dalek::PublicKey;

use crate::crypto::hkdf_key;

const QUIC_MARKER_INFO: &[u8] = b"mio quic marker 0.5.1";

const QUIC_V1_VERSION: u32 = 1;
const MAX_PENDING_PACKETS: usize = 4;
const PENDING_TIMEOUT: Duration = Duration::from_secs(5);
const RELAY_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MIO_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const MARKER_NONCE_SIZE: usize = 16;
const MARKER_TAG_SIZE: usize = 16;
const MARKER_RETENTION: Duration = Duration::from_secs(3 * 60);
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InitialStatus {
    None,
    Incomplete,
    Random,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowKind {
    Pending,
    Mio,
    Relay,
}

struct Flow {
    kind: FlowKind,
    pending: Vec<Vec<u8>>,
    relay: Option<Arc<UdpSocket>>,
    cancel: Option<Arc<Notify>>,
    last: Instant,
}

struct ReplayCache {
    seen: HashMap<[u8; MARKER_NONCE_SIZE], Instant>,
}

impl ReplayCache {
    fn new() -> Self {
        Self {
            seen: HashMap::new(),
        }
    }

    fn check(&mut self, key: &[u8; 32], random: &[u8]) -> bool {
        if random.len() != MARKER_NONCE_SIZE + MARKER_TAG_SIZE {
            return false;
        }
        let mut nonce = [0_u8; MARKER_NONCE_SIZE];
        nonce.copy_from_slice(&random[..MARKER_NONCE_SIZE]);
        let tag = &random[MARKER_NONCE_SIZE..];
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / 60;
        let valid = [now_ms.saturating_sub(1), now_ms, now_ms + 1]
            .into_iter()
            .any(|minute| marker_tag(key, &nonce, minute) == tag);
        if !valid {
            return false;
        }
        self.seen
            .retain(|_, expiration| *expiration > Instant::now());
        if self.seen.contains_key(&nonce) {
            return false;
        }
        self.seen.insert(nonce, Instant::now() + MARKER_RETENTION);
        true
    }
}

fn marker_tag(key: &[u8; 32], nonce: &[u8; MARKER_NONCE_SIZE], minute: u64) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC key");
    mac.update(nonce);
    mac.update(&minute.to_be_bytes());
    mac.finalize().into_bytes()[..MARKER_TAG_SIZE].to_vec()
}

pub struct UdpDemuxSocket {
    socket: Arc<UdpSocket>,
    incoming_tx: mpsc::UnboundedSender<(Vec<u8>, SocketAddr)>,
    incoming_rx: Mutex<mpsc::UnboundedReceiver<(Vec<u8>, SocketAddr)>>,
    marker_key: [u8; 32],
    destination: Option<SocketAddr>,
    flows: Arc<Mutex<HashMap<SocketAddr, Flow>>>,
    replay: Arc<Mutex<ReplayCache>>,
}

impl fmt::Debug for UdpDemuxSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpDemuxSocket")
            .field("local_addr", &self.socket.local_addr())
            .field("destination", &self.destination)
            .finish_non_exhaustive()
    }
}

impl UdpDemuxSocket {
    pub async fn bind(
        address: SocketAddr,
        server_public: PublicKey,
        destination: Option<SocketAddr>,
        stop: Arc<AtomicBool>,
    ) -> io::Result<Arc<Self>> {
        let socket = Arc::new(UdpSocket::bind(address).await?);
        let marker_key =
            hkdf_key(server_public.as_bytes(), &[], QUIC_MARKER_INFO).map_err(io::Error::other)?;
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel();
        let demux = Arc::new(Self {
            socket,
            incoming_tx,
            incoming_rx: Mutex::new(incoming_rx),
            marker_key,
            destination,
            flows: Arc::new(Mutex::new(HashMap::new())),
            replay: Arc::new(Mutex::new(ReplayCache::new())),
        });

        let reader = demux.clone();
        let reader_stop = stop.clone();
        tokio::spawn(async move { reader.read_loop(reader_stop).await });
        let cleaner = demux.clone();
        tokio::spawn(async move { cleaner.cleanup_loop(stop).await });
        Ok(demux)
    }

    async fn read_loop(self: Arc<Self>, stop: Arc<AtomicBool>) {
        let mut buffer = vec![0_u8; 65_535];
        while !stop.load(Ordering::Relaxed) {
            tokio::select! {
                result = self.socket.recv_from(&mut buffer) => {
                    match result {
                        Ok((length, address)) => {
                            self.handle_packet(address, buffer[..length].to_vec()).await;
                        }
                        Err(error) => {
                            log::debug!("UDP demux receive failed: {error}");
                            return;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
        }
    }

    async fn handle_packet(&self, address: SocketAddr, packet: Vec<u8>) {
        enum Action {
            None,
            Mio(Vec<Vec<u8>>),
            Relay(Vec<Vec<u8>>),
            RelaySend(Arc<UdpSocket>, Vec<u8>),
        }

        let action = {
            let mut flows = self.flows.lock().unwrap();
            let flow = flows.entry(address).or_insert_with(|| Flow {
                kind: FlowKind::Pending,
                pending: Vec::new(),
                relay: None,
                cancel: None,
                last: Instant::now(),
            });
            flow.last = Instant::now();

            match flow.kind {
                FlowKind::Mio => Action::Mio(vec![packet]),
                FlowKind::Relay => flow.relay.as_ref().map_or(Action::None, |relay| {
                    Action::RelaySend(relay.clone(), packet)
                }),
                FlowKind::Pending => {
                    let (random, status) = initial_client_hello_random(&packet);
                    match status {
                        InitialStatus::Random
                            if random.as_deref().is_some_and(|random| {
                                self.replay.lock().unwrap().check(&self.marker_key, random)
                            }) =>
                        {
                            flow.kind = FlowKind::Mio;
                            let mut packets = std::mem::take(&mut flow.pending);
                            packets.push(packet);
                            Action::Mio(packets)
                        }
                        InitialStatus::Incomplete if flow.pending.len() < MAX_PENDING_PACKETS => {
                            flow.pending.push(packet);
                            Action::None
                        }
                        _ => {
                            flow.kind = FlowKind::Relay;
                            let mut packets = std::mem::take(&mut flow.pending);
                            packets.push(packet);
                            Action::Relay(packets)
                        }
                    }
                }
            }
        };

        match action {
            Action::None => {}
            Action::Mio(packets) => {
                for packet in packets {
                    let _ = self.incoming_tx.send((packet, address));
                }
            }
            Action::Relay(packets) => {
                self.start_relay(address, packets).await;
            }
            Action::RelaySend(relay, packet) => {
                if let Err(error) = relay.send(&packet).await {
                    log::debug!("UDP relay send failed for {address}: {error}");
                }
            }
        }
    }

    async fn start_relay(&self, client: SocketAddr, packets: Vec<Vec<u8>>) {
        let Some(destination) = self.destination else {
            return;
        };
        let bind_address = if destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let relay = match UdpSocket::bind(bind_address).await {
            Ok(socket) => match socket.connect(destination).await {
                Ok(()) => Arc::new(socket),
                Err(error) => {
                    log::debug!("cannot connect UDP relay to {destination}: {error}");
                    return;
                }
            },
            Err(error) => {
                log::debug!("cannot bind UDP relay socket: {error}");
                return;
            }
        };

        let cancel = Arc::new(Notify::new());
        if let Some(flow) = self.flows.lock().unwrap().get_mut(&client) {
            flow.relay = Some(relay.clone());
            flow.cancel = Some(cancel.clone());
        }

        let socket = self.socket.clone();
        let relay_reader = relay.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            loop {
                tokio::select! {
                    result = relay_reader.recv(&mut buffer) => {
                        match result {
                            Ok(length) => {
                                if socket.send_to(&buffer[..length], client).await.is_err() {
                                    return;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    _ = cancel.notified() => return,
                }
            }
        });

        for packet in packets {
            if let Err(error) = relay.send(&packet).await {
                log::debug!("UDP relay initial send failed for {client}: {error}");
                break;
            }
        }
        log::debug!("UDP flow from {client} relayed to {destination}");
    }

    async fn cleanup_loop(self: Arc<Self>, stop: Arc<AtomicBool>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(30));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        while !stop.load(Ordering::Relaxed) {
            ticker.tick().await;
            let now = Instant::now();
            let mut flows = self.flows.lock().unwrap();
            let expired = flows
                .iter()
                .filter_map(|(address, flow)| {
                    let idle = now.duration_since(flow.last);
                    let timeout = match flow.kind {
                        FlowKind::Pending => PENDING_TIMEOUT,
                        FlowKind::Relay => RELAY_TIMEOUT,
                        FlowKind::Mio => MIO_TIMEOUT,
                    };
                    (idle > timeout).then_some(*address)
                })
                .collect::<Vec<_>>();
            for address in expired {
                if let Some(flow) = flows.remove(&address)
                    && let Some(cancel) = flow.cancel
                {
                    cancel.notify_waiters();
                }
            }
        }
    }
}

impl AsyncUdpSocket for UdpDemuxSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(QuinnPoller {
            socket: self.socket.clone(),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        match transmit.segment_size {
            Some(segment_size) => {
                for segment in transmit.contents.chunks(segment_size) {
                    self.socket.try_send_to(segment, transmit.destination)?;
                }
                Ok(())
            }
            None => self
                .socket
                .try_send_to(transmit.contents, transmit.destination)
                .map(|_| ()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut receiver = self.incoming_rx.lock().unwrap();
        match Pin::new(&mut *receiver).poll_recv(cx) {
            Poll::Ready(Some((packet, address))) => {
                if packet.len() > buffers[0].len() {
                    return Poll::Ready(Err(io::Error::other(
                        "QUIC receive buffer is smaller than incoming datagram",
                    )));
                }
                buffers[0][..packet.len()].copy_from_slice(&packet);
                meta[0] = RecvMeta {
                    addr: address,
                    len: packet.len(),
                    stride: packet.len(),
                    ecn: None,
                    dst_ip: None,
                };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(io::Error::other("UDP demux closed"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

struct QuinnPoller {
    socket: Arc<UdpSocket>,
}

impl fmt::Debug for QuinnPoller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuinnPoller")
            .finish_non_exhaustive()
    }
}

impl UdpPoller for QuinnPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let length = 1_usize << (first >> 6);
    if bytes.len() < length {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..length] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, length))
}

fn expand_label(secret: &[u8], label: &str, length: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = (length as u16).to_be_bytes().to_vec();
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(0);
    let hkdf = Hkdf::<Sha256>::from_prk(secret).expect("valid PRK");
    let mut output = vec![0_u8; length];
    hkdf.expand(&info, &mut output).expect("valid HKDF length");
    output
}

fn initial_client_hello_random(packet: &[u8]) -> (Option<Vec<u8>>, InitialStatus) {
    if packet.len() < 1200
        || packet[0] & 0xf0 != 0xc0
        || u32::from_be_bytes([packet[1], packet[2], packet[3], packet[4]]) != QUIC_V1_VERSION
    {
        return (None, InitialStatus::None);
    }
    let mut cursor = 5;
    let dcid_length = usize::from(packet[cursor]);
    cursor += 1;
    if dcid_length > 20 || cursor + dcid_length >= packet.len() {
        return (None, InitialStatus::None);
    }
    let dcid = &packet[cursor..cursor + dcid_length];
    cursor += dcid_length;
    let scid_length = usize::from(packet[cursor]);
    cursor += 1 + scid_length;
    if cursor >= packet.len() {
        return (None, InitialStatus::None);
    }
    let (token_length, token_varint) = match read_varint(&packet[cursor..]) {
        Some(value) => value,
        None => return (None, InitialStatus::None),
    };
    cursor += token_varint + token_length as usize;
    if cursor >= packet.len() {
        return (None, InitialStatus::None);
    }
    let (payload_length, length_varint) = match read_varint(&packet[cursor..]) {
        Some(value) => value,
        None => return (None, InitialStatus::None),
    };
    let packet_number_offset = cursor + length_varint;
    let end = packet_number_offset + payload_length as usize;
    if end > packet.len() || packet_number_offset + 20 > end {
        return (None, InitialStatus::None);
    }

    let (initial_secret, _) = Hkdf::<Sha256>::extract(Some(&QUIC_V1_SALT), dcid);
    let client_secret = expand_label(initial_secret.as_slice(), "client in", 32);
    let key = expand_label(&client_secret, "quic key", 16);
    let iv = expand_label(&client_secret, "quic iv", 12);
    let header_protection = expand_label(&client_secret, "quic hp", 16);

    let protection = Aes128::new_from_slice(&header_protection).expect("AES key length");
    let mut mask = [0_u8; 16];
    let mut sample = [0_u8; 16];
    sample.copy_from_slice(&packet[packet_number_offset + 4..packet_number_offset + 20]);
    protection.encrypt_block((&mut sample).into());
    mask.copy_from_slice(&sample);

    let mut protected = packet[..end].to_vec();
    protected[0] ^= mask[0] & 0x0f;
    let packet_number_length = usize::from(protected[0] & 0x03) + 1;
    let mut packet_number = 0_u64;
    for index in 0..packet_number_length {
        protected[packet_number_offset + index] ^= mask[1 + index];
        packet_number = (packet_number << 8) | u64::from(protected[packet_number_offset + index]);
    }
    let mut nonce = [0_u8; 12];
    nonce.copy_from_slice(&iv);
    for index in 0..8 {
        nonce[11 - index] ^= (packet_number >> (8 * index)) as u8;
    }

    let cipher = Aes128Gcm::new_from_slice(&key).expect("AES-GCM key length");
    let plaintext = match cipher.decrypt(
        Nonce::from_slice(&nonce),
        aes_gcm::aead::Payload {
            msg: &protected[packet_number_offset + packet_number_length..],
            aad: &protected[..packet_number_offset + packet_number_length],
        },
    ) {
        Ok(plaintext) => plaintext,
        Err(_) => return (None, InitialStatus::None),
    };

    let mut chunks = BTreeMap::new();
    let mut frame = plaintext.as_slice();
    while let Some((frame_type, type_length)) = read_varint(frame) {
        frame = &frame[type_length..];
        match frame_type {
            0x00 | 0x01 => {}
            0x06 => {
                let Some((offset, offset_length)) = read_varint(frame) else {
                    break;
                };
                frame = &frame[offset_length..];
                let Some((size, size_length)) = read_varint(frame) else {
                    break;
                };
                frame = &frame[size_length..];
                if frame.len() < size as usize {
                    break;
                }
                chunks.insert(offset, frame[..size as usize].to_vec());
                frame = &frame[size as usize..];
            }
            _ => break,
        }
    }

    let mut hello = Vec::new();
    while let Some(chunk) = chunks.get(&(hello.len() as u64)) {
        hello.extend_from_slice(chunk);
    }
    if hello.len() < 38 || hello[0] != 0x01 {
        return (None, InitialStatus::Incomplete);
    }
    (Some(hello[6..38].to_vec()), InitialStatus::Random)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        assert_eq!(read_varint(&[0x00]), Some((0, 1)));
        assert_eq!(read_varint(&[0x40, 0x7f]), Some((127, 2)));
        assert_eq!(read_varint(&[0x41, 0x00]), Some((256, 2)));
    }

    #[test]
    fn non_initial_packet_is_not_classified() {
        let packet = vec![0_u8; 1200];
        assert_eq!(
            initial_client_hello_random(&packet),
            (None, InitialStatus::None)
        );
    }

    #[test]
    fn captured_quic_initial_exposes_random_and_replay_cache() {
        let packet = hex::decode(include_str!("../tests/fixtures/quic_initial.hex").trim())
            .expect("valid fixture");
        let (random, status) = initial_client_hello_random(&packet);
        assert_eq!(status, InitialStatus::Random);
        let random = random.expect("ClientHello random");
        assert_eq!(random.len(), 32);

        let minute = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            / 60;
        let nonce = [7_u8; MARKER_NONCE_SIZE];
        let mut marker = Vec::from(nonce);
        marker.extend_from_slice(&marker_tag(&[9_u8; 32], &nonce, minute));
        let mut replay = ReplayCache::new();
        assert!(replay.check(&[9_u8; 32], &marker));
        assert!(!replay.check(&[9_u8; 32], &marker));
    }
}
