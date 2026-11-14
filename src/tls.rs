use anyhow::{Context, Result, anyhow, bail};
use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, HandshakeError, Ssl, SslContext,
    SslMethod, SslSessionCacheMode, SslStreamBuilder, SslVerifyMode, SslVersion,
};
use boring::x509::verify::X509CheckFlags;
use boring_sys as ffi;
use foreign_types::{ForeignType, ForeignTypeRef};
use std::io::{self, Read, Write};
use std::net::{IpAddr, TcpStream, ToSocketAddrs};
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

unsafe extern "C" {
    fn SSL_get_x25519_key_share_private_key(ssl: *const ffi::SSL, out: *mut u8) -> c_int;
}

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHelloProfile {
    pub name: &'static str,
    pub browser_version: &'static str,
}

pub const CHROME_PROFILE: ClientHelloProfile = ClientHelloProfile {
    name: "Chrome",
    browser_version: "133",
};

pub struct TlsHandshake {
    pub stream: TcpStream,
    pub client_random: [u8; 32],
    pub server_random: [u8; 32],
    pub x25519_private: [u8; 32],
}

struct BrotliCertificateDecompressor;

impl CertificateCompressor for BrotliCertificateDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        let mut decoder = brotli::Decompressor::new(input, 16 * 1024);
        io::copy(&mut decoder, output)?;
        Ok(())
    }
}

struct HandshakeIo {
    stream: TcpStream,
    handshaking: Arc<AtomicBool>,
    client_hello: Arc<Mutex<Vec<u8>>>,
}

impl Read for HandshakeIo {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // BoringSSL can request a large read. Limiting reads to one byte while
        // handshaking guarantees it cannot consume raw bytes belonging to the
        // post-handshake mio protocol. This costs a few thousand small reads
        // once per connection and avoids losing TLS 1.3 session tickets too.
        let limit = if self.handshaking.load(Ordering::Relaxed) {
            1.min(buffer.len())
        } else {
            buffer.len()
        };
        self.stream.read(&mut buffer[..limit])
    }
}

impl Write for HandshakeIo {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.handshaking.load(Ordering::Relaxed) {
            let mut capture = self.client_hello.lock().unwrap();
            if capture.len() < 64 * 1024 {
                capture.extend_from_slice(buffer);
            }
        }
        self.stream.write_all(buffer)?;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn chrome_context() -> Result<SslContext> {
    let mut context = SslContext::builder(SslMethod::tls())
        .map_err(|error| anyhow!("create TLS context: {error}"))?;
    context
        .set_default_verify_paths()
        .map_err(|error| anyhow!("load system trust store: {error}"))?;
    context.set_verify(SslVerifyMode::PEER);
    context.set_session_cache_mode(SslSessionCacheMode::OFF);
    context
        .set_min_proto_version(Some(SslVersion::TLS1_2))
        .map_err(|error| anyhow!("set minimum TLS version: {error}"))?;
    context
        .set_max_proto_version(Some(SslVersion::TLS1_3))
        .map_err(|error| anyhow!("set maximum TLS version: {error}"))?;
    context
        .set_strict_cipher_list(
            "ECDHE-ECDSA-AES128-GCM-SHA256:\
         ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:\
         ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:\
         ECDHE-RSA-CHACHA20-POLY1305:\
         ECDHE-RSA-AES128-SHA:\
         ECDHE-RSA-AES256-SHA:\
         AES128-GCM-SHA256:\
         AES256-GCM-SHA384:\
         AES128-SHA:\
         AES256-SHA",
        )
        .map_err(|error| anyhow!("set Chrome TLS 1.2 cipher suites: {error}"))?;
    context.set_grease_enabled(true);
    context.set_permute_extensions(true);
    context
        .set_curves_list("X25519MLKEM768:X25519:P-256:P-384")
        .map_err(|error| anyhow!("set Chrome supported groups: {error}"))?;
    context
        .set_sigalgs_list(
            "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:RSA-PSS+SHA512:RSA+SHA512",
        )
        .map_err(|error| anyhow!("set Chrome signature algorithms: {error}"))?;
    context
        .set_alpn_protos(b"\x02h2\x08http/1.1")
        .map_err(|error| anyhow!("set Chrome ALPN: {error}"))?;
    context.enable_signed_cert_timestamps();
    context.enable_ocsp_stapling();
    context
        .add_certificate_compression_algorithm(BrotliCertificateDecompressor)
        .map_err(|error| anyhow!("enable Brotli certificate compression: {error}"))?;
    Ok(context.build())
}

fn chrome_ssl(context: &SslContext, server_name: &str, insecure: bool) -> Result<Ssl> {
    let ssl = Ssl::new(context).map_err(|error| anyhow!("create TLS session: {error}"))?;
    let mut ssl = ssl;
    if let Ok(ip) = server_name.parse::<IpAddr>() {
        // Chrome does not send SNI for IP literals, but still verifies the IP.
        if insecure {
            ssl.set_verify(SslVerifyMode::NONE);
        } else if let Err(error) = ssl.param_mut().set_ip(ip) {
            bail!("set verification IP: {error}");
        }
    } else {
        ssl.set_hostname(server_name)
            .map_err(|error| anyhow!("set SNI: {error}"))?;
        if insecure {
            ssl.set_verify(SslVerifyMode::NONE);
        } else {
            let flags = X509CheckFlags::NO_PARTIAL_WILDCARDS;
            ssl.param_mut().set_hostflags(flags);
            ssl.param_mut()
                .set_host(server_name)
                .map_err(|error| anyhow!("set verification hostname: {error}"))?;
        }
    }

    unsafe {
        ffi::SSL_set_enable_ech_grease(ssl.as_ptr(), 1);
        ffi::SSL_set_alps_use_new_codepoint(ssl.as_ptr(), 1);
        let settings =
            ffi::SSL_add_application_settings(ssl.as_ptr(), b"h2".as_ptr(), 2, std::ptr::null(), 0);
        if settings != 1 {
            bail!("enable ALPS application settings");
        }
        let key_shares = [0x11ec_u16, 29];
        let configured =
            ffi::SSL_set1_client_key_shares(ssl.as_ptr(), key_shares.as_ptr(), key_shares.len());
        if configured != 1 {
            bail!("configure Chrome key shares");
        }
    }
    Ok(ssl)
}

pub fn connect_chrome(server: &str, dest: &str, insecure: bool) -> Result<TlsHandshake> {
    let context = chrome_context()?;
    let mut last_error = None;
    for address in server
        .to_socket_addrs()
        .with_context(|| format!("resolve server {server}"))?
    {
        match TcpStream::connect_timeout(&address, TLS_HANDSHAKE_TIMEOUT) {
            Ok(stream) => {
                return finish_handshake(context, stream, dest, insecure)
                    .with_context(|| format!("TLS handshake with {address}"));
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("server {server} resolved to no addresses")))
}

fn finish_handshake(
    context: SslContext,
    stream: TcpStream,
    dest: &str,
    insecure: bool,
) -> Result<TlsHandshake> {
    stream.set_nodelay(true).context("enable TCP_NODELAY")?;
    stream
        .set_read_timeout(Some(TLS_HANDSHAKE_TIMEOUT))
        .context("set TLS handshake read timeout")?;
    stream
        .set_write_timeout(Some(TLS_HANDSHAKE_TIMEOUT))
        .context("set TLS handshake write timeout")?;

    let handshaking = Arc::new(AtomicBool::new(true));
    let client_hello = Arc::new(Mutex::new(Vec::new()));
    let io = HandshakeIo {
        stream,
        handshaking: handshaking.clone(),
        client_hello: client_hello.clone(),
    };
    let ssl = chrome_ssl(&context, dest, insecure)?;
    let mut builder = SslStreamBuilder::new(ssl, io);
    builder.set_connect_state();
    let mut tls = match builder.handshake() {
        Ok(stream) => {
            handshaking.store(false, Ordering::Relaxed);
            stream
        }
        Err(HandshakeError::WouldBlock(mid)) => {
            handshaking.store(false, Ordering::Relaxed);
            let error = mid.error().to_string();
            let _ = mid.into_source_stream();
            bail!("TLS handshake blocked: {error}");
        }
        Err(HandshakeError::Failure(mid)) => {
            handshaking.store(false, Ordering::Relaxed);
            let error = mid.error().to_string();
            let _ = mid.into_source_stream();
            bail!("TLS handshake failed: {error}");
        }
        Err(HandshakeError::SetupFailure(error)) => {
            handshaking.store(false, Ordering::Relaxed);
            bail!("TLS setup failed: {error}");
        }
    };

    let mut client_random = [0_u8; 32];
    if tls.ssl().client_random(&mut client_random) != client_random.len() {
        bail!("TLS handshake did not expose client_random");
    }
    let mut server_random = [0_u8; 32];
    if tls.ssl().server_random(&mut server_random) != server_random.len() {
        bail!("TLS handshake did not expose server_random");
    }
    let mut x25519_private = [0_u8; 32];
    let key_available = unsafe {
        SSL_get_x25519_key_share_private_key(tls.ssl().as_ptr(), x25519_private.as_mut_ptr())
    };
    if key_available != 1 {
        bail!("TLS handshake did not expose the X25519 key_share private key");
    }
    tls.flush().context("flush TLS handshake")?;
    let io = tls.into_inner();
    io.stream
        .set_read_timeout(None)
        .context("clear TLS handshake read timeout")?;
    io.stream
        .set_write_timeout(None)
        .context("clear TLS handshake write timeout")?;
    let stream = io.stream;
    Ok(TlsHandshake {
        stream,
        client_random,
        server_random,
        x25519_private,
    })
}

/// Parse the ClientHello random and the X25519 key_share from a raw TLS record.
pub fn parse_client_hello_security(data: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if data.len() < 5 || data[0] != RECORD_HANDSHAKE {
        bail!("captured bytes do not start with a TLS handshake record");
    }
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_length {
        bail!("captured ClientHello record is incomplete");
    }
    let body = &data[5..5 + record_length];
    if body.len() < 4 || body[0] != HANDLER_CLIENT_HELLO {
        bail!("TLS record does not contain a ClientHello");
    }
    let hello_length = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    if body.len() < 4 + hello_length {
        bail!("truncated ClientHello body");
    }
    let hello = &body[4..4 + hello_length];
    if hello.len() < 34 {
        bail!("truncated ClientHello random");
    }
    let mut random = [0_u8; 32];
    random.copy_from_slice(&hello[2..34]);

    let mut offset = 34;
    let session_id_length = *hello
        .get(offset)
        .ok_or_else(|| anyhow!("truncated session ID"))? as usize;
    offset += 1 + session_id_length;
    let cipher_length = read_u16(hello, offset)? as usize;
    offset += 2 + cipher_length;
    let compression_length = *hello
        .get(offset)
        .ok_or_else(|| anyhow!("truncated compression methods"))?
        as usize;
    offset += 1 + compression_length;
    let extension_length = read_u16(hello, offset)? as usize;
    offset += 2;
    let extension_end = offset + extension_length;
    if hello.len() < extension_end {
        bail!("truncated extensions");
    }

    while offset + 4 <= extension_end {
        let extension_type = read_u16(hello, offset)?;
        let extension_size = read_u16(hello, offset + 2)? as usize;
        let body_start = offset + 4;
        let body_end = body_start + extension_size;
        let extension_body = hello
            .get(body_start..body_end)
            .ok_or_else(|| anyhow!("invalid extension length"))?;
        if extension_type == 0x0033 {
            let total = read_u16(extension_body, 0)? as usize;
            let shares = extension_body
                .get(2..2 + total)
                .ok_or_else(|| anyhow!("truncated key_share extension"))?;
            let mut cursor = 0;
            while cursor + 4 <= shares.len() {
                let group = read_u16(shares, cursor)?;
                let key_length = read_u16(shares, cursor + 2)? as usize;
                cursor += 4;
                let key = shares
                    .get(cursor..cursor + key_length)
                    .ok_or_else(|| anyhow!("truncated key_share entry"))?;
                cursor += key_length;
                if group == 0x001d && key_length == 32 {
                    let mut share = [0_u8; 32];
                    share.copy_from_slice(key);
                    return Ok((random, share));
                }
            }
            return Err(anyhow!("ClientHello has no X25519 key_share"));
        }
        offset = body_end;
    }
    Err(anyhow!("ClientHello has no key_share extension"))
}

pub fn summarize_client_hello(data: &[u8]) -> Result<ClientHelloSummary> {
    if data.len() < 5 || data[0] != 0x16 {
        bail!("captured bytes do not start with a TLS handshake record");
    }
    let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_length {
        bail!("captured ClientHello record is incomplete");
    }
    let body = &data[5..5 + record_length];
    if body.len() < 4 || body[0] != HANDLER_CLIENT_HELLO {
        bail!("TLS record does not contain a ClientHello");
    }
    let hello_length = ((body[1] as usize) << 16) | ((body[2] as usize) << 8) | body[3] as usize;
    if body.len() < 4 + hello_length {
        bail!("truncated ClientHello body");
    }
    let hello = &body[4..4 + hello_length];
    let mut offset = 2 + 32;
    let session_id_length = *hello
        .get(offset)
        .ok_or_else(|| anyhow!("truncated session ID"))? as usize;
    offset += 1 + session_id_length;
    let cipher_length = read_u16(hello, offset)? as usize;
    offset += 2;
    let cipher_bytes = hello
        .get(offset..offset + cipher_length)
        .ok_or_else(|| anyhow!("truncated cipher suites"))?;
    let cipher_suites = cipher_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_be_bytes(*chunk))
        .collect::<Vec<_>>();
    offset += cipher_length;
    let compression_length = *hello
        .get(offset)
        .ok_or_else(|| anyhow!("truncated compression methods"))?
        as usize;
    offset += 1 + compression_length;
    let extension_length = read_u16(hello, offset)? as usize;
    offset += 2;
    let extension_end = offset + extension_length;
    if hello.len() < extension_end {
        bail!("truncated extensions");
    }
    let mut extensions = Vec::new();
    let mut groups = Vec::new();
    let mut points = Vec::new();
    let mut sigalgs = Vec::new();
    let mut versions = Vec::new();
    let mut alpn = Vec::new();
    let mut sni = None;
    while offset + 4 <= extension_end {
        let extension_type = read_u16(hello, offset)?;
        let extension_size = read_u16(hello, offset + 2)? as usize;
        let body_start = offset + 4;
        let body_end = body_start + extension_size;
        let extension_body = hello
            .get(body_start..body_end)
            .ok_or_else(|| anyhow!("invalid extension length"))?;
        match extension_type {
            0x0000 => {
                if extension_body.len() >= 5 {
                    let name_length =
                        u16::from_be_bytes([extension_body[3], extension_body[4]]) as usize;
                    if let Some(name) = extension_body.get(5..5 + name_length) {
                        sni = Some(String::from_utf8_lossy(name).into_owned());
                    }
                }
            }
            0x000a => groups = parse_u16_vector16(extension_body)?,
            0x000b => {
                if let Some((&length, values)) = extension_body.split_first()
                    && values.len() >= length as usize
                {
                    points.extend_from_slice(&values[..length as usize]);
                }
            }
            0x000d => sigalgs = parse_u16_vector16(extension_body)?,
            0x0010 => {
                if extension_body.len() >= 2 {
                    let total = u16::from_be_bytes([extension_body[0], extension_body[1]]) as usize;
                    let mut cursor = 2;
                    let end = (2 + total).min(extension_body.len());
                    while cursor < end {
                        let length = extension_body[cursor] as usize;
                        cursor += 1;
                        if cursor + length > end {
                            break;
                        }
                        alpn.push(
                            String::from_utf8_lossy(&extension_body[cursor..cursor + length])
                                .into_owned(),
                        );
                        cursor += length;
                    }
                }
            }
            0x002b => {
                if let Some((&length, values)) = extension_body.split_first() {
                    let end = (length as usize).min(values.len());
                    versions.extend(
                        values[..end]
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|chunk| u16::from_be_bytes(*chunk)),
                    );
                }
            }
            _ => {}
        }
        extensions.push(extension_type);
        offset = body_end;
    }

    let ja3_string = ja3(&cipher_suites, &extensions, &groups, &points);
    let ja3_md5 = md5_hex(ja3_string.as_bytes());
    let mut sorted_extensions = extensions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();
    sorted_extensions.sort_unstable();
    let canonical_ja3 = ja3(&cipher_suites, &sorted_extensions, &groups, &points);
    let canonical_ja3_md5 = md5_hex(canonical_ja3.as_bytes());
    let ja4 = ja4(
        &cipher_suites,
        &extensions,
        &sigalgs,
        &versions,
        &alpn,
        sni.is_some(),
    );
    Ok(ClientHelloSummary {
        cipher_suites,
        extensions,
        groups,
        points,
        sigalgs,
        versions,
        alpn,
        sni,
        ja3: ja3_string,
        ja3_md5,
        canonical_ja3,
        canonical_ja3_md5,
        ja4,
    })
}

fn parse_u16_vector16(body: &[u8]) -> Result<Vec<u16>> {
    if body.len() < 2 {
        return Ok(Vec::new());
    }
    let length = u16::from_be_bytes([body[0], body[1]]) as usize;
    if length > body.len() - 2 {
        bail!("truncated TLS vector");
    }
    Ok(body[2..2 + length]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u16::from_be_bytes(*chunk))
        .collect())
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16> {
    let pair = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| anyhow!("truncated TLS field"))?;
    Ok(u16::from_be_bytes([pair[0], pair[1]]))
}

const RECORD_HANDSHAKE: u8 = 0x16;
const HANDLER_CLIENT_HELLO: u8 = 0x01;
pub const CHROME_133_CANONICAL_JA3: &str = "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,4588-29-23-24,0";
pub const CHROME_133_CANONICAL_JA3_MD5: &str = "8e19337e7524d2573be54efb2b0784c9";
pub const CHROME_133_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

fn ja3(cipher_suites: &[u16], extensions: &[u16], groups: &[u16], points: &[u8]) -> String {
    let ciphers = cipher_suites
        .iter()
        .filter(|value| !is_grease(**value))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let extensions = extensions
        .iter()
        .filter(|value| !is_grease(**value))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let groups = groups
        .iter()
        .filter(|value| !is_grease(**value))
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    let points = points
        .iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join("-");
    format!("771,{ciphers},{extensions},{groups},{points}")
}

fn md5_hex(bytes: &[u8]) -> String {
    use md5::{Digest, Md5};
    let digest = Md5::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn ja4(
    cipher_suites: &[u16],
    extensions: &[u16],
    sigalgs: &[u16],
    versions: &[u16],
    alpn: &[String],
    has_sni: bool,
) -> String {
    let ciphers = {
        let mut values = cipher_suites
            .iter()
            .copied()
            .filter(|value| !is_grease(*value))
            .map(|value| format!("{value:04x}"))
            .collect::<Vec<_>>();
        values.sort_unstable();
        values
    };
    let cipher_hash = sha256_prefix_12(&ciphers.join(","));

    let non_grease_extensions = extensions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .collect::<Vec<_>>();
    let mut extension_names = non_grease_extensions
        .iter()
        .copied()
        .filter(|value| !matches!(*value, 0x0000 | 0x0010))
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>();
    extension_names.sort_unstable();
    let signature_names = sigalgs
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .map(|value| format!("{value:04x}"))
        .collect::<Vec<_>>();
    let signature_input = format!(
        "{}_{}",
        extension_names.join(","),
        signature_names.join(",")
    );
    let signature_hash = sha256_prefix_12(&signature_input);

    let max_version = versions
        .iter()
        .copied()
        .filter(|value| !is_grease(*value))
        .max()
        .unwrap_or(0);
    let version = match max_version {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        _ => "00",
    };
    let sni_code = if has_sni { "d" } else { "i" };
    let alpn_code = alpn
        .first()
        .map(|protocol| {
            let bytes = protocol.as_bytes();
            if bytes.len() >= 2 {
                format!("{}{}", bytes[0] as char, bytes[bytes.len() - 1] as char)
            } else {
                "00".to_string()
            }
        })
        .unwrap_or_else(|| "00".to_string());
    let a_part = format!(
        "t{version}{sni_code}{:02}{:02}{alpn_code}",
        ciphers.len(),
        non_grease_extensions.len()
    );
    format!("{a_part}_{cipher_hash}_{signature_hash}")
}

fn sha256_prefix_12(input: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(input.as_bytes());
    digest
        .iter()
        .take(6)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_grease(value: u16) -> bool {
    value & 0x0f0f == 0x0a0a && (value >> 8) == (value & 0xff)
}

#[derive(Debug, Clone)]
pub struct ClientHelloSummary {
    pub cipher_suites: Vec<u16>,
    pub extensions: Vec<u16>,
    pub groups: Vec<u16>,
    pub points: Vec<u8>,
    pub sigalgs: Vec<u16>,
    pub versions: Vec<u16>,
    pub alpn: Vec<String>,
    pub sni: Option<String>,
    pub ja3: String,
    pub ja3_md5: String,
    pub canonical_ja3: String,
    pub canonical_ja3_md5: String,
    pub ja4: String,
}

pub fn probe_client_hello(server: &str, dest: &str) -> Result<ClientHelloSummary> {
    let mut last_error = None;
    for address in server
        .to_socket_addrs()
        .with_context(|| format!("resolve server {server}"))?
    {
        match TcpStream::connect_timeout(&address, TLS_HANDSHAKE_TIMEOUT) {
            Ok(stream) => {
                let context = chrome_context()?;
                stream.set_read_timeout(Some(Duration::from_secs(2)))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                let handshaking = Arc::new(AtomicBool::new(true));
                let capture = Arc::new(Mutex::new(Vec::new()));
                let io = HandshakeIo {
                    stream,
                    handshaking: handshaking.clone(),
                    client_hello: capture.clone(),
                };
                let ssl = chrome_ssl(&context, dest, true)?;
                let mut builder = SslStreamBuilder::new(ssl, io);
                builder.set_connect_state();
                let _ = builder.handshake();
                handshaking.store(false, Ordering::Relaxed);
                return summarize_client_hello(&capture.lock().unwrap());
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow!("server {server} resolved to no addresses")))
}
