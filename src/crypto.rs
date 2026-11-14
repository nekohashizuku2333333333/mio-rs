use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use kem::{Decapsulate, Encapsulate};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use rand::{Rng, RngCore, rngs::OsRng};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::protocol::{RECORD_APPDATA, RECORD_HEADER_SIZE, max_record_body};

pub const PROTOCOL_VERSION: &str = "0.5.1";
const AUTH_INFO: &[u8] = b"mio auth 0.5.1";
const CLIENT_TO_SERVER_LABEL: &[u8] = b"mio c2s";
const SERVER_TO_CLIENT_LABEL: &[u8] = b"mio s2c";
pub const X25519_SIZE: usize = 32;
pub const MLKEM768_ENCAPSULATION_KEY_SIZE: usize = 1184;
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
pub const CLIENT_SHARE_SIZE: usize = X25519_SIZE + MLKEM768_ENCAPSULATION_KEY_SIZE;
pub const SERVER_SHARE_SIZE: usize = X25519_SIZE + MLKEM768_CIPHERTEXT_SIZE;
pub const AEAD_OVERHEAD: usize = 16;

#[derive(Clone)]
pub struct AeadKey(Aes256Gcm);

impl AeadKey {
    pub fn new(key: &[u8; 32]) -> Self {
        Self(Aes256Gcm::new(key.into()))
    }

    pub fn seal(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        self.0
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .expect("AES-GCM encryption failed")
    }

    pub fn open(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        self.0
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| anyhow!("AES-GCM authentication failed"))
    }
}

pub fn nonce_for_sequence(sequence: u64) -> [u8; 12] {
    let mut nonce = [0_u8; 12];
    nonce[4..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

pub fn hkdf_key(ikm: &[u8], salt: &[u8], label: &[u8]) -> Result<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut key = [0_u8; 32];
    hkdf.expand(label, &mut key)
        .map_err(|_| anyhow!("HKDF output length is invalid"))?;
    Ok(key)
}

pub fn generate_key_pair() -> (String, String) {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    (
        URL_SAFE_NO_PAD.encode(private.to_bytes()),
        URL_SAFE_NO_PAD.encode(public.as_bytes()),
    )
}

pub fn parse_private_key(encoded: &str) -> Result<StaticSecret> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|_| anyhow!("invalid private key: want 43 base64url characters"))?;
    if decoded.len() != X25519_SIZE {
        bail!("invalid private key: want 43 base64url characters (run `mio keygen`)");
    }
    let mut bytes = [0_u8; X25519_SIZE];
    bytes.copy_from_slice(&decoded);
    Ok(StaticSecret::from(bytes))
}

pub fn parse_public_key(encoded: &str) -> Result<PublicKey> {
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded.trim())
        .map_err(|_| anyhow!("invalid public key: want 43 base64url characters"))?;
    if decoded.len() != X25519_SIZE {
        bail!("invalid public key: want 43 base64url characters (run `mio keygen`)");
    }
    let mut bytes = [0_u8; X25519_SIZE];
    bytes.copy_from_slice(&decoded);
    Ok(PublicKey::from(bytes))
}

pub fn x25519_shared(private: &StaticSecret, peer: &PublicKey) -> [u8; 32] {
    *private.diffie_hellman(peer).as_bytes()
}

pub fn auth_key(shared: &[u8; 32], client_random: &[u8], server_random: &[u8]) -> Result<AeadKey> {
    let mut salt = Vec::with_capacity(client_random.len() + server_random.len());
    salt.extend_from_slice(client_random);
    salt.extend_from_slice(server_random);
    Ok(AeadKey::new(&hkdf_key(shared, &salt, AUTH_INFO)?))
}

/// Build the TLS Application Data record carrying the client's hybrid key share.
pub fn auth_record(
    shared: &[u8; 32],
    client_random: &[u8],
    server_random: &[u8],
    share: &[u8],
) -> Result<Vec<u8>> {
    let aead = auth_key(shared, client_random, server_random)?;
    let padding_length = OsRng.gen_range(32..=1024);
    let mut plain = Vec::with_capacity(share.len() + padding_length);
    plain.extend_from_slice(share);
    let mut padding = vec![0_u8; padding_length];
    OsRng.fill_bytes(&mut padding);
    plain.extend_from_slice(&padding);

    let body_length = plain.len() + AEAD_OVERHEAD;
    if body_length > max_record_body() {
        bail!("authentication record is too large");
    }
    let header = [
        RECORD_APPDATA,
        0x03,
        0x03,
        (body_length >> 8) as u8,
        body_length as u8,
    ];
    let body = aead.seal(&[0_u8; 12], &plain, &header);
    let mut record = Vec::with_capacity(RECORD_HEADER_SIZE + body.len());
    record.extend_from_slice(&header);
    record.extend_from_slice(&body);
    Ok(record)
}

/// Verify an authentication record with the server static key and the TLS X25519 share.
pub fn verify_auth(
    server_private: &StaticSecret,
    client_key_share: &[u8; 32],
    client_random: &[u8],
    server_random: &[u8],
    header: &[u8],
    body: &[u8],
) -> Option<([u8; 32], Vec<u8>)> {
    let peer = PublicKey::from(*client_key_share);
    let shared = x25519_shared(server_private, &peer);
    let aead = auth_key(&shared, client_random, server_random).ok()?;
    let plain = aead.open(&[0_u8; 12], body, header).ok()?;
    if plain.len() < CLIENT_SHARE_SIZE + 32 || plain.len() > CLIENT_SHARE_SIZE + 1024 {
        return None;
    }
    Some((shared, plain[..CLIENT_SHARE_SIZE].to_vec()))
}

pub struct ClientKeys {
    x25519: StaticSecret,
    mlkem_dec: <MlKem768 as KemCore>::DecapsulationKey,
    mlkem_enc: <MlKem768 as KemCore>::EncapsulationKey,
}

impl ClientKeys {
    pub fn generate() -> Self {
        let x25519 = StaticSecret::random_from_rng(OsRng);
        let (mlkem_dec, mlkem_enc) = MlKem768::generate(&mut OsRng);
        Self {
            x25519,
            mlkem_dec,
            mlkem_enc,
        }
    }

    pub fn share(&self) -> Vec<u8> {
        let x25519_public = PublicKey::from(&self.x25519);
        let ek = self.mlkem_enc.as_bytes();
        let mut share = Vec::with_capacity(CLIENT_SHARE_SIZE);
        share.extend_from_slice(x25519_public.as_bytes());
        share.extend_from_slice(ek.as_slice());
        share
    }

    pub fn finish(&self, reply: &[u8]) -> Result<[u8; 64]> {
        if reply.len() != SERVER_SHARE_SIZE {
            bail!("invalid server key share");
        }
        let mut peer_bytes = [0_u8; 32];
        peer_bytes.copy_from_slice(&reply[..32]);
        let peer = PublicKey::from(peer_bytes);
        let x_shared = self.x25519.diffie_hellman(&peer);

        type Ciphertext = ml_kem::Ciphertext<MlKem768>;
        let ciphertext =
            Ciphertext::try_from(&reply[32..]).map_err(|_| anyhow!("invalid ML-KEM ciphertext"))?;
        let mlkem_shared = self
            .mlkem_dec
            .decapsulate(&ciphertext)
            .map_err(|_| anyhow!("ML-KEM decapsulation failed"))?;

        let mut shared = [0_u8; 64];
        shared[..32].copy_from_slice(x_shared.as_bytes());
        shared[32..].copy_from_slice(mlkem_shared.as_slice());
        Ok(shared)
    }
}

pub fn server_exchange(share: &[u8]) -> Result<(Vec<u8>, [u8; 64])> {
    if share.len() != CLIENT_SHARE_SIZE {
        bail!("invalid client key share");
    }
    let mut peer_bytes = [0_u8; 32];
    peer_bytes.copy_from_slice(&share[..32]);
    let peer = PublicKey::from(peer_bytes);
    let x25519 = StaticSecret::random_from_rng(OsRng);
    let x_shared = x25519.diffie_hellman(&peer);

    type EncapsulationKey = <MlKem768 as KemCore>::EncapsulationKey;
    let encoded = ml_kem::Encoded::<EncapsulationKey>::try_from(&share[32..])
        .map_err(|_| anyhow!("invalid ML-KEM encapsulation key"))?;
    let encapsulation_key = EncapsulationKey::from_bytes(&encoded);
    let (ciphertext, mlkem_shared) = encapsulation_key
        .encapsulate(&mut OsRng)
        .map_err(|_| anyhow!("ML-KEM encapsulation failed"))?;

    let mut reply = Vec::with_capacity(SERVER_SHARE_SIZE);
    reply.extend_from_slice(PublicKey::from(&x25519).as_bytes());
    reply.extend_from_slice(ciphertext.as_slice());

    let mut shared = [0_u8; 64];
    shared[..32].copy_from_slice(x_shared.as_bytes());
    shared[32..].copy_from_slice(mlkem_shared.as_slice());
    Ok((reply, shared))
}

pub fn transport_keys(
    shared: &[u8; 32],
    secret: Option<&[u8; 64]>,
    client_random: &[u8],
    server_random: &[u8],
    is_client: bool,
) -> Result<(AeadKey, AeadKey)> {
    let mut salt = Vec::with_capacity(client_random.len() + server_random.len());
    salt.extend_from_slice(client_random);
    salt.extend_from_slice(server_random);

    let mut ikm = Vec::with_capacity(shared.len() + secret.map_or(0, |value| value.len()));
    if let Some(secret) = secret {
        ikm.extend_from_slice(secret);
    }
    ikm.extend_from_slice(shared);

    let c2s = AeadKey::new(&hkdf_key(&ikm, &salt, CLIENT_TO_SERVER_LABEL)?);
    let s2c = AeadKey::new(&hkdf_key(&ikm, &salt, SERVER_TO_CLIENT_LABEL)?);
    if is_client {
        Ok((c2s, s2c))
    } else {
        Ok((s2c, c2s))
    }
}

pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; length];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_range(minimum: usize, maximum: usize) -> usize {
    debug_assert!(minimum <= maximum);
    OsRng.gen_range(minimum..=maximum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pair_encoding_round_trip() {
        let (private, public) = generate_key_pair();
        assert_eq!(private.len(), 43);
        assert_eq!(public.len(), 43);
        let private = parse_private_key(&private).unwrap();
        let public = parse_public_key(&public).unwrap();
        assert_eq!(PublicKey::from(&private).as_bytes(), public.as_bytes());
    }

    #[test]
    fn hybrid_exchange_agrees() {
        let client = ClientKeys::generate();
        let (reply, server_secret) = server_exchange(&client.share()).unwrap();
        let client_secret = client.finish(&reply).unwrap();
        assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn auth_record_round_trip() {
        let server_private = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_private);
        let client_private = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_private);
        let shared = x25519_shared(&client_private, &server_public);
        let client_random = [7_u8; 32];
        let server_random = [9_u8; 32];
        let keys = ClientKeys::generate();
        let record = auth_record(&shared, &client_random, &server_random, &keys.share()).unwrap();
        let header = &record[..RECORD_HEADER_SIZE];
        let body = &record[RECORD_HEADER_SIZE..];
        let (verified_shared, share) = verify_auth(
            &server_private,
            client_public.as_bytes(),
            &client_random,
            &server_random,
            header,
            body,
        )
        .unwrap();
        assert_eq!(verified_shared, shared);
        assert_eq!(share, keys.share());
    }
}
