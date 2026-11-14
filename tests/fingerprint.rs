use mio_rs::tls::{
    CHROME_133_CANONICAL_JA3, CHROME_133_CANONICAL_JA3_MD5, CHROME_133_JA4,
    parse_client_hello_security, summarize_client_hello,
};

#[test]
fn captured_client_hello_matches_chrome_133() {
    let bytes = hex::decode(include_str!("fixtures/chrome133_clienthello.hex").trim())
        .expect("valid fixture");
    let summary = summarize_client_hello(&bytes).expect("parse ClientHello");

    assert_eq!(summary.sni.as_deref(), Some("example.com"));
    assert_eq!(summary.alpn, ["h2", "http/1.1"]);
    assert_eq!(summary.canonical_ja3, CHROME_133_CANONICAL_JA3);
    assert_eq!(summary.canonical_ja3_md5, CHROME_133_CANONICAL_JA3_MD5);
    assert_eq!(summary.ja4, CHROME_133_JA4);
    assert_eq!(summary.cipher_suites.len(), 16);
    assert!(summary.cipher_suites.contains(&0x1301));
    assert!(summary.groups.contains(&0x11ec));
}

#[test]
fn captured_client_hello_exposes_tls_auth_key_share() {
    let bytes = hex::decode(include_str!("fixtures/chrome133_clienthello.hex").trim())
        .expect("valid fixture");
    let (random, share) = parse_client_hello_security(&bytes).expect("parse security fields");
    assert_ne!(random, [0_u8; 32]);
    assert_eq!(share.len(), 32);
}
