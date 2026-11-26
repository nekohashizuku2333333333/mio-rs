# Chrome 156+ ClientHello 复现报告

## 上游基准

上游 Go 项目固定使用：

```text
github.com/refraction-networking/utls v1.8.2
utls.HelloChrome_Auto
```

上游使用 uTLS v1.8.2；其中 `HelloChrome_Auto == HelloChrome_133`。v0.6.3 在该
spec 的 `signature_algorithms` 前插入一个随机 GREASE 值和 ML-DSA-44/65/87，并在
每条 TCP 连接新建 `UClient`，没有 session cache，因此观察对象是无 PSK、无恢复的
首次 ClientHello。

## Rust 配置

实现位于 `src/tls.rs::chrome_context` 和 `chrome_ssl`。关键调用：

```rust
SslContext::builder(SslMethod::tls())
set_session_cache_mode(SslSessionCacheMode::OFF)
set_min_proto_version(TLS1_2)
set_max_proto_version(TLS1_3)
set_strict_cipher_list(
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
     AES256-SHA")
set_curves_list("X25519MLKEM768:X25519:P-256:P-384")
set_sigalgs_list(
    "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:\
     ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:\
     RSA-PSS+SHA512:RSA+SHA512")
set_alpn_protos(b"\x02h2\x08http/1.1")
set_grease_enabled(true)
set_permute_extensions(true)
enable_ocsp_stapling()
enable_signed_cert_timestamps()
add_certificate_compression_algorithm(BrotliDecompressor)
```

每条连接额外设置：

```rust
ssl.set_enable_ech_grease(true);
SSL_set_alps_use_new_codepoint(ssl, 1);
SSL_add_application_settings(ssl, "h2", null, 0);
SSL_set1_client_key_shares(ssl, [X25519MLKEM768, X25519]);
```

Brotli certificate compression 必须注册真实的 decompressor，否则 BoringSSL 不会发送
`compress_certificate`，且可能错误声明无法处理的压缩算法。

## 捕获结果

30 次 uTLS 与 30 次 Rust BoringSSL 对比：

```text
JA4                 t13d1516h2_8daaf6152771_806a8c22fdea   capture-matched
canonical JA3 MD5   8e19337e7524d2573be54efb2b0784c9       capture-matched
```

canonical JA3 明文字段：

```text
771,
4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,
0-5-10-11-13-16-18-23-27-35-43-45-51-17613-65037-65281,
4588-29-23-24,
0
```

稳定字段：

| 字段 | 值 |
| --- | --- |
| record version | `0x0301` |
| ClientHello legacy version | `0x0303` |
| session ID | 32 字节随机，非空 |
| 非 GREASE ciphers | `1301 1302 1303 c02b c02f c02c c030 cca9 cca8 c013 c014 009c 009d 002f 0035` |
| groups | `11ec 001d 0017 0018` |
| sigalgs | `GREASE 0904 0905 0906 0403 0804 0401 0503 0805 0501 0806 0601` |
| supported_versions | `0304 0303` |
| ALPN | `h2`, `http/1.1` |
| ALPS | 新 codepoint `0x44cd`，body `0003026832` |
| cert compression | `020002`（仅 Brotli） |
| key shares | `11ec` 1216B、`001d` 32B |
| ECH GREASE body 长度 | 186/218/250/282 字节 |
| 非 GREASE ext 数量 | 16 |

## 为什么逐连接 JA3 不同

Chrome 106+ 与 uTLS `ShuffleChromeTLSExtensions` 会随机打乱 16 个非 GREASE
扩展。BoringSSL 的 `set_permute_extensions(true)` 行为相同。30 次捕获中，每一侧
都产生 30 个不同 JA3 MD5，交集为 0。这不是实现差异；标准 JA4 和 canonical JA3
才是可重复的验收口径。

## BoringSSL 补丁与 vendored 构建

stock BoringSSL 的默认 sigalg 列表不含 Chrome 156+ 的 GREASE + ML-DSA 前缀，也
不会暴露 TLS ClientHello 的 X25519 key_share 私钥。mio v0.6.3 的静态认证需要后者，
指纹需要前者，因此仓库内置 `vendor/boringssl` 并在其上应用三个补丁：

1. `boring-pq.patch`（boring-sys 的 Cloudflare PQ 补丁）
2. `patches/boringssl-no-sigalg-grease.patch`
3. `patches/boringssl-x25519-key-share.patch`

`.cargo/config.toml` 将 `boring-sys` 指向该源码树，并设置
`BORING_BSSL_ASSUME_PATCHED=1`。默认 `cargo build --release` 就使用这个版本，
不需要额外环境变量。

实测在 ECH GREASE body 为 282 字节时：

```text
stock boring      1821 bytes
patched           1821 bytes
uTLS v0.6.3 profile  1825 bytes
```

X25519 补丁通过真实 TLS 1.3 握手、HelloRetryRequest、`SSL_CONFIG` shedding 和
公私钥一致性检查。它只在 ClientHello 实际包含纯 X25519 key_share 时返回 1；只有
hybrid-only 的 ClientHello 返回 0。

扩展顺序随机，因此仍不能要求逐条连接原始字节顺序相同；补丁解决固定长度和 sigalg
槽位差异。

## 验证

```bash
./target/release/mio fingerprint --server 127.0.0.1:19443 --dest example.com
```

输出中的 `chrome_156_match=true` 要求 JA4 和 canonical JA3 MD5 同时匹配。离线样本
测试位于 `tests/fingerprint.rs`；真实 Chrome 156/158 还会发送上游未实现的
`trust_anchors (0xca34)`，因此浏览器捕获的 JA4 是 `..._cb7bf5808d99`，而本实现与
上游 v0.6.3 对齐为 `..._806a8c22fdea`。`vendor/boringssl` 的 X25519 补丁探针位于
`.research/v051-bssl/probe/x25519_probe.cc` 和 `test-output.txt`，其测试覆盖 HRR 和配置 shedding。
