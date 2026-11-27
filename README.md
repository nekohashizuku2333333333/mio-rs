# mio-rs

`mio-rs` 是 [orgmio/mio](https://github.com/orgmio/mio) v0.6.5 的 Rust 重写。它实现：

- TCP 伪装站点转发、静态 X25519 认证、X25519MLKEM768 会话密钥交换
- TCP 上的多路复用 stream、32 MiB 会话流控、每条流 16 MiB 流控、close/reset/window 帧
- QUIC 同端口 UDP marker 分流、静态密钥双向证明、stream 代理
- SOCKS5 `CONNECT` 客户端，可选 UDP ASSOCIATE
- UDP-over-mio 关联：长度前缀数据报、服务端 64 目标 socket 上限
- Chrome 156+ TCP ClientHello 指纹（uTLS Chrome 133 扩展集 + ML-DSA sigalgs）
- 初始 TCP、首选路径 + 延迟备份竞争、动态运输选择与 10–30 分钟重新比较
- Quinn 实验性 BBR，初始窗口 `32 × MTU`

二进制版本是 `0.6.5`，线上协议版本是 `1.0.1`。KDF label 只绑定协议主版本，
因此 v1 系列统一使用 `1.0.0`；客户端和服务端仍须使用兼容的协议版本。

## 状态

| 功能 | 状态 |
| --- | --- |
| mio v0.6.5 TCP 两条认证记录、ready、混合密钥交换 | 已实现 |
| 服务端 TCP 伪装转发与认证接管 | 已实现 |
| TCP 多路复用会话、32 MiB 会话窗口、16 MiB stream window、100 流上限 | 已实现 |
| 服务端 QUIC UDP marker 分流 | 已实现 |
| 未标记 UDP 转发到 `dest`（每 5 分钟刷新目标地址） | 已实现 |
| QUIC exporter HMAC 静态密钥认证 | 已实现 |
| SOCKS5 `CONNECT` 客户端 | 已实现 |
| SOCKS5 UDP ASSOCIATE（`socks5_udp=true`） | 已实现 |
| UDP-over-mio 关联与 datagram 帧 | 已实现 |
| TCP/QUIC 首选 + 延迟备份竞争、动态选路与自动回退 | 已实现 |
| Chrome 156+ TCP ClientHello | JA4/canonical JA3 匹配；含 GREASE + ML-DSA sigalgs |
| QUIC TLS 指纹 | Quinn/rustls，不是 Chrome |
| BBR | Quinn 实验性 BBR，非上游逐行移植 |

## 构建

要求 Rust 1.88+、C/C++ 构建工具、CMake、Ninja 或 Make、clang/gcc。

```bash
cargo build --release
./target/release/mio version
```

如果 Cargo 缓存目录不可写：

```bash
CARGO_HOME="$PWD/.cargo-home" cargo build --release
```

### BoringSSL

仓库内置 [vendor/boringssl](vendor/boringssl)，`.cargo/config.toml` 通过
`BORING_BSSL_SOURCE_PATH` 使用它，并设置 `BORING_BSSL_ASSUME_PATCHED=1`。
源码基于 `boring-sys 5.4.0`，已按顺序应用：

1. `boring-pq.patch`（Cloudflare PQ 支持）
2. `patches/boringssl-no-sigalg-grease.patch`（Chrome 156+ sigalg shape）
3. `patches/boringssl-x25519-key-share.patch`（导出 ClientHello X25519 私钥）

第三项是 v0.6.5 所必需的：上游用 TLS ClientHello 里的 X25519 key_share 私钥与
服务端静态公钥计算认证共享密钥，stock BoringSSL 不提供该私钥。

重新构建内置 BoringSSL：

```bash
CARGO_HOME="$PWD/.cargo-home" cargo clean -p boring-sys
CARGO_HOME="$PWD/.cargo-home" cargo build --release
```

## 生成密钥

```bash
./target/release/mio keygen
# PrivateKey: ...
# PublicKey: ...
```

私钥只放服务端，公钥放客户端。密钥是 32 字节 X25519，使用无填充 URL-safe base64
编码。

## 配置

客户端和/或服务端可以放在同一个文件中。客户端示例
[config/client.example.toml](config/client.example.toml)：

```toml
[log]
enable = true
level = "info"
output = ""
timestamp = true

[outbounds]
socks_listen = "127.0.0.1"
socks_listen_port = 1080
server = "example.com"
server_port = 443
dest = "www.example.com"
public_key = "mio keygen 生成的 PublicKey"
```

服务端示例 [config/server.example.toml](config/server.example.toml)：

```toml
[log]
enable = true
level = "info"
output = ""
timestamp = true

[inbounds]
listen = "0.0.0.0"
listen_port = 443
dest = "www.example.com"
private_key = "mio keygen 生成的 PrivateKey"
```

`dest` 必须与客户端一致。服务端 `dest_port` 可选，缺省时等于 `listen_port`；TCP 和 UDP 使用同一个 `listen_port`。同时配置
`[outbounds]` 和 `[inbounds]` 时，`mio run` 会同时启动客户端与服务端。

运行：

```bash
./target/release/mio run -c config/client.toml
./target/release/mio run -c config/server.toml
```

`insecure = true` 是本地测试扩展，不属于上游配置。生产配置不要使用它。

## 协议行为

### TCP

1. 客户端经服务端向 `dest` 转发真实 TLS 握手；服务端记录 ClientHello random、
   X25519 key_share 和最后的 ServerHello random。
2. 客户端用 TLS X25519 私钥与静态服务端公钥计算 `shared`。
3. 客户端连续发送两条 TLS Application Data 记录：
   - 认证记录：nonce 0，71 字节随机明文；
   - 份额记录：nonce 1，`share(1216) ‖ padding(0–255)`。
   - key 为 `HKDF(shared, client_random‖server_random, "mio auth 1.0.0")`，header
     作为 AAD。
4. 服务端校验认证记录，再读取份额记录；生成 X25519MLKEM768 服务端份额，用初始
   会话密钥发出 ready 帧，最后切换到包含混合 secret 的会话密钥。
5. 认证后的 TCP 连接可同时承载多条 stream；stream 请求格式沿用
   `atyp/address/port`。

### QUIC

- ClientHello.random = 16B nonce + 16B 分钟级 HMAC，key 由服务端公钥 HKDF 派生。
- 服务端解析 QUIC v1 Initial，验证 marker、±1 分钟窗口和 replay cache。
- 合法 marker 交给 Quinn；未标记 UDP 流按客户端地址转发到 `dest` 并回传响应。
- 握手后首个 stream：客户端临时 X25519 公钥 + 客户端 HMAC；服务端返回服务端 HMAC。
- HMAC key 由静态 X25519 shared 与 TLS exporter 通过
  `"mio quic auth 1.0.0"` 派生。

完整线上格式见 [docs/protocol.md](docs/protocol.md)。

## Chrome 指纹

```bash
./target/release/mio fingerprint \
  --server 127.0.0.1:19443 \
  --dest example.com
```

预期输出：

```text
ja4=t13d1516h2_8daaf6152771_806a8c22fdea
canonical_ja3_md5=8e19337e7524d2573be54efb2b0784c9
chrome_156_match=true
```

扩展顺序和 GREASE 值按连接随机，逐连接原始 JA3 MD5 不稳定是 Chrome/uTLS 的正常行为。
稳定验收使用 JA4 和 canonical JA3。

## 测试

```bash
cargo test
cargo clippy --all-targets -- -D warnings
python3 scripts/e2e_local.py
python3 scripts/udp_relay_local.py
```

验证覆盖：

- 静态 X25519 认证和两条认证记录 round-trip
- 混合密钥交换一致性
- QUIC marker 的真实 Initial 解析和 replay cache
- TCP/QUIC 并行探测、TCP fallback
- TCP 多 stream 会话复用
- Chrome ClientHello 离线回归
- 未标记 UDP 伪装转发
- SOCKS5 UDP ASSOCIATE over TCP tunnel
- Rust 客户端 ↔ Go v0.6.5 服务端 TCP 互操作；Rust↔Rust QUIC E2E

结果：

```text
cargo test                         33 unit + 2 fingerprint regression PASS
scripts/e2e_local.py               Rust client/server two-request session PASS
scripts/udp_relay_local.py         UDP camouflage relay PASS
socks5 UDP ASSOCIATE E2E           UDP echo over TCP tunnel PASS
Rust client -> Go v0.6.5, auto race PASS (TCP selected)
Rust client -> Go v0.6.5, forced TCP PASS
Go v0.6.5 client -> Rust, TCP two streams PASS
```

## 目录

- `src/tls.rs`：Chrome ClientHello、BoringSSL 握手边界、私钥导出和指纹解析
- `src/crypto.rs`：静态密钥、HKDF、AES-GCM、X25519MLKEM768
- `src/protocol.rs`：TLS record、请求/应答和 relay helper
- `src/session.rs`：v0.6.5 多路复用流、window/close/reset 帧和 TCP 记录层
- `src/client.rs`：SOCKS5、TCP session pool、TCP/QUIC 探测和回退
- `src/server.rs`：伪装转发、静态认证接管、stream 代理
- `src/quic.rs`：Quinn、BBR、QUIC marker/proof 和 stream 代理
- `src/udp_demux.rs`：QUIC Initial 解析、UDP 分流和伪装 relay
- `src/config.rs`：v0.6.5 严格 TOML 配置

## 已知差异

- QUIC TLS 使用 rustls，不是 Chrome/uTLS；上游 QUIC 也不是 Chrome 指纹。
- Quinn BBR 与上游 quic-go/Hysteria2 BBR 不是逐行等价实现。
- 不提供 UDP over SOCKS5，与上游一致。
- QUIC 未实现上游客户端那种零长度源 Connection ID，但协议认证和数据互操作通过。

## 许可

本实现研究并重写了 [orgmio/mio](https://github.com/orgmio/mio) 的协议行为。上游项目
采用 [Mo Public License](https://867678.xyz/docs/mopl)；使用、分发或修改前请阅读并
遵守上游许可和适用法律。仓库内 `vendor/boringssl/LICENSE` 是 BoringSSL 的许可证。
本项目没有复制上游 quic-go BBR 源码，使用 Quinn 自带实验性 BBR。