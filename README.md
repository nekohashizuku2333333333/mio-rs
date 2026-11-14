# mio-rs

`mio-rs` 是 [orgmio/mio](https://github.com/orgmio/mio) v0.5.1 的 Rust 重写。它实现：

- TCP 伪装站点转发、静态 X25519 认证、X25519MLKEM768 会话密钥交换
- QUIC 同端口 UDP marker 分流、静态密钥双向证明、stream 代理
- SOCKS5 `CONNECT` 客户端
- Chrome 133 TCP ClientHello 指纹
- TCP/QUIC 并行探测、延迟选择、10–30 分钟重新探测和自动回退
- Quinn 实验性 BBR，初始窗口 `32 × MTU`

上游协议版本同时是线上协议版本。v0.5.1 使用静态 X25519 密钥对和版本化 HKDF
标签，与旧版密码认证不兼容；客户端和服务端必须一起升级。

## 状态

| 功能 | 状态 |
| --- | --- |
| mio v0.5.1 TCP 认证、ready 帧、混合密钥交换 | 已实现 |
| 服务端 TCP 伪装转发与认证接管 | 已实现 |
| 服务端 QUIC UDP marker 分流 | 已实现 |
| 未标记 UDP 转发到 `dest` | 已实现 |
| QUIC exporter HMAC 静态密钥认证 | 已实现 |
| SOCKS5 客户端 | 已实现 |
| TCP/QUIC 并行探测与回退 | 已实现 |
| Chrome 133 TCP ClientHello | JA4/canonical JA3/raw 长度均匹配 |
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

仓库内置了 `vendor/boringssl`，`.cargo/config.toml` 通过
`BORING_BSSL_SOURCE_PATH` 使用它，并设置 `BORING_BSSL_ASSUME_PATCHED=1`。
源码基于 `boring-sys 5.4.0`，已按顺序应用：

1. `boring-pq.patch`（Cloudflare PQ 支持）
2. `patches/boringssl-no-sigalg-grease.patch`（Chrome 133 sigalg shape）
3. `patches/boringssl-x25519-key-share.patch`（导出 ClientHello X25519 私钥）

第三项是 v0.5.1 所必需的：上游用 TLS ClientHello 里的 X25519 key_share 私钥与
服务端静态公钥计算认证共享密钥，stock BoringSSL 不提供该私钥。补丁实测通过真实
TLS 1.3 握手、HRR、配置 shedding 和公私钥一致性检查。

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

客户端 [config/client.example.toml](config/client.example.toml)：

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
dest_port = 443
public_key = "mio keygen 生成的 PublicKey"
```

服务端 [config/server.example.toml](config/server.example.toml)：

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
dest_port = 443
private_key = "mio keygen 生成的 PrivateKey"
```

`dest` 必须与客户端一致，客户端会用该名称校验真实伪装站证书。服务端 TCP 和 UDP
使用同一个 `listen_port`。

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
3. 客户端发送 TLS Application Data 认证记录： `share(1216) ‖ padding(32–1024)`，
   使用 `HKDF(shared, client_random‖server_random, "mio auth 0.5.1")` 和 header AAD。
4. 服务端吞掉认证记录，生成 X25519MLKEM768 服务端份额，用初始会话密钥发送 ready 帧，
   双方再切换到包含混合 secret 的会话密钥。
5. 目标请求和应答沿用 v0.5.1 的 `atyp/address/port` 格式。

### QUIC

- ClientHello.random = 16B nonce + 16B 分钟级 HMAC，key 由服务端公钥 HKDF 派生。
- 服务端解析 QUIC v1 Initial，验证 marker、±1 分钟窗口和 replay cache。
- 合法 marker 交给 Quinn；未标记 UDP 流按客户端地址转发到 `dest` 并回传响应。
- 握手后首个 stream：客户端临时 X25519 公钥 + 客户端 HMAC；服务端返回服务端 HMAC。
- HMAC key 由静态 X25519 shared 与 TLS exporter 通过
  `"mio quic auth 0.5.1"` 派生。

完整线上格式见 [docs/protocol.md](docs/protocol.md)。

## Chrome 指纹

```bash
./target/release/mio fingerprint \
  --server 127.0.0.1:19443 \
  --dest example.com
```

预期输出：

```text
ja4=t13d1516h2_8daaf6152771_d8a2da3f94cd
canonical_ja3_md5=8e19337e7524d2573be54efb2b0784c9
chrome_133_match=true
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

- 静态 X25519 认证和认证记录 round-trip
- 混合密钥交换一致性
- QUIC marker 的真实 Initial 解析和 replay cache
- TCP/QUIC 并行探测、TCP fallback
- Chrome ClientHello 离线回归
- 未标记 UDP 伪装转发
- Rust 客户端 ↔ Go v0.5.1 服务端的 TCP/QUIC 互操作

结果：

```text
cargo test                         10 unit + 2 fingerprint regression PASS
scripts/e2e_local.py               Rust client/server QUIC PASS
scripts/udp_relay_local.py         UDP camouflage relay PASS
Rust client -> Go v0.5.1 server     TCP + QUIC PASS
Go v0.5.1 client -> Rust server     TCP + QUIC PASS
```

## 目录

- `src/tls.rs`：Chrome ClientHello、BoringSSL 握手边界、私钥导出和指纹解析
- `src/crypto.rs`：静态密钥、HKDF、AES-GCM、X25519MLKEM768
- `src/protocol.rs`：TLS record、mio v0.5.1 帧、请求/应答和 relay
- `src/client.rs`：SOCKS5、TCP/QUIC 探测和回退
- `src/server.rs`：伪装转发、静态认证接管、目标代理
- `src/quic.rs`：Quinn、BBR、QUIC marker/proof 和 stream 代理
- `src/udp_demux.rs`：QUIC Initial 解析、UDP 分流和伪装 relay
- `src/config.rs`：v0.5.1 严格 TOML 配置

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