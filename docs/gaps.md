# v0.6.3 差异补全与可行性研究

本文记录 Rust 重写与上游 `orgmio/mio` v0.6.3（线上协议 v1.0.0）的逐项差异。

## 总览

| 差异 | 状态 | 说明 |
| --- | --- | --- |
| TCP 静态 X25519 认证 | 已补全 | ClientHello key_share 私钥 + 服务端静态私钥 |
| TCP 多路复用 stream | 已补全 | stream id、流量控制、close/reset/window 帧 |
| 双认证记录 | 已补全 | 认证记录 nonce 0 + 份额记录 nonce 1 |
| 服务端 QUIC UDP 分流 | 已补全 | 公钥派生 marker、replay cache、未标记 UDP relay |
| UDP-over-mio 关联 | 已补全 | `00` 流请求、长度前缀 datagram、服务端多目标 UDP relay |
| 客户端 SOCKS5 UDP ASSOCIATE | 已补全 | `socks5_udp=true`，经 TCP 代理流转发 UDP |
| 客户端 TCP/QUIC 首选+备份 | 已补全 | 延迟启动备份，先成功打开目标者胜出 |
| Chrome 156+ sigalgs | 已补全 | GREASE + ML-DSA-44/65/87，vendored BoringSSL |
| BoringSSL ClientHello 私钥导出 | 已补全 | 自定义补丁，支持 HRR/config shedding |
| QUIC BBR | 已启用 | Quinn 0.11.19 内置实验性 BBR，非上游逐行移植 |
| QUIC TLS 指纹 | 保留差异 | 上游 QUIC 使用 Go crypto/tls，非 uTLS Chrome |

## TCP 静态认证

v0.6.3 不使用密码。服务端持有一对 X25519 静态密钥，客户端只配置公钥：

```text
shared = X25519(client TLS key_share private, server static public)
       = X25519(server static private, client key_share public)
```

握手后客户端连续发送两条记录：

```text
key       = HKDF(shared, client_random ‖ server_random, "mio auth 1.0.0")
认证记录: nonce = 0，plaintext = random_padding(71)
份额记录: nonce = 1，plaintext = client_share(1216) ‖ random_padding(0–255)
header    = 17 03 03 ‖ length
record    = header ‖ AEAD-Seal(key, nonce, plaintext, ad=header)
```

服务端先验证认证记录，再读取份额记录。认证记录固定 87 字节密文，对应 Chromium
HTTP/2 连接开头的第一条 Application Data 记录。

TLS 记录转发只在对端正常 EOF 时转发已读到的残缺记录；本地主动关闭或发生 I/O
错误时丢弃残缺部分，避免给对端留下半条记录导致后续记录错位。

BoringSSL 本身不暴露 ClientHello X25519 key_share 私钥。`vendor/boringssl` 增加了
稳定 getter，并经过真实 TLS 1.3 握手、HelloRetryRequest、配置 shedding 和公私钥
一致性测试。

## TCP 多路复用

`src/session.rs` 实现 v0.6.3 `Session`：

- 帧头：`type(1) ‖ stream_id(4) ‖ payload_length(2)`
- ready/data/close/reset/window 五种帧
- 每方向 32 MiB 会话窗口；每条流另有 16 MiB 窗口，发送/接收同时计入两层额度
- 流编号由客户端分配，从 1 递增；服务端收到新编号的第一个 data 帧即创建流
- 每条 TCP 会话最多 100 条并发流；服务端用 reset 帧拒绝超限的新流
- 客户端 pool 尽量复用同一条 TCP session，达到 100 条流后再新建
- 每条流的读写独立阻塞，不阻塞同一 session 的其他流
- 所有流共享容量为 1 的 write slot；等待者会观察自己的 write deadline 和 session 关闭
- 每帧写 socket 前设置最长 10 秒写超时；写失败会同时回滚 session 和 stream 额度、sentData、nextPadding
- 首帧流编号和记录写入在同一个 write slot 内完成，保持编号和 TLS 记录顺序
- 会话窗口更新由独立 control loop 合并发送；未知/已关闭流占用后归还的会话额度也会批量返还

本地测试覆盖两个连续 SOCKS 请求复用同一 session；Go v0.6.3 客户端到 Rust 服务端
也通过了同一条 TCP 连接上的两条流。

## 服务端 QUIC UDP 分流

实现位于 `src/udp_demux.rs`：

1. 用 `AsyncUdpSocket` 适配器把合法 QUIC 包送入 Quinn。
2. 对每个 UDP 源地址维护 `Pending / Mio / Relay` 流状态。
3. 解密 QUIC v1 Initial 并读取 ClientHello.random。
4. marker key 由服务端静态公钥经
   `HKDF(public_key, empty_salt, "mio quic marker 1.0.0")` 派生。
5. 验证 16 字节 nonce + 16 字节分钟级 HMAC，接受当前分钟 ±1 分钟。
6. 用 replay cache 拒绝重复 marker。
7. 无 marker 的流按客户端地址建立到 `dest` 的 UDP relay，响应从同一服务端
   端口返回。

## UDP-over-mio

- 代理流首字节 `0` 表示 UDP 关联；服务端回复 `0` 后双方交换
  `length(2) ‖ 地址 ‖ payload` 的独立数据报。
- 服务端为每个关联维护目标 UDP socket，最多 64 个；空闲约 60 秒由读超时回收。
- TCP 与 QUIC 服务端都支持该扩展。
- 客户端 `[outbounds].socks5_udp = true` 时接受 SOCKS5 UDP ASSOCIATE，校验
  控制连接对端地址、固定客户端 UDP 源地址、拒绝 FRAG 非零的数据报。
- Rust 客户端当前通过 TCP 代理流承载 UDP 关联；上游也可能使用 QUIC，属于实现差异，
  但线上 datagram 格式兼容。
- 记录层每个方向限制同一密钥最多 `2^24` 条记录，达到上限前关闭会话。

## 客户端传输探测

实现位于 `src/client.rs::Dialer`：

- 初始 preferred transport 为 TCP，不再后台预热 QUIC。
- 每个代理请求先启动 preferred；延迟 250ms–1s 后启动 backup。若已到重新比较时间，
  head start 缩短到 25ms，让两条路径近似同时竞争。
- 不单独发起后台 probe：两条路径都直接打开目标连接，先成功者在本次请求获胜；
  preferred 明确收到目标不可达时立即返回，不等待 backup。
- 成功后更新 preferred、平滑延迟，并安排下一次比较：首次 1–10 秒，之后 10–30 分钟。
- QUIC session 在 Dialer 内缓存；并发请求共享同一个 `quicDial` attempt，失败不会排队重试。
- TCP pool 会剔除 closed session，并选择少于 100 条流的会话复用；并发的 TCP 建连共享
  同一个 attempt。
- QUIC 目标请求的 write + reply 共用 deadline；失败时 CancelRead/CancelWrite。
- TCP 请求 reply 超时且整个会话期间没有收到任何记录时，关闭该僵死 session。
- TCP 建连、TLS 握手、认证记录和 ready 使用 10 秒总预算；单次 Dial 总时限 25 秒
  （DNS 解析仍受系统解析器限制）。
- `Dialer::close()` 在客户端停止时关闭缓存 QUIC 与所有 TCP session。Rust 同步 API
  没有 Go context 的完整取消语义。

验证：Rust↔Go v0.6.3 的 TCP 强制路径、auto race 和 TCP 两 stream 均通过；
Go v0.6.3 在该环境默认选择了 TCP，未单独强制其 QUIC 路径。Rust↔Rust QUIC E2E 通过。
SOCKS5 UDP ASSOCIATE 使用 `udp=false` 的 TCP 隧道做了本机 UDP echo E2E，通过。

## BoringSSL 与 Chrome 156+

`vendor/boringssl` 基于 `boring-sys 5.4.0`，预应用：

1. `boring-pq.patch`
2. `patches/boringssl-no-sigalg-grease.patch`
3. `patches/boringssl-x25519-key-share.patch`

默认构建同时满足：

- JA4 `t13d1516h2_8daaf6152771_806a8c22fdea`
- canonical JA3 MD5 `8e19337e7524d2573be54efb2b0784c9`
- raw ClientHello 与 uTLS 的固定长度一致（ECH body 282 时为 1825 bytes）

扩展顺序仍然随机，逐连接 JA3 MD5 不稳定是 Chrome 本身行为。上游在 uTLS Chrome 133
扩展集上给 `signature_algorithms` 前置 GREASE + ML-DSA-44/65/87；Rust 的 vendored
BoringSSL 同步该形状。真实 Chrome 156/158 还发送 `trust_anchors (0xca34)`，上游没有
该扩展，因此本实现的 JA4 为 `..._806a8c22fdea`（16 个非 GREASE 扩展），而不是当前
浏览器捕获的 `..._cb7bf5808d99`（17 个）。

## QUIC BBR

Quinn 0.11.12 实际解析到 `quinn-proto 0.11.19`，内置
`quinn::congestion::BbrConfig`。客户端和服务端都启用：

- 客户端 `initial_mtu`：IPv4 1252，IPv6 1232
- 服务端 `initial_mtu`：1200
- 初始窗口：`32 × initial_mtu`
- 服务端关闭 segmentation offload

它不是上游 BBR 的忠实移植：Quinn pacer 使用 `window()/RTT`，公开 `Controller`
trait 没有逐包 ACK/丢失列表，无法复现上游的 packet-number-indexed bandwidth
sampler。因此口径是“已启用 Quinn 实验性 BBR”，不是“算法级等价”。

## 保留差异

- QUIC 的 TLS 栈是 rustls，不是 Chrome/uTLS；上游 QUIC 自身也不是 Chrome 指纹。
- Quinn BBR 不是上游算法逐行等价实现。
- 不提供 UDP-over-SOCKS5。
- QUIC 未复刻上游的零长度源 Connection ID。
- 未复刻 Go 的 recvmmsg / OOB / GSO 优化；Rust 继续使用 Quinn 自身的分段发送和
  `AsyncUdpSocket` 路径。收包 Vec 在循环外复用，relay 缓冲保持 2048 字节。
- Go 的 `DialTCP`、可替换 `PaddingPolicy` 和公开 `NewSession` 属于上游 API 调整，
  Rust 已有自己的 API/内部填充实现，不做机械复制。
- Go 的 Session 发送/接收缓冲和 nonce 原地复用、加密缓冲 zero padding 属于内部性能优化；
  Rust 的 Session 结构不同，暂未逐项照搬，线上帧长度语义保持一致。
- Rust TCP session pool 没有复刻 Go 客户端 4–6 分钟空闲回收；当前按 100 条流上限或
  session 关闭来换新连接。
- Rust 同步 API 没有 Go context 的完整取消语义；QUIC 使用显式 timeout/retire，TCP
  建连仍受同步 DNS 解析和 10 秒握手预算限制。
