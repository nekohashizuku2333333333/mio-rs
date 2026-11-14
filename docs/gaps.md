# v0.5.1 差异补全与可行性研究

本文记录 Rust 重写与上游 `orgmio/mio` v0.5.1 的逐项差异、已补全部分和保留限制。

## 总览

| 差异 | 状态 | 说明 |
| --- | --- | --- |
| TCP 静态 X25519 认证 | 已补全 | ClientHello X25519 key_share 私钥 + 服务端静态私钥 |
| 服务端 QUIC 同端口 UDP 分流 | 已补全 | 公钥派生 marker、replay cache、未标记 UDP relay |
| 客户端 TCP/QUIC 并行探测 | 已补全 | 首请求并行、平滑延迟、10–30 分钟重新探测 |
| 原始 ClientHello sigalg GREASE | 已补全 | vendored BoringSSL，默认构建即匹配 |
| BoringSSL ClientHello 私钥导出 | 已补全 | 自定义补丁，支持 HRR/config shedding |
| QUIC BBR | 已启用 | Quinn 0.11.19 内置实验性 BBR，非上游逐行移植 |
| QUIC TLS 指纹 | 保留差异 | 上游 QUIC 使用 Go crypto/tls，非 uTLS Chrome |

## TCP 静态认证

v0.5.1 不再使用密码。服务端持有一对 X25519 静态密钥，客户端只配置公钥：

```text
shared = X25519(client TLS key_share private, server static public)
       = X25519(server static private, client key_share public)
```

认证记录使用：

```text
key       = HKDF(shared, client_random ‖ server_random, "mio auth 0.5.1")
plaintext = client_share(1216) ‖ random_padding(32–1024)
header    = 17 03 03 ‖ length
record    = header ‖ AEAD-Seal(key, nonce=0, plaintext, ad=header)
```

服务端从转发的 ClientHello 中提取 random 和 X25519 key_share，再用静态私钥验证。
认证成功后发送 ready 帧，双方切换到包含 X25519MLKEM768 secret 的会话密钥。

BoringSSL 本身不暴露 ClientHello X25519 key_share 私钥。`vendor/boringssl` 增加了
一个稳定 getter，并通过真实 TLS 1.3 握手、HelloRetryRequest、配置 shedding 和
公私钥一致性测试。

## 服务端 QUIC UDP demux

实现位于 `src/udp_demux.rs`。服务端不再让 Quinn 直接占用 UDP socket，而是：

1. 用 `AsyncUdpSocket` 适配器把合法 QUIC 包送入 Quinn。
2. 对每个 UDP 源地址维护 `Pending / Mio / Relay` 流状态。
3. 解密 QUIC v1 Initial 并读取 ClientHello.random。
4. marker key 由服务端静态公钥经
   `HKDF(public_key, empty_salt, "mio quic marker 0.5.1")` 派生。
5. 验证 16 字节 nonce + 16 字节分钟级 HMAC，接受当前分钟 ±1 分钟。
6. 用 replay cache 拒绝重复 marker。
7. 无 marker 的流按客户端地址建立到 `dest` 的 UDP relay，响应从同一服务端
   端口返回。

新增测试：

- `tests/fixtures/quic_initial.hex`：真实 Rust 客户端 QUIC Initial。
- `udp_demux::tests::captured_quic_initial_exposes_random_and_replay_cache` 校验 Initial
  解密和 marker 解析。
- `scripts/udp_relay_local.py` 校验未标记 UDP 的端到端 relay。

## 客户端传输探测

实现位于 `src/client.rs::Dialer`。行为：

- 后台预热一条 QUIC session。
- 首次请求并行执行 TCP 和 QUIC 完整代理建立，先成功者交给应用。
- 保存两条线路的平滑建立延迟；后续选择更快线路。
- 随机 10–30 分钟后重新探测。
- QUIC stream 传输失败时回退 TCP。
- 服务端明确返回“目标连接失败”时不误判为传输故障，不重复尝试。

验证：占用服务端 UDP 端口强制 QUIC bind 失败后，SOCKS5 echo 仍成功，日志选择
`Tcp`。

## BoringSSL 与 Chrome 133

`vendor/boringssl` 基于 `boring-sys 5.4.0`，预应用：

1. `boring-pq.patch`
2. `patches/boringssl-no-sigalg-grease.patch`
3. `patches/boringssl-x25519-key-share.patch`

默认构建同时满足：

- JA4 `t13d1516h2_8daaf6152771_d8a2da3f94cd`
- canonical JA3 MD5 `8e19337e7524d2573be54efb2b0784c9`
- raw ClientHello 与 uTLS 相同的固定长度（1817 bytes，ECH body 282 时）

扩展顺序仍然随机，逐连接 JA3 MD5 不稳定是 Chrome 本身行为。

## QUIC BBR

Quinn 0.11.12 实际解析到 `quinn-proto 0.11.19`，内置
`quinn::congestion::BbrConfig`。客户端和服务端都启用：

- 客户端 `initial_mtu`：IPv4 1252，IPv6 1232
- 服务端 `initial_mtu`：1200
- 初始窗口：`32 × initial_mtu`
- 服务端关闭 segmentation offload

但它不是上游 BBR 的忠实移植：

- Quinn pacer 使用 `window()/RTT`，不直接使用 BBR `pacing_rate`。
- 公开 `Controller` trait 没有逐包 ACK/丢失列表，无法复现上游的
  packet-number-indexed bandwidth sampler。
- 上游 BBR 约 2.5k Go LoC，Quinn BBR 约 900 Rust LoC。

因此口径是“已启用 Quinn 实验性 BBR”，不是“与上游 quic-go BBR 等价”。

## 保留差异

- QUIC 的 TLS 栈是 rustls，不是 Chrome/uTLS；上游 QUIC 自身也不是 Chrome 指纹。
- Quinn BBR 不是上游算法逐行等价实现。
- 不提供 UDP-over-SOCKS5。
- QUIC 未复刻上游的零长度源 Connection ID。