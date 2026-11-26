# mio 协议规范

本文描述 mio 协议 v1 的线上格式，目的是让其他实现不看代码也能互通。所有密钥派生 label 中的 `VERSION` 值均为 `1.0.0`，不包含前导 `v`、空格或终止符。

## 总览

mio 有两条传输路径，监听同一个端口：

- **TCP 路径**：外观是一条到伪装站（`dest`）的普通 TLS 连接，认证后数据由 mio 自己的记录层加密。一条连接上可以同时承载多个代理连接，就像浏览器在一条 HTTP/2 连接上发出多个请求。
- **QUIC 路径**：外观是到伪装站的 HTTP/3，认证靠 ClientHello.random 里的标记和握手后基于 `S` 的双向证明，数据由 QUIC 本身加密。

两条路径在认证之后使用相同的[目标请求](#4-目标请求)格式。

## 密钥

服务端持有一对 X25519 静态密钥，由 `mio keygen` 生成：

- **私钥** `S`：只放在服务端（`[inbounds].private_key`）。
- **公钥** `S_pub`：放在客户端（`[outbounds].public_key`）。客户端靠它确认对端确实是这台服务端；服务端则把「知道 `S_pub`」视为客户端获得了授权。

两者都编码为不带填充的 URL 安全 base64（43 个字符）。
mio 不使用密码：所有认证用的密钥都来自 X25519 共享密钥，其中没有任何低熵的值可供离线猜测；没有 `S`，也无法冒充服务端。

记号：`‖` 表示字节拼接；多字节整数一律大端；`HKDF` 指 HKDF-SHA256；`AEAD` 指 AES-256-GCM（12 字节 nonce，16 字节 tag）。

## TCP 路径

### 借用伪装站完成 TLS 握手

1. 客户端用 Chrome 指纹（uTLS）向服务端发起 TLS 握手，SNI 为 `dest`。
2. 服务端为每个入站连接拨号 `dest:dest_port`（`dest_port` 缺省时等于 `listen_port`），按 TLS 记录双向原样转发，同时记下：
   - `client_random`：ClientHello 的 random（32 字节）。
   - `E_pub`：ClientHello 里 `key_share` 扩展中 X25519（group `0x001d`）的份额（32 字节）。
   - `server_random`：最后一条 ServerHello 的 random（出现 HelloRetryRequest 时以最后一条为准）。
3. 客户端与真实的伪装站完成整个 TLS 握手，并按正常规则校验其证书。

### 认证记录

客户端在发出 ClientHello 之前就持有 `E_pub` 对应的私钥 `E`，两端可以算出同一个共享密钥：

```
shared = X25519(E, S_pub) = X25519(S, E_pub)
```

`E_pub` 本来就是 ClientHello 里的普通 key_share，所以这一步不会在线上多出任何字节。

握手完成后，客户端直接在 TCP 上连续发出两条记录，**认证记录**和**份额记录**：

```
key    = HKDF(ikm = shared, salt = client_random ‖ server_random, info = "mio auth " ‖ VERSION, 32)
header = 17 03 03 ‖ length(2)            ; length = len(plaintext) + 16
record = header ‖ AEAD-Seal(key, nonce, plaintext, ad = header)

认证记录：nonce = 0^12，     plaintext = random_padding(71)
份额记录：nonce = 0^11 ‖ 01，plaintext = client_share(1216) ‖ random_padding(0–255)
```

- `client_share` = X25519 公钥（32）‖ ML-KEM-768 封装公钥（1184）。
- 认证记录的明文只有随机填充，它的作用是证明发送方算得出 `key`。记录体因此固定是 87 字节，
  与 Chrome 在 HTTP/2 连接开头发出的第一条记录（连接前言、SETTINGS 和 WINDOW_UPDATE）一样长（Chromium 157 实测）；紧随其后的份额记录则处在浏览器第一个请求的位置上。

服务端在看到 ServerHello 之后，用 `S` 和 `E_pub` 算出 `shared`，对客户端随后发来的 Application Data 记录尝试按认证记录的方式解密。
解密成功且明文不超过 256 字节即认证通过。服务端只尝试握手后的前 8 条记录，之后这条连接只做原样转发，所以认证记录必须紧跟在握手之后发出。
出现 HelloRetryRequest 时，`E_pub` 取第一条 ClientHello 里的份额。
认证通过后，服务端吞掉这条记录，停止转发并关闭到 `dest` 的连接；否则继续转发，中间设备甚至用户看到的始终是伪装站。
随后服务端读取下一条记录，它必须是能解开的份额记录（明文不少于 1216 字节），否则关闭连接。份额记录须在 5 秒内到达。
服务端收到 Application Data 后停止解析，并把后续字节原样转发；正常 EOF 会半关闭对应方向，以双向传递 FIN。

因为密钥依赖每条连接都不同的 `server_random`，所以录下的认证记录无法在别的连接上重放。
不知道 `S_pub` 的人算不出 `shared`，造不出认证记录；被动监听者也无从离线猜测，因为没有任何低熵的秘密。

### 密钥交换与会话密钥

两个方向的密钥由下面的函数派生（代码中为 `protocol.DeriveKeys`）：

```
DeriveKeys(secret):
  ikm  = secret ‖ shared
  salt = client_random ‖ server_random
  c2s  = HKDF(ikm, salt, "mio c2s", 32)      ; 客户端 → 服务端
  s2c  = HKDF(ikm, salt, "mio s2c", 32)      ; 服务端 → 客户端
```

1. 服务端从份额记录里取出 `client_share`，生成 X25519 临时密钥，对 ML-KEM-768 封装公钥做封装，得到：
   - `server_share` = X25519 公钥（32）‖ ML-KEM-768 密文（1088）
   - `secret` = X25519 共享密钥（32）‖ ML-KEM 共享密钥（32）
2. 服务端用 `DeriveKeys(空)` 的 `s2c` 密钥，以序号 0 发出一条 **ready 帧**（流编号为 0），负载为 `server_share`。
3. 客户端在收到 ready 帧之前，会跳过所有解不开的记录（例如伪装站在握手后发来的 NewSessionTicket）。收到 ready 后算出同样的 `secret`。
   能发出可解密的 ready 帧，就证明对端算得出 `shared`，也就是持有 `S`，因此中间人无法冒充服务端。
4. 双方都切换到 `DeriveKeys(secret)`，两个方向的序号都重置为 0。此后所有记录都使用会话密钥。

### 记录层与帧

每个帧单独封装成一条 TLS Application Data 记录：

```
header = 17 03 03 ‖ length(2)
record = header ‖ AEAD-Seal(key, nonce(seq), frame, ad = header)
nonce(seq) = 0^4 ‖ seq(8)          ; seq 每个方向独立，从 0 开始，每条记录加 1
```

发送方写出的记录体（密文）最长 16401 字节，与不带填充的 TLS 1.3 实现相同（16384 字节明文 + 1 字节类型 + 16 字节 tag）；
接收方须接受最长 16640 字节的记录体。解密后的帧为：

```
frame = type(1) ‖ stream_id(4) ‖ payload_length(2) ‖ payload ‖ padding
```

| type | 名称   | 含义                                                                |
| ---- | ------ | ------------------------------------------------------------------- |
| 0    | ready  | 服务端就绪，负载为 `server_share`，`stream_id` 为 0                 |
| 1    | data   | 流上的应用数据，负载最长 16378 字节                                 |
| 2    | close  | 发送方不再在这条流上发送数据（半关闭），负载为空                    |
| 3    | reset  | 发送方放弃这条流，不再读也不再写，负载为空                          |
| 4    | window | 流量控制，负载为 4 字节正整数。流编号为 0 时更新会话窗口，其余编号更新对应的流窗口 |

- `padding` 是随机字节，接收方按 `payload_length` 取负载后直接丢弃剩余部分。
- **接收方遇到不认识的 type 必须跳过该帧**，以便以后扩展。
- 每个方向的同一把会话密钥最多加密/解密 `2^24`（16,777,216）条记录，包括控制帧；达到上限前必须关闭整个 TCP 会话，禁止序号回绕。

### 流

握手完成后，一条连接上可以同时有多条**流**，每条流承载一个代理连接，并各自进行流量控制。

- **打开**：只有客户端可以打开流。`stream_id` 从 1 开始，每条新流加 1，并且新流的第一个 data 帧必须按 `stream_id` 递增的顺序写出。
  服务端收到 `stream_id` 大于此前见过的最大值的 data 帧，就视为客户端打开了一条新流。没有单独的"打开"帧。
- **半关闭**：一方发完数据后发 close 帧，另一方读完已到达的数据后读到结束。两个方向各自独立，都发过 close 帧后这条流就结束了。
- **放弃**：一方不想再读写时发 reset 帧。对端收到后，这条流上的发送立即失败；已经到达的数据仍可读完，之后的读取得到结束（对端已先发过 close 帧）或错误。
  在还没读到对端 close 帧时关闭一条流，应当先发 close 帧（如果自己还没发过），再发 reset 帧。
- **已结束的流**：收到属于已结束流的帧、或属于未知流的非 data 帧时，直接丢弃。编号 0 的 window 帧按会话处理。
- **并发上限**：每条 TCP 会话同时最多承载 100 条流。服务端用 reset 帧拒绝超过上限的新流。
- **流量控制**：每个方向都有 32 MiB 的会话窗口，每条流另有 16 MiB 的流窗口。发送 data 帧时按负载字节数同时扣减两个窗口，任一窗口耗尽后等待对应的 window 帧。接收方在应用读走数据后归还会话额度和仍在接收数据的流额度。被丢弃的 data 也占用会话额度，丢弃后归还。控制帧和填充不占用额度。
  对端发送的数据超出可用窗口、或者把窗口增加到超过初始值，属于协议错误，应关闭整条连接。
- **连接关闭**：TCP 连接断开或出现协议错误时，其上所有的流一并失效。

客户端的行为（不影响互通）：所有代理连接尽量复用同一条 TCP 连接；一条连接上的流达到 100 条时再开一条；
连接上没有任何流的状态持续 4 到 6 分钟（随机）后关闭它。

### 填充

默认填充策略（`protocol.DefaultPadding`）：

- ready 帧：0–1024 字节。
- 每条流在每个方向上的前 8 个 data 帧：负载不足 900 字节的，补到整帧 900–1400 字节；其余随机加 0–255 字节。
- 之后的 data 帧，以及 close、reset、window 帧不填充。
- 例外：目标请求和应答所在的 data 帧，填充 16–512 字节。

大块数据按一帧 16378 字节的负载发出，正好填满一条最大的记录，记录长度与被代理连接自身的分包方式无关。

## QUIC 路径

### 标记

客户端把 ClientHello.random 设为：

```
nonce  = 随机 16 字节
minute = floor(unix_time / 60)，8 字节
marker_key = HKDF(ikm = S_pub, salt = 空, info = "mio quic marker " ‖ VERSION, 32)
random     = nonce ‖ HMAC-SHA256(marker_key, nonce ‖ minute)[:16]
```

服务端用 RFC 9001 的方法解开客户端的 Initial 包，取出 random，接受 `minute` 与本地相差 ±1 的标记。用过的 nonce 会被记住 5 分钟，重复的视为重放。
没有有效标记的 UDP 流量会原样转发给伪装站。**双方时钟误差需要在 1 分钟以内。**

### 握手与认证

服务端使用临时自签证书，ALPN 为 `h3`，TLS 1.3；客户端不校验这个证书，对端身份由下面的证明确认。

```
exporter = TLS-Exporter("mio quic auth", 空, 32)          ; 双方各自导出，绑定到这条 QUIC 连接
C        = 客户端新生成的 X25519 临时密钥
shared   = X25519(C, S_pub) = X25519(S, C_pub)
key      = HKDF(ikm = shared, salt = exporter, info = "mio quic auth " ‖ VERSION, 32)
```

1. 客户端打开第一个 stream，发送 `C_pub(32) ‖ HMAC-SHA256(key, "client")`，共 64 字节。
2. 服务端算出 `key` 并校验客户端证明，通过后回复 `HMAC-SHA256(key, "server")`（32 字节），然后关闭这个 stream。
3. 客户端校验服务端的回复，通过后才开始发送代理请求。整个过程须在 5 秒内完成。

只有持有 `S` 的一方能算出服务端的回复，所以即使客户端不校验证书，中间人也无法冒充服务端。

### 数据

之后客户端每发起一个代理连接就打开一个新的双向 stream，先交换[目标请求](#4-目标请求)，再直接传输原始字节。QUIC 本身已经加密，所以这里不再套用第 2.4 节的帧格式。

### 客户端选路

客户端初始偏好 TCP。每个新代理连接先尝试 preferred 路径，随后在 250ms–1s 后启动另一条路径；两条路径都直接打开目标连接，先成功者为本次请求服务。若到达重新比较时间，备用路径的延迟缩短到 25ms。成功后更新 preferred 和平滑延迟，首次安排 1–10 秒后重新比较，之后每 10–30 分钟一次。

服务端明确回复目标不可达时立即返回该错误，不再等待另一条路径。切换 preferred 只影响后续新连接，已有连接继续在原路径上传输。

## 目标请求

每条流（QUIC 路径上是每个 stream）的第一段数据是客户端发出的目标地址：

```
request = atyp(1) ‖ address ‖ port(2)
  atyp 1：address = IPv4（4 字节）
  atyp 3：address = length(1) ‖ 域名（1–255 字节）
  atyp 4：address = IPv6（16 字节）
```

服务端连接目标后回复 1 字节：`0` 表示成功，`1` 表示失败。成功之后双向转发数据；失败只结束这一条流，连接上的其他流不受影响。
在 TCP 路径上，请求和应答各自放在一个 data 帧里；在 QUIC 路径上，直接写在 stream 上。

首字节 `0` 不是 TCP 地址类型，而是 **UDP 关联**扩展：客户端在新代理流上只发送 `00`，服务端支持时回复 `00` 表示关联就绪，拒绝时回复非零。旧服务端会把 `0` 当作未知地址类型并结束流。

UDP 关联建立后，双方在流上依次交换带长度前缀的数据报：

```text
datagram = length(2) ‖ atyp(1) ‖ address ‖ port(2) ‖ payload
```

`length` 覆盖地址与负载，范围 5–65504。客户端发送目标地址，服务端回复实际来源地址。每条消息保持一个 UDP 数据报的边界，允许空负载；消息可以跨越多个 TCP data 帧或 QUIC STREAM 帧。非法长度、消息中途 EOF 时必须终止关联。参考服务端每个关联最多保留 64 个目标 socket，空闲约 60 秒回收。

Rust 客户端在 `[outbounds].socks5_udp = true` 时提供 SOCKS5 UDP ASSOCIATE；控制 TCP 连接关闭即结束关联。UDP 负载在 mio 两端之间通过可靠、有序的代理流传输。

## Rust 实现接口

Rust 实现以 `mio-rs` crate 暴露：

| 模块 / 接口 | 作用 |
|------|------|
| `crypto::generate_key_pair` / `parse_private_key` / `parse_public_key` | 静态 X25519 密钥 |
| `crypto::auth_records` | 客户端两条认证/份额记录 |
| `crypto::verify_auth` / `read_share` | 服务端认证与份额读取 |
| `crypto::transport_keys` | 初始和会话阶段 AES-GCM 密钥 |
| `session::Session` | 多路复用 TCP 会话、流编号、close/reset/window |
| `session::Stream` | 单条代理流的 `Read` / `Write` / `CloseWrite` |
| `protocol::write_request` / `read_request` / `write_reply` / `read_reply` | 第 4 节目标请求 |
| `udp_demux::UdpDemuxSocket` | QUIC marker、replay cache 和未标记 UDP relay |
| `quic::QuicSession` | QUIC 静态认证和 stream 复用 |

版本常量：

```text
二进制版本: 0.6.3
协议版本:   1.0.0
```

协议版本参与 TCP auth label、QUIC marker key 和 QUIC auth key 派生。两端必须一致。

`vendor/boringssl` 中的补丁额外导出 ClientHello X25519 key_share 私钥；上游 uTLS
通过 `BuildHandshakeState().State13.KeyShareKeys.Ecdhe` 取得同一私钥。
