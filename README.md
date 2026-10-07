# ArkTP Reliable 用户开发指南

> **项目**：`arktp-reliable`\
> **版本**：`0.2.2`\
> **语言**：Rust 2024 Edition\
> **运行时**：Tokio\
> **协议定位**：基于 UDP 的可靠、可复用、多路复用传输层\
> **许可证**：Apache License 2.0

------------------------------------------------------------------------

## 1. 文档说明

ArkTP Reliable 是一个面向 Rust 应用程序的可靠 UDP 传输库。它在 UDP
之上提供可靠传输、丢包恢复、拥塞控制、加密、流、多路径、连接迁移、NAT
辅助、会话恢复以及运行时统计等能力。

本文件面向**直接使用 ArkTP Reliable 开发程序的用户**，重点回答以下问题：

-   如何把 ArkTP Reliable 加入 Rust 项目；
-   如何创建服务端；
-   如何创建客户端；
-   如何建立连接、发送和接收数据；
-   如何使用多路复用 Stream；
-   如何处理大数据、批量发送和异步读写；
-   如何配置加密、认证、后量子密钥交换；
-   如何使用 FEC、拥塞控制、多路径和连接聚合；
-   如何做连接迁移、MTU 探测、会话恢复和 0-RTT；
-   如何读取统计数据和导出 Prometheus 指标；
-   如何热更新运行时配置；
-   常见错误应该如何定位；
-   哪些 API 属于高级能力，什么时候应该使用。

本文根据项目当前源码中的公开 API
编写。源码中没有附带完整的用户示例目录，因此下面的代码示例是依据当前公开接口整理出的推荐使用方式。

------------------------------------------------------------------------

## 2. ArkTP Reliable 解决什么问题

普通 UDP 只提供"不保证可靠送达"的数据报能力。应用如果直接使用
UDP，需要自己处理：

-   丢包；
-   重复包；
-   乱序；
-   超时；
-   重传；
-   ACK/SACK；
-   流量控制；
-   拥塞控制；
-   加密；
-   密钥协商；
-   MTU；
-   多路径；
-   连接迁移；
-   连接生命周期；
-   统计与监控。

ArkTP Reliable 将这些能力封装到传输层中。

可以把它理解为：

``` text
┌───────────────────────────────────────────┐
│                你的应用程序               │
├───────────────────────────────────────────┤
│       ArkTPStream / ArkTPConnection       │
├───────────────────────────────────────────┤
│     可靠传输 / ACK / SACK / 重传 / 流控    │
├───────────────────────────────────────────┤
│   拥塞控制 / FEC / pacing / 批量 / HEDT    │
├───────────────────────────────────────────┤
│     加密 / 密钥交换 / 认证 / 会话恢复      │
├───────────────────────────────────────────┤
│        多路径 / 迁移 / NAT / PMTU         │
├───────────────────────────────────────────┤
│                    UDP                    │
└───────────────────────────────────────────┘
```

因此，应用通常不需要直接操作 ArkTP
的数据包格式。对于普通业务，建议只使用高层 API：

-   `ArkTPReliableServer`
-   `ArkTPReliableClient`
-   `ArkTPSocket`
-   `ArkTPConnection`
-   `ArkTPStream`
-   `SendHalf`
-   `RecvHalf`
-   `ArkTPConfig`

只有实现网关、协议调试器、监控工具或底层扩展时，才需要直接使用
`protocol` / `wire` 层。

------------------------------------------------------------------------

# 3. 快速开始

## 3.1 创建 Rust 项目

``` bash
cargo new my-arktp-app
cd my-arktp-app
```

ArkTP Reliable 当前 Cargo 包名称为：

``` toml
arktp-reliable
```

依赖方式：

``` toml
[dependencies]
arktp-reliable = "0.2.2"
tokio = { version = "1", features = ["full"] }
```

项目自身使用 Rust 2024 Edition，因此建议使用支持 Rust 2024 Edition
的现代 Rust 工具链。

检查环境：

``` bash
rustc --version
cargo --version
```

------------------------------------------------------------------------

## 3.2 服务端最小示例

推荐使用 `ArkTPReliableServer`：

``` rust
use arktp_reliable::{ArkTPConfig, ArkTPReliableServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = ArkTPReliableServer::bind(
        "0.0.0.0:9000",
        ArkTPConfig::default(),
    ).await?;

    println!("ArkTP server listening on {}", server.local_addr()?);

    loop {
        let connection = server.accept().await?;

        tokio::spawn(async move {
            loop {
                match connection.recv().await {
                    Ok(data) => {
                        println!("received {} bytes", data.len());

                        if let Err(e) = connection.send(&data).await {
                            eprintln!("send failed: {e}");
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("connection receive failed: {e}");
                        break;
                    }
                }
            }
        });
    }
}
```

这个服务端实现的是一个最简单的 Echo 服务：

``` text
Client ── data ──> Server
Client <── data ── Server
```

------------------------------------------------------------------------

## 3.3 客户端最小示例

``` rust
use arktp_reliable::{ArkTPConfig, ArkTPReliableClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = ArkTPReliableClient::new(ArkTPConfig::default())?;

    let socket = client.connect("127.0.0.1:9000").await?;

    socket.send(b"hello ArkTP").await?;

    let response = socket.recv().await?;

    println!(
        "server replied: {}",
        String::from_utf8_lossy(&response)
    );

    socket.close().await?;

    Ok(())
}
```

客户端内部会创建本地 UDP socket，然后连接到目标地址。

------------------------------------------------------------------------

# 4. 两种主要 Endpoint 使用方式

项目提供两套使用层级。

## 4.1 高层 API：推荐普通应用使用

``` text
ArkTPReliableServer
ArkTPReliableClient
```

优点：

-   API 简单；
-   自动创建和管理 socket；
-   适合业务程序；
-   不需要了解 PacketBus；
-   不需要自己管理连接 ID；
-   更适合直接封装成业务服务。

------------------------------------------------------------------------

## 4.2 底层 Endpoint API：需要更多控制时使用

``` text
ArkTPSocket
ArkTPListener
ArkTPConnection
```

例如服务端：

``` rust
let socket = ArkTPSocket::bind_with_config(
    "0.0.0.0:9000",
    ArkTPConfig::default(),
).await?;

let listener = socket.listen()?;

loop {
    let conn = listener.accept().await?;

    tokio::spawn(async move {
        // 使用 conn
    });
}
```

客户端：

``` rust
let mut socket = ArkTPSocket::bind("0.0.0.0:0").await?;

socket.connect("192.168.1.10:9000").await?;

socket.send(b"hello").await?;

let data = socket.recv().await?;
```

当程序需要：

-   动态修改配置；
-   多路径；
-   连接聚合；
-   会话票据；
-   连接迁移；
-   直接读取统计；
-   精细控制 endpoint；

建议使用 `ArkTPSocket`。

------------------------------------------------------------------------

# 5. ArkTP 的核心对象

## 5.1 ArkTPSocket

`ArkTPSocket` 是应用侧最主要的 Endpoint 对象。

它负责：

-   UDP socket；
-   ArkTP PacketBus；
-   Endpoint 配置；
-   建立连接；
-   接收连接；
-   发送和接收普通数据；
-   Stream；
-   多路径；
-   连接迁移；
-   密钥更新；
-   统计；
-   配置热更新。

主要 API：

``` rust
ArkTPSocket::bind(addr)
ArkTPSocket::bind_with_config(addr, config)
socket.connect(addr).await
socket.send(data).await
socket.recv().await
socket.send_batch(data).await
socket.open_stream(id).await
socket.accept_stream().await
socket.split()
socket.migrate(addr).await
socket.key_update().await
socket.probe_mtu(mtu).await
socket.reload_config(config)
socket.config()
socket.stats()
socket.close().await
```

------------------------------------------------------------------------

## 5.2 ArkTPConnection

`ArkTPConnection` 表示一个已经建立的 ArkTP 连接。

它提供：

``` rust
connection.send(...)
connection.recv().await
connection.send_all(...).await
connection.recv_exact(...).await
connection.send_batch(...).await
connection.open_stream(...).await
connection.accept_stream().await
connection.split()
connection.shutdown().await
connection.close().await
```

同时可以查询：

``` rust
connection.id()
connection.conn_id()
connection.remote_addr()
connection.state().await
connection.path_count().await
connection.path_stats().await
connection.stats()
connection.get_session_key()
connection.get_key_exchange_method()
```

------------------------------------------------------------------------

## 5.3 ArkTPStream

Stream 是在同一个 ArkTPConnection 内建立的逻辑数据流。

``` rust
let stream = connection.open_stream(1).await?;

stream.send(b"hello").await?;

let data = stream.recv().await?;

stream.shutdown().await?;
```

Stream 适合：

-   文件传输；
-   RPC；
-   控制通道；
-   日志通道；
-   多个独立业务流；
-   在一个连接上承载多个逻辑会话。

一个连接可以拥有多个 Stream：

``` text
ArkTPConnection
│
├── Stream 1: RPC
├── Stream 2: File
├── Stream 3: Telemetry
└── Stream 4: Control
```

------------------------------------------------------------------------

# 6. 普通数据收发

## 6.1 send

``` rust
let n = connection.send(b"hello").await?;
println!("sent {n} bytes");
```

返回值是实际接受进入发送流程的数据字节数。

------------------------------------------------------------------------

## 6.2 recv

``` rust
let data = connection.recv().await?;

println!("received {} bytes", data.len());
```

返回类型是：

``` rust
bytes::Bytes
```

因此非常适合 Tokio 异步程序和零拷贝友好的数据处理流程。

------------------------------------------------------------------------

## 6.3 send_all

如果数据可能大于单个数据包能够承载的有效负载，推荐：

``` rust
connection.send_all(&large_data).await?;
```

例如：

``` rust
let data = vec![0u8; 1024 * 1024];

connection.send_all(&data).await?;
```

不要假设一次 `send()` 可以发送任意大小的数据。

------------------------------------------------------------------------

## 6.4 recv_exact

当应用知道需要读取固定长度的数据时：

``` rust
let header = connection.recv_exact(32).await?;
```

这适合固定长度的业务协议头。

------------------------------------------------------------------------

## 6.5 批量发送

ArkTP 支持：

``` rust
let packets = vec![
    Bytes::from_static(b"one"),
    Bytes::from_static(b"two"),
    Bytes::from_static(b"three"),
];

let seqs = connection.send_batch(&packets).await?;
```

返回：

``` rust
Vec<SeqNum>
```

用于需要跟踪发送序列的应用。

项目默认的单次批量上限由：

``` rust
max_batch_packets
```

控制，默认值为 64。

------------------------------------------------------------------------

# 7. 使用 Tokio AsyncRead / AsyncWrite

`ArkTPConnection::split()` 可以得到：

``` rust
let (mut send, mut recv) = connection.split()?;
```

其中：

-   `SendHalf` 实现 `AsyncWrite`；
-   `RecvHalf` 实现 `AsyncRead`。

因此可以和 Tokio 生态中的代码结合。

示例：

``` rust
use tokio::io::{AsyncReadExt, AsyncWriteExt};

let (mut tx, mut rx) = connection.split()?;

tx.write_all(b"hello").await?;

let mut buf = vec![0u8; 1024];
let n = rx.read(&mut buf).await?;

println!("received {n} bytes");
```

这对以下场景尤其方便：

-   文件；
-   编解码器；
-   自定义协议；
-   Tokio IO pipeline；
-   与已有 `AsyncRead` / `AsyncWrite` 代码集成。

------------------------------------------------------------------------

# 8. 多路复用 Stream

## 8.1 主动打开 Stream

一方可以主动：

``` rust
let stream = connection.open_stream(100).await?;
```

Stream ID 是：

``` rust
u64
```

应用可以自己规划 ID，例如：

``` text
1   控制流
2   RPC
100 文件流
200 日志流
```

建议在应用层定义明确的 Stream ID 分配规则。

------------------------------------------------------------------------

## 8.2 被动接受 Stream

另一方：

``` rust
let stream = connection.accept_stream().await?;
```

然后：

``` rust
let data = stream.recv().await?;
```

------------------------------------------------------------------------

## 8.3 Stream 发送

``` rust
stream.send(b"hello").await?;
```

如果需要自动分片：

``` rust
stream.send_all(&large_data).await?;
```

Stream 自己维护发送 offset，并结合连接级流量控制和 Stream 级流量控制。

------------------------------------------------------------------------

## 8.4 Stream 关闭

``` rust
stream.shutdown().await?;
```

这会发送 FIN 语义的 Stream frame。

------------------------------------------------------------------------

# 9. 配置系统

ArkTP 的核心配置结构：

``` rust
ArkTPConfig
```

获取默认配置：

``` rust
let config = ArkTPConfig::default();
```

推荐不要从零构造配置，而是在默认配置上修改：

``` rust
let mut config = ArkTPConfig::default();

config.mtu = 1400;
config.max_retries = 10;
config.enable_ecn = true;
```

然后：

``` rust
config.validate()?;
```

------------------------------------------------------------------------

# 10. ArkTPConfig 完整配置说明

## 10.1 MTU

``` rust
config.mtu = 1420;
```

默认：

``` text
1420
```

代码要求 MTU 至少为：

``` text
576
```

如果配置过小：

``` text
ArkTPError::InvalidConfig
```

------------------------------------------------------------------------

## 10.2 重试次数

``` rust
config.max_retries = 12;
```

控制可靠传输中的最大重试次数。

对于互联网长距离网络，可以根据网络质量调整。

------------------------------------------------------------------------

## 10.3 发送/接收缓冲区

``` rust
config.send_buffer_size = 4096;
config.receive_buffer_size = 4096;
```

这是 ArkTP 用户态缓冲相关配置。

另外还有 UDP socket 缓冲：

``` rust
config.udp_send_buffer_size = 4 * 1024 * 1024;
config.udp_receive_buffer_size = 4 * 1024 * 1024;
```

高带宽、高 RTT 场景尤其需要关注 UDP socket buffer。

------------------------------------------------------------------------

# 11. 流量控制

ArkTP 同时具有：

``` rust
initial_max_data
initial_max_stream_data
max_streams
```

例如：

``` rust
config.initial_max_data = 64 * 1024 * 1024;
config.initial_max_stream_data = 16 * 1024 * 1024;
config.max_streams = 1024;
```

含义：

  配置                        作用
  --------------------------- ------------------------
  `initial_max_data`          初始连接级数据窗口
  `initial_max_stream_data`   初始 Stream 级数据窗口
  `max_streams`               最大 Stream 数量

如果出现：

``` text
FlowControlBlocked
```

通常需要检查：

-   接收端是否及时消费数据；
-   `initial_max_data` 是否过小；
-   `initial_max_stream_data` 是否过小；
-   应用是否读取了 `recv()`；
-   是否产生了发送端背压。

------------------------------------------------------------------------

# 12. 拥塞控制

支持：

``` rust
CongestionAlgorithm::Reno
CongestionAlgorithm::Bbr
```

默认：

``` rust
CongestionAlgorithm::Bbr
```

例如切换 Reno：

``` rust
config.congestion_control = CongestionAlgorithm::Reno;
```

通常建议：

-   普通互联网：优先默认 BBR；
-   需要更传统的 TCP Reno 风格行为：使用 Reno；
-   不要在没有实际网络测试的情况下频繁切换拥塞算法。

ArkTP 还暴露：

``` rust
CongestionControl
```

trait，因此可以实现自己的拥塞控制插件。

插件需要实现：

``` rust
on_packet_sent
on_ack
on_loss
on_timeout
on_duplicate_ack
cwnd
ssthresh
can_send
pacing_rate
rto
clone_box
```

然后通过：

``` rust
config.congestion_plugin = Some(...);
```

注入。

------------------------------------------------------------------------

# 13. FEC 前向纠错

ArkTP 支持 FEC。

默认：

``` rust
fec_enabled = true
```

默认组大小：

``` text
8
```

配置：

``` rust
config.fec_enabled = true;
config.fec_group_size = 8;
```

FEC 适合：

-   有明显随机丢包的网络；
-   实时数据；
-   高 RTT 网络；
-   不希望所有丢包都依赖重传的场景。

但 FEC 会增加：

-   CPU；
-   带宽；
-   编码/解码延迟。

因此在极低丢包率环境下，不一定需要激进 FEC。

------------------------------------------------------------------------

# 14. Smart Adaptive FEC

项目提供：

``` rust
SmartAdaptiveFec
```

它根据历史丢包率在以下模式之间切换：

``` text
Disabled
Xor
ReedSolomon
Hybrid
```

源码中的默认策略大致为：

``` text
平均丢包率 < 1%
    -> XOR

1% ~ 5%
    -> Reed-Solomon

>= 5%
    -> Hybrid
```

因此应用通常不需要手工决定每一个数据包使用哪种 FEC。

如果实现自己的 FEC 策略，可以使用：

``` rust
FecPlugin
```

------------------------------------------------------------------------

# 15. 加密

ArkTP 默认：

``` rust
enable_encryption = true
```

默认密钥交换方式：

``` rust
HybridX25519Kyber
```

默认还启用：

``` rust
enable_post_quantum = true
```

底层数据加密使用：

``` text
ChaCha20-Poly1305
```

密钥长度：

``` text
32 bytes
```

------------------------------------------------------------------------

# 16. EncryptionKey

生成随机密钥：

``` rust
let key = EncryptionKey::generate();
```

从 32 字节读取：

``` rust
let key = EncryptionKey::from_bytes(&bytes)?;
```

从密码派生：

``` rust
let key = EncryptionKey::from_password(
    "your-password",
    salt,
)?;
```

源码使用 Argon2 进行密码派生。

读取原始密钥：

``` rust
let bytes = key.as_bytes();
```

应用层应避免把密钥打印到日志。

------------------------------------------------------------------------

# 17. 使用预共享密钥

如果客户端和服务端已经拥有同一密钥，可以配置：

``` rust
let key = EncryptionKey::generate();

let mut config = ArkTPConfig::default();

config.encryption_key = Some(key);
config.authentication = AuthenticationConfig::PreSharedKey;
config.key_exchange_method = KeyExchangeMethod::PreSharedKey;
```

注意：

``` text
PreSharedKey authentication
```

要求：

``` rust
encryption_key.is_some()
```

否则：

``` text
ArkTPError::InvalidConfig
```

------------------------------------------------------------------------

# 18. 认证方式

ArkTP 提供：

``` rust
AuthenticationConfig
```

包括：

``` rust
AuthenticationConfig::None
AuthenticationConfig::PreSharedKey
AuthenticationConfig::PinnedPublicKey { fingerprint }
AuthenticationConfig::Tofu
```

## None

``` rust
AuthenticationConfig::None
```

适合开发和不需要应用身份认证的场景。

------------------------------------------------------------------------

## PreSharedKey

双方共享密钥：

``` rust
AuthenticationConfig::PreSharedKey
```

适合：

-   私有集群；
-   内网服务；
-   已有密钥管理系统的环境。

------------------------------------------------------------------------

## PinnedPublicKey

固定对端公钥指纹：

``` rust
AuthenticationConfig::PinnedPublicKey {
    fingerprint: expected_fingerprint,
}
```

适合：

-   固定服务器身份；
-   客户端内置服务端身份；
-   不希望依赖动态信任建立。

------------------------------------------------------------------------

## TOFU

TOFU：

``` text
Trust On First Use
```

配置：

``` rust
config.authentication = AuthenticationConfig::Tofu;
```

第一次看到对端指纹后记录，之后要求一致。

适合内部工具和没有传统证书体系的部署，但应用必须认真考虑首次连接时的信任建立问题。

------------------------------------------------------------------------

# 19. 密钥交换方式

支持：

``` rust
KeyExchangeMethod::X25519
KeyExchangeMethod::X25519WithArgon2
KeyExchangeMethod::PreSharedKey
KeyExchangeMethod::AutoGenerated
KeyExchangeMethod::PostQuantumKyber
KeyExchangeMethod::HybridX25519Kyber
```

推荐普通应用保留默认：

``` rust
KeyExchangeMethod::HybridX25519Kyber
```

如果关闭：

``` rust
config.enable_post_quantum = false;
```

则不能继续选择：

``` text
PostQuantumKyber
HybridX25519Kyber
```

否则配置校验失败。

------------------------------------------------------------------------

# 20. 后量子密码能力

项目提供：

``` rust
PostQuantumCrypto
```

包括：

-   Kyber 密钥封装；
-   Dilithium 签名；
-   公钥获取；
-   签名验证。

示例：

``` rust
let pq = PostQuantumCrypto::new()?;

let (ciphertext, shared_secret) = pq.encapsulate()?;

let recovered = pq.decapsulate(&ciphertext)?;

assert_eq!(shared_secret, recovered);
```

签名：

``` rust
let signature = pq.sign(message)?;

let valid = pq.verify(message, &signature)?;
```

验证外部公钥：

``` rust
let valid = PostQuantumCrypto::verify_with_public(
    message,
    &signature,
    public_key,
)?;
```

如果业务只是使用 ArkTP
连接，不建议直接操作这一层；优先让连接层负责密钥协商。

------------------------------------------------------------------------

# 21. 自动生成密钥

默认：

``` rust
auto_generate_key = true
```

如果启用了加密但没有提供：

``` rust
encryption_key
```

ArkTP 可以自动生成密钥并进行连接级密钥协商。

普通应用通常可以直接：

``` rust
ArkTPConfig::default()
```

无需自己管理第一把会话密钥。

------------------------------------------------------------------------

# 22. 密钥更新

长时间运行的连接可以主动：

``` rust
connection.key_update().await?;
```

或者：

``` rust
socket.key_update().await?;
```

项目内部也会根据加密 nonce 使用情况判断是否需要密钥更新。

对于：

-   长连接；
-   大规模持续数据流；
-   长时间运行的服务；

建议将密钥更新纳入运维策略。

------------------------------------------------------------------------

# 23. 会话恢复

ArkTP 支持：

``` rust
SessionTicket
```

建立连接后可以：

``` rust
let ticket = connection.export_session_ticket(
    std::time::Duration::from_secs(3600)
)?;
```

然后应用负责安全保存 ticket。

下一次可以：

``` rust
socket.connect_with_ticket(
    "server:9000",
    &ticket,
).await?;
```

启用会话恢复：

``` rust
config.enable_session_resumption = true;
```

默认已启用。

------------------------------------------------------------------------

# 24. 0-RTT

0-RTT 需要：

``` rust
config.enable_0rtt = true;
```

然后：

``` rust
socket.connect_0rtt(
    "server:9000",
    &ticket,
).await?;
```

也可以发送早期数据：

``` rust
socket.connect_0rtt_with_data(
    "server:9000",
    &ticket,
    b"early-data",
).await?;
```

## 重要：0-RTT 数据不要默认视为"不可重放"

0-RTT 的本质是减少握手等待，因此业务数据可能在连接完全建立之前被处理。

建议：

-   不要把不可重复执行的操作直接放进 0-RTT；
-   不要用 0-RTT 承载资金转账、删除资源、修改关键状态等不可幂等操作；
-   优先发送幂等请求；
-   服务端必须对 0-RTT 数据的业务语义做额外限制。

如果业务无法接受早期数据风险，关闭：

``` rust
config.enable_0rtt = false;
```

------------------------------------------------------------------------

# 25. 多路径

默认：

``` rust
enable_multipath = true
```

最大路径数默认：

``` text
4
```

上限：

``` text
16
```

可以通过：

``` rust
config.max_paths = 4;
```

调整。

连接建立后可以添加 UDP socket：

``` rust
let path_id = connection.add_path(
    socket,
    remote_addr,
).await?;
```

然后查看：

``` rust
let count = connection.path_count().await;

let stats = connection.path_stats().await;
```

路径统计包括：

``` text
path_id
quality
RTT
loss
```

------------------------------------------------------------------------

# 26. PathScheduler

ArkTP 提供：

``` rust
PathScheduler
```

用于选择路径。

可以使用：

``` rust
MultiPathManager
```

管理：

-   path；
-   路径质量；
-   RTT；
-   loss；
-   最优路径；
-   多路径调度。

还可以通过：

``` rust
PathSchedulerPlugin
```

实现自己的路径选择算法。

适合：

-   Wi-Fi + Ethernet；
-   多网卡服务器；
-   蜂窝网络 + Wi-Fi；
-   多出口服务器；
-   多链路传输。

------------------------------------------------------------------------

# 27. 连接迁移

如果远端地址变化，可以：

``` rust
connection.migrate(new_addr).await?;
```

配置：

``` rust
config.enable_connection_migration = true;
```

迁移能力适合：

-   移动客户端；
-   NAT 映射变化；
-   网络切换；
-   IP 变化；
-   多网络接口。

不要把 `migrate()`
当作普通的"修改目标地址"函数；它属于连接迁移流程，应保证新地址确实属于当前连接对应的对端。

------------------------------------------------------------------------

# 28. NAT Traversal

配置：

``` rust
config.enable_nat_traversal = true;
```

连接可以获得：

``` rust
connection.get_nat_traversal()
```

项目提供：

``` rust
NatTraversal
NatType
StunClient
```

可以用于：

-   查询公网地址；
-   判断 NAT 类型；
-   NAT probe；
-   NAT refresh。

例如获取 NAT helper：

``` rust
if let Some(nat) = connection.get_nat_traversal() {
    println!("NAT type: {:?}", nat.get_nat_type());
}
```

NAT 穿透并不意味着所有网络环境都可以直接建立点对点连接。对称
NAT、防火墙策略、运营商网络等仍可能限制连通性。

------------------------------------------------------------------------

# 29. 连接聚合

ArkTP 支持多个独立连接组合成一个逻辑发送/接收入口。

开启：

``` rust
config.enable_connection_aggregation = true;
```

然后：

``` rust
socket.connect_aggregated(&[
    "10.0.0.1:9000".to_string(),
    "10.0.0.2:9000".to_string(),
]).await?;
```

之后仍然可以：

``` rust
socket.send(data).await?;
let data = socket.recv().await?;
```

ArkTP 内部会根据连接健康状态进行调度。

可以查询：

``` rust
socket.get_aggregator()
```

以及：

``` rust
aggregator.connection_count()
aggregator.get_health_scores()
```

------------------------------------------------------------------------

# 30. 连接聚合和多路径有什么区别

两者不要混淆。

## 多路径

一个 ArkTPConnection：

``` text
Connection
 ├── Path A
 ├── Path B
 └── Path C
```

属于**一个逻辑连接的多个网络路径**。

## Connection Aggregation

多个独立 Connection：

``` text
Connection 1 ─┐
Connection 2 ─┼── Aggregator
Connection 3 ─┘
```

适合：

-   多服务器地址；
-   多个独立连接；
-   failover；
-   多入口架构。

------------------------------------------------------------------------

# 31. PMTU 探测

可以主动探测 MTU：

``` rust
let supported = connection.probe_mtu(1400).await?;

if supported {
    println!("MTU candidate is reachable");
}
```

启用：

``` rust
config.enable_pmtud = true;
```

ArkTP 的 MTU 最小值为：

``` text
576
```

实际部署中建议根据网络环境选择合理 MTU，不要盲目追求最大值。

------------------------------------------------------------------------

# 32. ECN

项目支持 ECN 相关配置：

``` rust
config.enable_ecn = true;
```

统计中可以读取：

``` text
ecn_ce
ecn_ect0
ecn_ect1
```

ECN 更适合由网络工程和传输层优化人员使用。

如果不确定网络设备是否正确支持 ECN，建议先保持默认：

``` rust
enable_ecn = false
```

------------------------------------------------------------------------

# 33. HEDT：大包加密卸载

ArkTP 提供 HEDT：

``` text
High-Efficiency Data Transmission
```

相关配置：

``` rust
config.hedt_enabled = true;
config.hedt_threshold = 1380;
config.hedt_max_inflight = 4;
```

它主要用于避免大包加密任务阻塞小包发送路径。

适合：

-   高吞吐；
-   大文件；
-   大消息；
-   CPU 加密成本较高的场景。

通常保持默认即可。

------------------------------------------------------------------------

# 34. 并行处理 Pipeline

默认：

``` rust
enable_parallel_pipeline = true
```

ArkTP 内部提供：

``` rust
ParallelPipeline
```

用于批量：

-   加密；
-   解密；
-   FEC；
-   路径选择。

一般应用无需直接操作。

如果是高性能网关、代理或专用传输服务，可以通过：

``` rust
connection.get_parallel_pipeline()
```

访问。

------------------------------------------------------------------------

# 35. SmartCache

默认：

``` rust
enable_smart_cache = true
```

项目提供：

``` rust
SmartCache
CacheStats
```

用于缓存：

-   encryption context；
-   path；
-   FEC；
-   route。

获取：

``` rust
let cache = connection.get_smart_cache();

let stats = cache.stats();
```

通常建议保持默认。

------------------------------------------------------------------------

# 36. 运行时配置热更新

ArkTP 支持：

``` rust
socket.reload_config(config)?;
```

例如：

``` rust
let mut config = socket.config();

config.mtu = 1400;
config.enable_ecn = true;

socket.reload_config(config)?;
```

内部使用：

``` rust
ArkTPConfigHandle
```

进行线程安全的配置快照管理。

注意：

-   新连接使用最新配置；
-   当前连接会更新支持运行时修改的配置；
-   并不是所有初始化期参数都能在连接建立后无条件改变。

当前源码明确更新的连接级运行时参数包括：

``` text
recv_timeout
idle_timeout
keep_alive_interval
mtu
```

因此，如果修改的是：

-   密钥交换方式；
-   身份认证方式；
-   socket 创建属性；
-   某些初始化阶段的算法；

建议关闭旧连接并创建新连接，而不是依赖热更新。

------------------------------------------------------------------------

# 37. 超时

默认：

``` rust
recv_timeout = Some(Duration::from_secs(30))
```

即：

``` rust
connection.recv().await
```

不是无限等待。

可以设置：

``` rust
config.recv_timeout = Some(
    std::time::Duration::from_secs(10)
);
```

永久等待：

``` rust
config.recv_timeout = None;
```

握手超时默认：

``` text
5 秒
```

可以：

``` rust
config.handshake_timeout =
    std::time::Duration::from_secs(10);
```

------------------------------------------------------------------------

# 38. Idle Timeout

默认：

``` rust
idle_timeout = Some(Duration::from_secs(120))
```

如果不希望连接因为空闲而过期：

``` rust
config.idle_timeout = None;
```

长连接服务如果需要持续保持连接，可以结合：

``` rust
keep_alive_interval
```

------------------------------------------------------------------------

# 39. Keep Alive

默认：

``` rust
keep_alive_interval =
    Some(Duration::from_secs(20))
```

可以修改：

``` rust
config.keep_alive_interval =
    Some(Duration::from_secs(15));
```

如果完全不需要：

``` rust
config.keep_alive_interval = None;
```

------------------------------------------------------------------------

# 40. 最大重组内存

配置：

``` rust
config.max_reassembly_bytes =
    64 * 1024 * 1024;
```

这是每个连接的用户态接收重组状态上限。

在高并发服务器上，这个值非常重要。

例如：

``` text
1000 connections
× 64 MiB
= 理论上非常大的潜在内存压力
```

因此高并发部署时需要结合：

-   最大连接数；
-   最大并发 Stream；
-   接收窗口；
-   应用消费速度；

一起评估。

------------------------------------------------------------------------

# 41. 服务端连接并发控制

服务端：

``` rust
max_pending_connections
```

默认：

``` text
5000
```

用于限制正在进行中的入站握手数量。

可以：

``` rust
config.max_pending_connections = 2000;
```

如果服务器遭遇大量连接建立请求，可以降低这个值，减少握手状态占用。

如果达到上限，可能出现：

``` text
PendingConnectionsFull
```

------------------------------------------------------------------------

# 42. 统计信息

ArkTP 提供：

``` rust
ArkTPStats
```

获取：

``` rust
let stats = connection.stats();
```

其中包含大量原子计数器，包括：

-   `packets_sent`
-   `packets_received`
-   `packets_retransmitted`
-   `packets_lost`
-   `bytes_sent`
-   `bytes_received`
-   `rtt_avg`
-   `rtt_min`
-   `rtt_max`
-   `cwnd`
-   `loss_rate`
-   `fec_recovered`
-   `active_paths`
-   `total_bandwidth`
-   `encrypted_packets`
-   `decrypted_packets`
-   `failed_decryptions`
-   `queue_length`
-   `in_flight`
-   `key_exchanges_completed`
-   `key_exchanges_failed`
-   `cache_hits`
-   `cache_misses`
-   `parallel_operations`
-   `nat_traversals`
-   `aggregated_connections`
-   `ecn_ce`
-   `ecn_ect0`
-   `ecn_ect1`
-   HEDT 相关统计。

例如：

``` rust
let sent = stats.packets_sent.load(
    std::sync::atomic::Ordering::Relaxed
);
```

------------------------------------------------------------------------

# 43. Prometheus 指标

可以直接：

``` rust
let text = stats.prometheus();
```

得到 Prometheus text exposition 格式。

例如：

``` rust
println!("{}", stats.prometheus());
```

当前导出的指标包括：

``` text
arktp_packets_sent
arktp_packets_received
arktp_bytes_sent
arktp_bytes_received
arktp_rtt_ms
arktp_rtt_min_ms
arktp_rtt_max_ms
arktp_cwnd
arktp_ecn_ce
arktp_hedt_small_fast_path
arktp_hedt_large_offloaded
arktp_hedt_large_completed
arktp_hedt_large_fallback_inline
```

可以在 HTTP `/metrics` Endpoint 中直接返回这段文本，然后让 Prometheus
抓取。

------------------------------------------------------------------------

# 44. 一个简单的 metrics HTTP 服务

如果业务已经使用 Tokio，可以将：

``` rust
stats.prometheus()
```

挂到现有 HTTP 服务。

伪代码：

``` rust
async fn metrics_handler(stats: Arc<ArkTPStats>) -> String {
    stats.prometheus()
}
```

推荐：

``` text
GET /metrics
```

只返回：

``` text
stats.prometheus()
```

不要把：

-   session key；
-   EncryptionKey；
-   peer fingerprint；
-   ticket token；

暴露到 Prometheus。

------------------------------------------------------------------------

# 45. 错误处理

所有主要 API 使用：

``` rust
Result<T, ArkTPError>
```

建议业务代码始终匹配错误类型，而不是只打印字符串。

例如：

``` rust
match connection.recv().await {
    Ok(data) => {
        // process
    }

    Err(ArkTPError::Timeout) => {
        // timeout
    }

    Err(ArkTPError::ConnectionClosed) => {
        // connection ended
    }

    Err(e) => {
        eprintln!("ArkTP error: {e}");
    }
}
```

------------------------------------------------------------------------

# 46. 常见错误

## Timeout

``` text
ArkTPError::Timeout
```

可能原因：

-   网络不可达；
-   对端没有响应；
-   防火墙；
-   UDP 丢包严重；
-   handshake timeout 太短；
-   recv timeout 太短。

------------------------------------------------------------------------

## ConnectionClosed

``` text
ArkTPError::ConnectionClosed
```

说明连接已经结束或不可用。

通常应该：

``` text
停止当前发送/接收循环
→ 清理业务资源
→ 根据业务决定是否重新连接
```

------------------------------------------------------------------------

## SendQueueFull

``` text
ArkTPError::SendQueueFull
```

说明应用生产数据速度高于传输层发送速度。

不要简单地无限增加发送速度。

正确方式：

-   等待；
-   使用 `send_async()`；
-   使用 Tokio backpressure；
-   控制生产者速率；
-   检查网络带宽。

------------------------------------------------------------------------

## PacketTooLarge

``` text
ArkTPError::PacketTooLarge
```

普通 `send()` 或 Stream `send()` 超过当前包能够承载的最大数据。

对于大数据使用：

``` rust
send_all()
```

而不是手动猜测分片大小。

------------------------------------------------------------------------

## FlowControlBlocked

说明远端流量控制窗口不足。

优先检查：

``` text
initial_max_data
initial_max_stream_data
```

以及接收端是否及时读取数据。

------------------------------------------------------------------------

## AuthenticationFailed

认证失败。

检查：

-   PSK 是否一致；
-   fingerprint 是否正确；
-   TOFU 状态；
-   对端身份是否发生变化。

------------------------------------------------------------------------

## KeyAgreementTimeout

密钥协商超时。

检查：

-   UDP 是否可达；
-   防火墙；
-   MTU；
-   握手超时；
-   两端协议版本；
-   加密配置。

------------------------------------------------------------------------

## SessionResumptionFailed

会话恢复失败。

常见原因：

-   ticket 已过期；
-   ticket 已经被消费；
-   ticket 数据损坏；
-   两端状态已经不存在；
-   `enable_session_resumption` 未启用。

------------------------------------------------------------------------

# 47. 建议的服务器结构

生产服务器建议采用：

``` text
main
 │
 ├── load config
 │
 ├── bind ArkTPReliableServer
 │
 ├── metrics task
 │
 └── accept loop
       │
       ├── connection task
       │      ├── recv
       │      ├── protocol decode
       │      └── send
       │
       ├── connection task
       └── connection task
```

示例：

``` rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = ArkTPConfig::default();

    config.max_pending_connections = 2000;
    config.max_reassembly_bytes = 32 * 1024 * 1024;

    let server =
        ArkTPReliableServer::bind("0.0.0.0:9000", config).await?;

    loop {
        let connection = server.accept().await?;

        tokio::spawn(async move {
            while let Ok(data) = connection.recv().await {
                if connection.send_all(&data).await.is_err() {
                    break;
                }
            }
        });
    }
}
```

------------------------------------------------------------------------

# 48. 建议的客户端结构

``` text
client
 │
 ├── create ArkTPReliableClient
 │
 ├── connect
 │
 ├── create streams
 │
 ├── send requests
 │
 ├── receive responses
 │
 └── close
```

示例：

``` rust
let client =
    ArkTPReliableClient::new(ArkTPConfig::default())?;

let connection =
    client.connect("server.example:9000").await?;

let control = connection.open_stream(1).await?;

control.send(b"request").await?;

let response = control.recv().await?;

connection.close().await?;
```

------------------------------------------------------------------------

# 49. RPC 场景推荐设计

如果 ArkTP 用来做 RPC，建议：

``` text
Stream 1: request
Stream 2: response
```

或者：

``` text
每个 RPC 一个 Stream
```

业务协议可以自己定义：

``` text
[length][request_id][method][payload]
```

ArkTP 负责：

-   可靠传输；
-   顺序；
-   重传；
-   加密；
-   流量控制。

业务层负责：

-   RPC ID；
-   方法；
-   参数；
-   返回值；
-   错误码。

不要把业务语义塞进 ArkTP wire protocol。

------------------------------------------------------------------------

# 50. 文件传输场景推荐设计

对于大文件：

``` rust
let stream = connection.open_stream(file_id).await?;

stream.send_all(&file_data).await?;

stream.shutdown().await?;
```

生产环境不要一次性把整个文件加载进内存。

建议：

``` text
File
 ↓
chunk
 ↓
ArkTPStream.send()
 ↓
network
```

例如：

``` rust
use tokio::io::AsyncReadExt;

let mut file = tokio::fs::File::open("large.bin").await?;
let stream = connection.open_stream(10).await?;

let mut buf = vec![0u8; 64 * 1024];

loop {
    let n = file.read(&mut buf).await?;

    if n == 0 {
        break;
    }

    stream.send_all(&buf[..n]).await?;
}

stream.shutdown().await?;
```

这样可以控制内存占用。

------------------------------------------------------------------------

# 51. 日志与可观测性

项目依赖：

``` text
tracing
tracing-subscriber
log
env_logger
```

应用可以配置自己的 tracing subscriber。

例如：

``` rust
tracing_subscriber::fmt::init();
```

然后运行：

``` bash
RUST_LOG=info cargo run
```

在生产环境建议：

-   INFO：连接建立、关闭、重要状态；
-   WARN：网络异常、重传异常；
-   ERROR：协议或安全失败；
-   DEBUG/TRACE：仅在排障时打开。

不要记录：

``` text
EncryptionKey
session ticket
PSK
私密 payload
```

------------------------------------------------------------------------

# 52. 配置序列化

`ArkTPConfig` 实现：

``` rust
Serialize
Deserialize
```

因此可以使用 JSON：

``` rust
let json = serde_json::to_string_pretty(&config)?;
```

再恢复：

``` rust
let config: ArkTPConfig =
    serde_json::from_str(&json)?;
```

注意：

-   `stats` 不参与序列化；
-   runtime plugin 字段不参与序列化；
-   `Duration` 使用毫秒表示。

例如：

``` json
{
  "mtu": 1420,
  "max_retries": 12,
  "recv_timeout": 30000,
  "handshake_timeout": 5000
}
```

`recv_timeout` 的单位是毫秒。

------------------------------------------------------------------------

# 53. 推荐生产配置

一个偏向稳定生产环境的例子：

``` rust
let mut config = ArkTPConfig::default();

config.mtu = 1420;

config.enable_encryption = true;
config.enable_post_quantum = true;

config.enable_multipath = true;
config.max_paths = 4;

config.enable_pmtud = true;
config.enable_pacing = true;
config.enable_ecn = false;

config.fec_enabled = true;
config.enable_smart_fec = true;

config.enable_parallel_pipeline = true;
config.enable_smart_cache = true;
config.hedt_enabled = true;

config.recv_timeout =
    Some(std::time::Duration::from_secs(30));

config.idle_timeout =
    Some(std::time::Duration::from_secs(120));

config.keep_alive_interval =
    Some(std::time::Duration::from_secs(20));

config.max_pending_connections = 2000;

config.validate()?;
```

注意：真正的生产参数应通过真实网络测试确定，而不是直接照搬。

------------------------------------------------------------------------

# 54. 高吞吐场景调优思路

如果目标是高吞吐：

## 第一层：UDP buffer

首先考虑：

``` rust
udp_send_buffer_size
udp_receive_buffer_size
```

例如：

``` rust
config.udp_send_buffer_size = 16 * 1024 * 1024;
config.udp_receive_buffer_size = 16 * 1024 * 1024;
```

同时确保操作系统允许设置到这个大小。

------------------------------------------------------------------------

## 第二层：拥塞控制

默认：

``` text
BBR
```

先保持默认，再通过统计观察：

``` text
RTT
cwnd
loss
in_flight
bandwidth
```

------------------------------------------------------------------------

## 第三层：FEC

丢包严重时可以保留 Smart FEC。

不要在低丢包网络上无条件增加大量冗余。

------------------------------------------------------------------------

## 第四层：HEDT / Pipeline

保持：

``` text
enable_parallel_pipeline = true
hedt_enabled = true
```

观察 CPU 与吞吐。

------------------------------------------------------------------------

## 第五层：应用层 backpressure

最常见的错误不是 ArkTP 本身，而是：

``` text
生产速度 >> 网络发送速度
```

必须让应用尊重：

``` text
SendQueueFull
FlowControlBlocked
```

------------------------------------------------------------------------

# 55. 低延迟场景调优思路

低延迟应用建议：

``` text
适当 MTU
+
较小批量
+
pacing
+
合理拥塞控制
+
不过度 FEC
+
合理 keep-alive
```

不要简单把所有 buffer 调到最大。

如果是：

-   实时控制；
-   游戏；
-   交互式 RPC；

优先观察：

``` text
rtt_avg
rtt_min
rtt_max
packets_lost
retransmissions
cwnd
```

------------------------------------------------------------------------

# 56. 高丢包网络调优思路

建议：

``` rust
config.fec_enabled = true;
config.enable_smart_fec = true;
```

同时保持：

``` rust
config.max_retries
```

合理。

FEC 和重传不是互斥关系：

``` text
FEC：尝试直接恢复
↓
仍无法恢复
↓
可靠重传
```

------------------------------------------------------------------------

# 57. 移动网络调优思路

如果客户端可能切换：

``` text
Wi-Fi
↓
4G/5G
```

建议考虑：

``` rust
enable_connection_migration = true;
enable_multipath = true;
enable_nat_traversal = true;
```

并监控：

``` text
path_count
path_stats
NAT 状态
RTT
loss
```

------------------------------------------------------------------------

# 58. 多线程与并发模型

ArkTP 基于 Tokio，并使用大量：

-   `Arc`
-   原子变量；
-   `parking_lot::RwLock`;
-   `DashMap`;
-   Tokio Notify；
-   broadcast；
-   flume。

因此适合多任务并发模型。

典型方式：

``` rust
let connection = server.accept().await?;

tokio::spawn(async move {
    // one task per connection
});
```

如果同一连接有多个 Stream，可以：

``` text
Connection
├── task Stream A
├── task Stream B
└── task Stream C
```

应用应自行保证业务状态同步。

------------------------------------------------------------------------

# 59. 不建议的使用方式

## 不要把 UDP socket 当 TCP 用

ArkTP 已经提供可靠连接。

不要同时自己再实现：

``` text
ACK
重传
排序
```

否则容易形成两套可靠层。

------------------------------------------------------------------------

## 不要直接依赖内部模块

例如：

``` text
transport::sender
transport::receiver
PacketBus
```

除非你正在开发 ArkTP 本身或需要做深度扩展。

业务程序优先：

``` text
ArkTPSocket
ArkTPConnection
ArkTPStream
```

------------------------------------------------------------------------

## 不要依赖私有 API

源码中的：

``` rust
pub(crate)
```

接口不是应用稳定 API。

------------------------------------------------------------------------

# 60. Protocol / Wire 层

项目提供：

``` rust
arktp_reliable::protocol
arktp_reliable::wire
```

其中：

``` rust
wire
```

是稳定 wire-format facade：

``` rust
pub use crate::protocol::packet::*;
```

可以使用：

``` rust
PacketHeader
PacketType
SackBlock
StreamFrame
AckInfo
ExtensionFrame
FlowControl
```

这部分适合：

-   协议分析；
-   packet capture；
-   调试工具；
-   自定义扩展；
-   兼容性实现。

普通业务开发通常不需要直接使用。

------------------------------------------------------------------------

# 61. PacketHeader

当前协议：

``` text
VERSION = 2
SIZE = 26 bytes
```

应用一般不应该手工构造 PacketHeader。

如果确实开发底层工具，可以：

``` rust
let header =
    PacketHeader::new(
        PacketType::Data,
        seq,
        conn_id,
    );

let encoded = header.encode();
```

------------------------------------------------------------------------

# 62. SeqNum

ArkTP 提供：

``` rust
SeqNum
```

用于处理 32 位序列号。

支持：

``` rust
SeqNum::new(value)
seq.next()
seq.add(n)
seq.sub(n)
seq.is_before(other)
seq.is_after(other)
seq.diff(other)
seq.in_window(base, window)
```

应用层通常不需要管理它。

------------------------------------------------------------------------

# 63. SessionTicket 的生命周期

推荐：

``` text
第一次连接
    ↓
正常握手
    ↓
export_session_ticket()
    ↓
安全保存 ticket
    ↓
下一次连接
    ↓
connect_with_ticket / connect_0rtt
```

Ticket 不应该：

-   写入普通日志；
-   发给不可信第三方；
-   放进前端公开数据；
-   长期无期限保存。

------------------------------------------------------------------------

# 64. 安全注意事项

## 64.1 不要关闭加密来"解决网络问题"

如果出现：

``` text
HandshakeFailed
AuthenticationFailed
DecryptionError
```

优先排查：

-   key；
-   auth；
-   MTU；
-   UDP；
-   版本；
-   时间；
-   ticket；
-   防火墙。

不要第一时间设置：

``` rust
enable_encryption = false
```

作为长期方案。

------------------------------------------------------------------------

## 64.2 PSK 要安全保存

不要：

``` rust
println!("{:?}", key);
```

不要把 PSK 提交 Git。

推荐：

``` text
环境变量
密钥管理系统
容器 secret
操作系统 secret store
```

------------------------------------------------------------------------

## 64.3 0-RTT 谨慎使用

只承载：

``` text
幂等请求
缓存读取
重复执行无副作用的操作
```

------------------------------------------------------------------------

## 64.4 TOFU 需要保护首次连接

TOFU 并不是"无需验证"。

它的核心是：

``` text
第一次信任
后续检测变化
```

因此首次连接仍然需要可信渠道。

------------------------------------------------------------------------

# 65. 错误排查流程

当客户端连接失败时，推荐按照以下顺序排查：

``` text
1. IP/端口是否正确
        ↓
2. UDP 是否可以到达
        ↓
3. 防火墙是否允许 UDP
        ↓
4. MTU 是否合理
        ↓
5. handshake_timeout 是否足够
        ↓
6. 两端 ArkTP 版本是否兼容
        ↓
7. encryption 配置是否一致
        ↓
8. PSK / fingerprint 是否一致
        ↓
9. post-quantum 配置是否一致
        ↓
10. 查看 ArkTPStats
```

------------------------------------------------------------------------

# 66. 最小完整 Echo Server

``` rust
use arktp_reliable::{
    ArkTPConfig,
    ArkTPReliableServer,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let config = ArkTPConfig::default();

    let server =
        ArkTPReliableServer::bind("0.0.0.0:9000", config)
            .await?;

    println!("listening on {}", server.local_addr()?);

    loop {
        let connection = server.accept().await?;

        tokio::spawn(async move {
            loop {
                let data = match connection.recv().await {
                    Ok(data) => data,
                    Err(e) => {
                        eprintln!("recv: {e}");
                        break;
                    }
                };

                if let Err(e) = connection.send_all(&data).await {
                    eprintln!("send: {e}");
                    break;
                }
            }
        });
    }
}
```

------------------------------------------------------------------------

# 67. 最小完整 Echo Client

``` rust
use arktp_reliable::{
    ArkTPConfig,
    ArkTPReliableClient,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let client =
        ArkTPReliableClient::new(
            ArkTPConfig::default()
        )?;

    let connection =
        client.connect("127.0.0.1:9000").await?;

    connection.send_all(
        b"hello from client"
    ).await?;

    let response =
        connection.recv().await?;

    println!(
        "{}",
        String::from_utf8_lossy(&response)
    );

    connection.close().await?;

    Ok(())
}
```

------------------------------------------------------------------------

# 68. 一个带安全配置的示例

``` rust
use arktp_reliable::{
    ArkTPConfig,
    AuthenticationConfig,
    EncryptionKey,
    KeyExchangeMethod,
};

fn build_config() -> Result<ArkTPConfig, arktp_reliable::ArkTPError> {
    let key = EncryptionKey::generate();

    let mut config = ArkTPConfig::default();

    config.encryption_key = Some(key);
    config.enable_encryption = true;

    config.authentication =
        AuthenticationConfig::PreSharedKey;

    config.key_exchange_method =
        KeyExchangeMethod::PreSharedKey;

    config.enable_0rtt = false;

    config.validate()?;

    Ok(config)
}
```

这个模式适合已经拥有 PSK 的受控环境。

------------------------------------------------------------------------

# 69. Cargo 构建

开发：

``` bash
cargo build
```

Release：

``` bash
cargo build --release
```

检查：

``` bash
cargo check
```

格式化：

``` bash
cargo fmt
```

Clippy：

``` bash
cargo clippy
```

测试：

``` bash
cargo test
```

如果项目后续加入 benchmark，可以：

``` bash
cargo bench
```

------------------------------------------------------------------------

# 70. Feature

Cargo features：

``` toml
[features]
default = ["reliable"]
reliable = []
diagnostics = []
```

默认启用：

``` text
reliable
```

另外：

``` text
diagnostics
```

用于额外运行时诊断。

使用：

``` bash
cargo build --features diagnostics
```

或者：

``` bash
cargo run --features diagnostics
```

------------------------------------------------------------------------

# 71. 项目源码结构

当前源码主要结构：

``` text
arktp/
├── Cargo.toml
└── src/
    ├── api/
    │   └── mod.rs
    │
    ├── control/
    │   ├── congestion.rs
    │   ├── fec.rs
    │   └── mod.rs
    │
    ├── core/
    │   ├── config.rs
    │   ├── constants.rs
    │   ├── error.rs
    │   ├── seqnum.rs
    │   └── util.rs
    │
    ├── observability/
    │   └── stats.rs
    │
    ├── performance/
    │   ├── aggregation.rs
    │   ├── cache.rs
    │   ├── hedt.rs
    │   └── pipeline.rs
    │
    ├── protocol/
    │   └── packet.rs
    │
    ├── security/
    │   ├── encryption.rs
    │   └── nat.rs
    │
    ├── transport/
    │   ├── connection.rs
    │   ├── path.rs
    │   ├── receiver.rs
    │   ├── sender.rs
    │   └── socket.rs
    │
    ├── wire/
    │   └── mod.rs
    │
    └── lib.rs
```

模块职责：

  模块              主要职责
  ----------------- --------------------------------
  `api`             高层 Client/Server Endpoint
  `core`            配置、错误、常量、序列号
  `transport`       连接、发送、接收、Stream、路径
  `protocol`        协议包与 frame
  `wire`            wire-format 对外 facade
  `security`        加密、密钥交换、NAT
  `control`         拥塞控制、FEC
  `performance`     聚合、缓存、pipeline、HEDT
  `observability`   运行时统计

------------------------------------------------------------------------

# 72. 推荐的开发层次

如果你第一次使用 ArkTP，建议按以下顺序学习：

``` text
第一阶段
ArkTPReliableServer
ArkTPReliableClient
ArkTPConfig

第二阶段
ArkTPConnection
send / recv / send_all

第三阶段
ArkTPStream
split()
AsyncRead / AsyncWrite

第四阶段
ArkTPStats
Prometheus

第五阶段
EncryptionKey
AuthenticationConfig

第六阶段
FEC / congestion / PMTU

第七阶段
multipath / migration / NAT

第八阶段
session ticket / 0-RTT

第九阶段
custom plugin / protocol / wire
```

不要一开始就直接修改：

``` text
sender.rs
receiver.rs
packet.rs
```

除非目标是参与 ArkTP 内核开发。

------------------------------------------------------------------------

# 73. API 速查表

## Endpoint

``` rust
ArkTPSocket::bind()
ArkTPSocket::bind_with_config()
socket.connect()
socket.connect_with_ticket()
socket.connect_0rtt()
socket.connect_0rtt_with_data()
socket.connect_aggregated()
socket.listen()
socket.accept()
socket.send()
socket.send_batch()
socket.recv()
socket.open_stream()
socket.accept_stream()
socket.split()
socket.migrate()
socket.key_update()
socket.probe_mtu()
socket.add_path()
socket.reload_config()
socket.config()
socket.stats()
socket.close()
```

## Connection

``` rust
connection.id()
connection.conn_id()
connection.remote_addr()
connection.send()
connection.send_async()
connection.send_all()
connection.send_batch()
connection.recv()
connection.recv_exact()
connection.open_stream()
connection.accept_stream()
connection.split()
connection.add_path()
connection.migrate()
connection.shutdown_send()
connection.close()
connection.key_update()
connection.export_session_ticket()
connection.get_session_key()
connection.get_key_exchange_method()
connection.state()
connection.path_count()
connection.path_stats()
connection.stats()
```

## Stream

``` rust
stream.id()
stream.send()
stream.send_all()
stream.recv()
stream.shutdown()
```

------------------------------------------------------------------------

# 74. 默认值速查

重要默认值：

  配置                            默认
  --------------------------- --------
  `mtu`                           1420
  `max_retries`                     12
  `send_buffer_size`              4096
  `receive_buffer_size`           4096
  `initial_max_data`            64 MiB
  `initial_max_stream_data`     16 MiB
  `max_streams`                   1024
  congestion                       BBR
  FEC                             开启
  FEC group                          8
  aggressive retransmit           开启
  multipath                       开启
  max paths                          4
  encryption                      开启
  post-quantum                    开启
  NAT traversal                   开启
  parallel pipeline               开启
  smart cache                     开启
  connection aggregation          开启
  smart FEC                       开启
  recv timeout                   30 秒
  handshake timeout               5 秒
  pending connections             5000
  migration                       开启
  session resumption              开启
  0-RTT                           关闭
  PMTUD                           开启
  ECN                             关闭
  UDP send buffer                4 MiB
  UDP receive buffer             4 MiB
  max batch packets                 64
  pacing                          开启
  HEDT                            开启
  HEDT threshold                  1380
  HEDT max inflight                  4
  idle timeout                  120 秒
  keep alive                     20 秒
  max reassembly                64 MiB

------------------------------------------------------------------------

# 75. 生产部署 Checklist

上线前建议逐项检查：

## 网络

-   [ ] UDP 端口已经开放；
-   [ ] 防火墙允许 UDP；
-   [ ] 云厂商安全组允许 UDP；
-   [ ] MTU 已验证；
-   [ ] UDP socket buffer 足够；
-   [ ] NAT 环境已测试。

## 安全

-   [ ] 已启用加密；
-   [ ] PSK 不在源码中；
-   [ ] ticket 不写日志；
-   [ ] 0-RTT 业务已做幂等设计；
-   [ ] TOFU 首次信任渠道可信；
-   [ ] fingerprint 已正确部署。

## 性能

-   [ ] 已选择拥塞算法；
-   [ ] FEC 已根据丢包率评估；
-   [ ] pacing 已评估；
-   [ ] HEDT 已评估；
-   [ ] pipeline 已评估；
-   [ ] max_reassembly_bytes 已根据并发量设置。

## 稳定性

-   [ ] recv timeout 已设置；
-   [ ] idle timeout 已评估；
-   [ ] keep-alive 已评估；
-   [ ] pending connection 上限已设置；
-   [ ] connection close 已正确处理；
-   [ ] reconnect 策略已实现。

## 可观测性

-   [ ] ArkTPStats 已采集；
-   [ ] RTT 已监控；
-   [ ] loss 已监控；
-   [ ] retransmission 已监控；
-   [ ] cwnd 已监控；
-   [ ] queue/in-flight 已监控；
-   [ ] 加密失败已监控；
-   [ ] Prometheus `/metrics` 已接入。

------------------------------------------------------------------------

# 76. Apache License 2.0

本项目按照 **Apache License 2.0** 发布。

建议项目仓库根目录包含：

``` text
LICENSE
```

内容应为 Apache License 2.0 的完整许可证文本。

源代码文件如果需要保留版权声明，可以使用类似：

``` text
Copyright 2026 ArkTP contributors

Licensed under the Apache License, Version 2.0
(the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0
```

Apache 2.0 允许在满足许可证条件的情况下：

-   使用；
-   修改；
-   分发；
-   商业使用；
-   创建衍生作品。

使用 Apache 2.0 时应注意：

-   保留许可证；
-   保留适用的版权声明；
-   保留 NOTICE 文件中的必要声明；
-   对修改进行适当说明；
-   遵守专利条款。

> 本项目压缩包当前源码树中未见独立 `LICENSE`
> 文件；如果该仓库准备正式对外发布，建议在仓库根目录补充 Apache License
> 2.0 正式许可证文本，并根据实际版权归属补充版权声明。

------------------------------------------------------------------------

# 77. 版本兼容与升级建议

应用升级 ArkTP 时，建议同时检查：

``` text
Cargo.toml version
protocol version
configuration changes
authentication behavior
session ticket behavior
```

如果升级后出现：

``` text
VersionMismatch
UnsupportedExtension
HandshakeFailed
```

优先检查两端是否使用兼容版本。

对于跨版本长期运行的客户端/服务端，不建议直接假定所有内部结构都保持兼容。

------------------------------------------------------------------------

# 78. 总结：一个应用到底需要使用多少 ArkTP API？

对于绝大多数应用，只需要：

``` rust
ArkTPConfig
ArkTPReliableServer
ArkTPReliableClient
ArkTPConnection
ArkTPStream
```

最常见服务端：

``` rust
let server =
    ArkTPReliableServer::bind(
        "0.0.0.0:9000",
        ArkTPConfig::default(),
    ).await?;

let conn = server.accept().await?;

let data = conn.recv().await?;
conn.send_all(&data).await?;
```

最常见客户端：

``` rust
let client =
    ArkTPReliableClient::new(
        ArkTPConfig::default()
    )?;

let conn =
    client.connect("server:9000").await?;

conn.send_all(b"hello").await?;

let data = conn.recv().await?;
```

需要业务多路复用：

``` rust
let stream =
    conn.open_stream(1).await?;
```

需要监控：

``` rust
let stats = conn.stats();
let metrics = stats.prometheus();
```

需要安全策略：

``` rust
EncryptionKey
AuthenticationConfig
KeyExchangeMethod
```

需要极致性能：

``` text
FEC
BBR
Pacing
HEDT
ParallelPipeline
SmartCache
Multipath
Aggregation
```

需要移动/复杂网络：

``` text
NAT Traversal
Connection Migration
PMTUD
Multipath
```

需要快速恢复：

``` text
SessionTicket
0-RTT
```

------------------------------------------------------------------------

# 79. 最后建议

如果你是第一次把 ArkTP Reliable
集成到产品中，推荐不要一次打开所有高级功能进行调参。

推荐路线：

``` text
Step 1
ArkTPConfig::default()

Step 2
完成 Client / Server 通信

Step 3
加入业务 Stream

Step 4
接入 ArkTPStats

Step 5
确认网络稳定

Step 6
根据真实数据调 FEC / BBR / pacing

Step 7
再加入 multipath / migration / NAT

Step 8
最后评估 session resumption / 0-RTT

Step 9
对生产配置做压测和故障注入
```

ArkTP 的核心价值在于：**让应用以类似可靠连接的方式使用
UDP，同时把可靠性、加密、拥塞控制、FEC、流量控制和复杂网络处理下沉到传输层。**

业务层应该尽量关注：

``` text
“我要传什么数据”
```

而不是：

``` text
“这个 UDP 包丢了以后我要怎么重传”
```

这正是 ArkTP Reliable 最适合承担的职责。
