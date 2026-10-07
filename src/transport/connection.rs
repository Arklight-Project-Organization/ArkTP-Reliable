use sha2::Sha256;
use std::{
    net::SocketAddr,
    future::Future,
    pin::Pin,
    sync::OnceLock,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::Notify,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    time::{sleep, interval, timeout},
};
use bytes::Bytes;
use rand::RngCore;
use log::{debug, info, error};

// 加密相关
use chacha20poly1305::aead::{Aead, KeyInit};
use sha2::Digest;
use hmac::{Hmac, Mac};

// 后量子密码学

// 性能优化
use parking_lot::RwLock as PLRwLock;
use flume::{bounded, Receiver};
use rayon::prelude::*;

use crate::*;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SessionTicket {
    pub token: Vec<u8>,
    pub expires_at_ms: u64,
}
impl SessionTicket {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.token.len());
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        out.extend_from_slice(&(self.token.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.token);
        out
    }
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 10 { return None; }
        let expiry = u64::from_be_bytes(data[..8].try_into().ok()?);
        let len = u16::from_be_bytes(data[8..10].try_into().ok()?) as usize;
        if len == 0 || data.len() < 10 + len { return None; }
        Some(Self { expires_at_ms: expiry, token: data[10..10 + len].to_vec() })
    }
    pub fn is_well_formed(&self) -> bool {
        self.expires_at_ms > now_ms() && self.token.len() >= 32
    }
}
static SESSION_TICKETS: OnceLock<dashmap::DashMap<Vec<u8>, (EncryptionKey, u64)>> = OnceLock::new();
static TOFU_KEYS: OnceLock<dashmap::DashMap<SocketAddr, Vec<u8>>> = OnceLock::new();
fn tofu_store() -> &'static dashmap::DashMap<SocketAddr, Vec<u8>> { TOFU_KEYS.get_or_init(dashmap::DashMap::new) }

static SESSION_TICKET_SECRET: OnceLock<[u8; 32]> = OnceLock::new();
fn session_ticket_secret() -> &'static [u8; 32] { SESSION_TICKET_SECRET.get_or_init(rand::random) }

fn session_ticket_store() -> &'static dashmap::DashMap<Vec<u8>, (EncryptionKey, u64)> {
    SESSION_TICKETS.get_or_init(dashmap::DashMap::new)
}
fn cleanup_session_tickets() {
    let now = now_ms();
    let store = session_ticket_store();
    let expired: Vec<Vec<u8>> = store.iter().filter_map(|e| (e.value().1 <= now).then(|| e.key().clone())).collect();
    for key in expired { store.remove(&key); }
}

// ==================== 安全连接 ====================
pub struct ArkTPConnection {
    conn_id: u64,
    remote_addr: Arc<PLRwLock<SocketAddr>>,
    socket: Arc<UdpSocket>,
    bus: Arc<PacketBus>,
    sender: Arc<ArkTPSender>,
    receiver: Arc<ArkTPReceiver>,
    stats: Arc<ArkTPStats>,
    state: Arc<PLRwLock<ConnectionState>>,
    recv_channel: Option<Receiver<Bytes>>,
    recv_pending: Arc<PLRwLock<Bytes>>,
    recv_notify: Arc<Notify>,
    flow_notify: Arc<Notify>,
    send_notify: Arc<Notify>,
    running: Arc<AtomicBool>,
    created_at: Instant,
    crypto: Arc<PLRwLock<CryptoContext>>,
    encryption_enabled: bool,
    multi_path_enabled: bool,
    migration_enabled: bool,
    ecn_enabled: bool,
    tofu_enabled: bool,
    recv_timeout: Arc<PLRwLock<Option<Duration>>>,
    idle_timeout: Arc<PLRwLock<Option<Duration>>>,
    keep_alive_interval: Arc<PLRwLock<Option<Duration>>>,
    last_activity: Arc<PLRwLock<Instant>>,
    handshake_timeout: Duration,
    key_exchange_manager: Arc<KeyExchangeManager>,
    nat_traversal: Option<Arc<NatTraversal>>,
    smart_cache: Arc<SmartCache>,
    parallel_pipeline: Arc<ParallelPipeline>,
    smart_fec: Arc<PLRwLock<SmartAdaptiveFec>>,
    path_challenge: Arc<PLRwLock<Option<(u64, SocketAddr)>>>,
    migration_notify: Arc<Notify>,
    pmtu_probes: Arc<dashmap::DashMap<u64, (u16, Arc<Notify>)>>,
    send_stream_offsets: Arc<PLRwLock<std::collections::HashMap<u64, u64>>>,
    recv_streams: Arc<PLRwLock<std::collections::HashMap<u64, flume::Sender<Bytes>>>>,
    stream_buffers: Arc<PLRwLock<std::collections::HashMap<u64, std::collections::BTreeMap<u64, Bytes>>>>,
    stream_next_offsets: Arc<PLRwLock<std::collections::HashMap<u64, u64>>>,
    stream_fin_offsets: Arc<PLRwLock<std::collections::HashMap<u64, u64>>>,
    stream_receivers: Arc<PLRwLock<std::collections::HashMap<u64, flume::Receiver<Bytes>>>>,
    max_data: Arc<std::sync::atomic::AtomicU64>,
    recv_window_size: u64,
    recv_received_total: Arc<std::sync::atomic::AtomicU64>,
    max_stream_data: Arc<std::sync::atomic::AtomicU64>,
    max_streams: u64,
    peer_max_streams: Arc<std::sync::atomic::AtomicU64>,
    peer_max_stream_data: Arc<std::sync::atomic::AtomicU64>,
    sent_data: Arc<std::sync::atomic::AtomicU64>,
    recv_consumed: Arc<std::sync::atomic::AtomicU64>,
    key_phase: Arc<std::sync::atomic::AtomicU64>,
    peer_max_data: Arc<std::sync::atomic::AtomicU64>,
    recv_data: Arc<std::sync::atomic::AtomicU64>,
    peer_stream_max_data: Arc<dashmap::DashMap<u64, u64>>,
    recv_stream_data: Arc<dashmap::DashMap<u64, u64>>,
    recv_stream_consumed: Arc<dashmap::DashMap<u64, u64>>,
    local_stream_max_data: Arc<dashmap::DashMap<u64, u64>>,
    stream_send_locks: Arc<dashmap::DashMap<u64, Arc<tokio::sync::Mutex<()>>>>,
    send_flow_lock: Arc<tokio::sync::Mutex<()>>,
    stream_notify: Arc<Notify>,
    window_update_pending: Arc<AtomicBool>,
    key_update_lock: Arc<tokio::sync::Mutex<()>>,
    crypto_send_lock: Arc<tokio::sync::Mutex<()>>,
    hedt: Arc<HedtScheduler>,
    previous_crypto: Arc<PLRwLock<Option<CryptoContext>>>,
    send_shutdown: Arc<AtomicBool>,
    peer_send_shutdown: Arc<AtomicBool>,
    retry_token: Arc<PLRwLock<Vec<u8>>>,
}

impl Drop for ArkTPConnection {
    fn drop(&mut self) {
        self.bus.unregister_conn(self.conn_id);
        self.running.store(false, Ordering::Release);
        self.recv_notify.notify_waiters();
        self.flow_notify.notify_waiters();
        self.send_notify.notify_waiters();
        self.stream_notify.notify_waiters();
    }
}

pub struct ArkTPStream {
    conn: Arc<ArkTPConnection>,
    stream_id: u64,
    rx: flume::Receiver<Bytes>,
    send_closed: Arc<AtomicBool>,
}
impl ArkTPStream {
    pub fn id(&self) -> u64 { self.stream_id }
    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        if self.conn.send_shutdown.load(Ordering::Acquire) || self.send_closed.load(Ordering::Acquire) { return Err(ArkTPError::ConnectionClosed); }
        let max_payload = (self.conn.sender.mtu() as usize)
            .saturating_sub(PacketHeader::SIZE + TAG_SIZE + StreamFrame::PREFIX);
        if data.len() > max_payload { return Err(ArkTPError::PacketTooLarge { max: max_payload }); }
        let lock = self.conn.stream_send_locks
            .entry(self.stream_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _stream_guard = lock.lock().await;
        loop {
            let _flow_guard = self.conn.send_flow_lock.lock().await;
            let offset = *self.conn.send_stream_offsets.read().get(&self.stream_id).unwrap_or(&0);
            let peer_limit = self.conn.peer_stream_limit(self.stream_id);
            let conn_limit = self.conn.peer_max_data.load(Ordering::Acquire);
            let used = self.conn.sent_data.load(Ordering::Acquire);
            if peer_limit != 0 && offset.saturating_add(data.len() as u64) <= peer_limit &&
               used.saturating_add(data.len() as u64) <= conn_limit {
                let frame = StreamFrame { stream_id: self.stream_id, offset, fin: false, data: data.to_vec() };
                self.conn.sender.enqueue_stream_async(self.stream_id, Bytes::from(frame.encode())).await?;
                self.conn.send_stream_offsets.write().insert(self.stream_id, offset + data.len() as u64);
                self.conn.sent_data.fetch_add(data.len() as u64, Ordering::Release);
                drop(_flow_guard);
                self.conn.send_notify.notify_one();
                return Ok(data.len());
            }
            drop(_flow_guard);
            if !self.conn.running.load(Ordering::Acquire) { return Err(ArkTPError::ConnectionClosed); }
            self.conn.flow_notify.notified().await;
        }
    }
    async fn advertise_window(&self, consumed: usize) -> Result<()> {
        let used = { let mut e = self.conn.recv_stream_consumed.entry(self.stream_id).or_insert(0); *e = (*e).saturating_add(consumed as u64); *e };
        let max = used.saturating_add(self.conn.max_stream_data.load(Ordering::Acquire));
        self.conn.local_stream_max_data.insert(self.stream_id, max);
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(&self.stream_id.to_be_bytes());
        payload.extend_from_slice(&max.to_be_bytes());
        self.conn.send_control_frame(PacketType::MaxStreamData, &payload).await
    }

    pub async fn recv(&self) -> Result<Bytes> {
        let b = self.rx.recv_async().await.map_err(|_| ArkTPError::StreamClosed)?;
        self.conn.account_consumed(b.len());
        self.conn.drain_stream(self.stream_id);
        self.conn.advertise_window(b.len()).await?;
        self.advertise_window(b.len()).await?;
        Ok(b)
    }
    pub async fn shutdown(&self) -> Result<()> {
        if self.send_closed.swap(true, Ordering::AcqRel) { return Ok(()); }
        let offset = *self.conn.send_stream_offsets.read().get(&self.stream_id).unwrap_or(&0);
        let frame = StreamFrame { stream_id: self.stream_id, offset, fin: true, data: Vec::new() };
        self.conn.sender.enqueue_stream_async(self.stream_id, Bytes::from(frame.encode())).await?;
        self.conn.send_notify.notify_one();
        self.conn.send_stream_offsets.write().remove(&self.stream_id);
        Ok(())
    }
    pub async fn send_all(&self, mut data: &[u8]) -> Result<()> {
        let max = self.conn.sender.mtu() as usize - PacketHeader::SIZE - TAG_SIZE - StreamFrame::PREFIX;
        while !data.is_empty() { let n = data.len().min(max.max(1)); self.send(&data[..n]).await?; data=&data[n..]; }
        Ok(())
    }
}

pub struct SendHalf {
    conn: Arc<ArkTPConnection>,
}
pub struct RecvHalf {
    conn: Arc<ArkTPConnection>,
}

impl AsyncRead for RecvHalf {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>) -> std::task::Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        let pending = { let mut p = this.conn.recv_pending.write(); if p.is_empty() { None } else { let n = p.len().min(buf.remaining()); let out = p.slice(..n); *p = p.slice(n..); Some(out) } };
        if let Some(pending) = pending {
            let n = pending.len();
            buf.put_slice(&pending);
            this.conn.account_consumed(n);
            return std::task::Poll::Ready(Ok(()));
        }
        match this.conn.try_recv_now() {
            Ok(Some(bytes)) => {
                let n = bytes.len().min(buf.remaining());
                buf.put_slice(&bytes[..n]);
                if n < bytes.len() { *this.conn.recv_pending.write() = bytes.slice(n..); }
                this.conn.account_consumed(n);
                std::task::Poll::Ready(Ok(()))
            }
            Ok(None) => {
                let w = cx.waker().clone();
                let notify = self.conn.recv_notify.clone();
                tokio::spawn(async move { notify.notified().await; w.wake(); });
                std::task::Poll::Pending
            }
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))),
        }
    }
}
impl AsyncWrite for SendHalf {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        let max = self.conn.sender.mtu() as usize - PacketHeader::SIZE - TAG_SIZE;
        let n = buf.len().min(max.max(1));
        let used = self.conn.sent_data.load(Ordering::Relaxed);
        if used.saturating_add(n as u64) > self.conn.peer_max_data.load(Ordering::Acquire) {
            return std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ArkTPError::FlowControlBlocked.to_string())));
        }
        match self.conn.sender.enqueue(Bytes::copy_from_slice(&buf[..n])) {
            Ok(_) => { self.conn.sent_data.fetch_add(n as u64, Ordering::Relaxed); self.conn.send_notify.notify_one(); std::task::Poll::Ready(Ok(n)) }
            Err(ArkTPError::SendQueueFull) => {
                let w = cx.waker().clone();
                let notify = self.conn.sender.notify_space();
                tokio::spawn(async move { notify.notified().await; w.wake(); });
                std::task::Poll::Pending
            },
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> { std::task::Poll::Ready(Ok(())) }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        self.conn.send_shutdown.store(true, Ordering::Release);
        let conn = self.conn.clone();
        tokio::spawn(async move { let _ = conn.shutdown_send().await; });
        std::task::Poll::Ready(Ok(()))
    }
}

impl ArkTPConnection {
    pub async fn connect_with_bus(
        socket: Arc<UdpSocket>,
        bus: Arc<PacketBus>,
        remote_addr: SocketAddr,
        config: ArkTPConfig,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        let mut config = config;
        if config.enable_encryption && config.encryption_key.is_none() && config.auto_generate_key {
            config.encryption_key = Some(EncryptionKey::generate());
            config.key_exchange_method = KeyExchangeMethod::AutoGenerated;
        }
        let conn_id = rand::random::<u64>().max(1);
        tracing::info!(conn_id, remote = %remote_addr, "ArkTP connection start");
        Self::connect_with_id_and_bus(socket, bus, remote_addr, conn_id, config, true).await
    }

    pub async fn connect(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        mut config: ArkTPConfig,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        
        if config.enable_encryption && config.encryption_key.is_none() && config.auto_generate_key {
            info!("Auto-generating encryption key");
            config.encryption_key = Some(EncryptionKey::generate());
            config.key_exchange_method = KeyExchangeMethod::AutoGenerated;
        }
        
        let conn_id = rand::random::<u64>();
        Self::connect_with_id(socket, remote_addr, conn_id, config).await
    }
    
    pub async fn connect_with_id(
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        conn_id: u64,
        config: ArkTPConfig,
    ) -> Result<Arc<Self>> {
        let bus = PacketBus::new(socket.clone());
        Self::connect_with_id_and_bus(socket, bus, remote_addr, conn_id, config, true).await
    }

    pub(crate) async fn connect_with_id_and_bus(
        socket: Arc<UdpSocket>,
        bus: Arc<PacketBus>,
        remote_addr: SocketAddr,
        conn_id: u64,
        config: ArkTPConfig,
        start_handshake: bool,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        let stats = config.stats.clone().unwrap_or_else(|| Arc::new(ArkTPStats::new()));
        let mut config = config;
        config.stats = Some(stats.clone());
        
        let encryption_enabled = config.enable_encryption;
        let multi_path_enabled = config.enable_multipath;
        let migration_enabled = config.enable_connection_migration;
        let recv_timeout = config.recv_timeout;
        let idle_timeout = config.idle_timeout;
        let keep_alive_interval = config.keep_alive_interval;
        let handshake_timeout = config.handshake_timeout;
        let authentication = config.authentication.clone();
        let ecn_enabled = config.enable_ecn;
        let initial_max_data = config.initial_max_data;
        let initial_max_stream_data = config.initial_max_stream_data;
        let max_streams = config.max_streams;
        let path_scheduler_plugin = config.path_scheduler_plugin.clone();
        let hedt_config = HedtConfig {
            enabled: config.hedt_enabled,
            threshold: config.hedt_threshold,
            max_inflight: config.hedt_max_inflight,
        };
        
        let key_exchange_manager = if let Some(key) = &config.encryption_key {
            Arc::new(KeyExchangeManager::from_pre_shared_key(key)?)
        } else {
            Arc::new(KeyExchangeManager::new()?)
        };
        
        key_exchange_manager.set_preferred_method(config.key_exchange_method);
        if let AuthenticationConfig::PinnedPublicKey { fingerprint } = &authentication {
            key_exchange_manager.set_trusted_fingerprint(fingerprint.clone());
        } else if matches!(&authentication, AuthenticationConfig::Tofu) {
            key_exchange_manager.enable_tofu();
            if let Some(fp) = tofu_store().get(&remote_addr) { key_exchange_manager.set_trusted_fingerprint(fp.clone()); }
        }

        let crypto = if let Some(key) = &config.encryption_key {
            CryptoContext::new(key)
        } else {
            let temp_key = EncryptionKey::generate();
            CryptoContext::new(&temp_key)
        };
        
        let nat_traversal = if config.enable_nat_traversal {
            Some(Arc::new(NatTraversal::new().await?))
        } else {
            None
        };
        
        let smart_cache = Arc::new(SmartCache::new());
        let parallel_pipeline = Arc::new(ParallelPipeline::new());
        let smart_fec = Arc::new(PLRwLock::new(SmartAdaptiveFec::new()));
        
        let (recv_sender, recv_channel) = bounded(config.receive_buffer_size);
        let send_notify = Arc::new(Notify::new());
        
        let conn = Arc::new(Self {
            conn_id,
            remote_addr: Arc::new(PLRwLock::new(remote_addr)),
            socket: socket.clone(),
            bus: bus.clone(),
            sender: Arc::new(ArkTPSender::with_config(conn_id, config.clone())),
            receiver: Arc::new(ArkTPReceiver::with_config(
                conn_id,
                config.clone(),
                recv_sender.clone(),
            )),
            stats,
            state: Arc::new(PLRwLock::new(ConnectionState::SynSent)),
            recv_channel: Some(recv_channel),
            recv_pending: Arc::new(PLRwLock::new(Bytes::new())),
            recv_notify: Arc::new(Notify::new()),
            flow_notify: Arc::new(Notify::new()),
            send_notify: send_notify.clone(),
            running: Arc::new(AtomicBool::new(true)),
            created_at: Instant::now(),
            crypto: Arc::new(PLRwLock::new(crypto)),
            encryption_enabled,
            multi_path_enabled,
            migration_enabled,
            ecn_enabled,
            tofu_enabled: matches!(authentication, AuthenticationConfig::Tofu),
            recv_timeout: Arc::new(PLRwLock::new(recv_timeout)),
            idle_timeout: Arc::new(PLRwLock::new(idle_timeout)),
            keep_alive_interval: Arc::new(PLRwLock::new(keep_alive_interval)),
            last_activity: Arc::new(PLRwLock::new(Instant::now())),
            handshake_timeout,
            key_exchange_manager,
            nat_traversal,
            smart_cache,
            parallel_pipeline,
            smart_fec,
            path_challenge: Arc::new(PLRwLock::new(None)),
            migration_notify: Arc::new(Notify::new()),
            pmtu_probes: Arc::new(dashmap::DashMap::new()),
            send_stream_offsets: Arc::new(PLRwLock::new(std::collections::HashMap::new())),
            recv_streams: Arc::new(PLRwLock::new(std::collections::HashMap::new())),
            stream_buffers: Arc::new(PLRwLock::new(std::collections::HashMap::new())),
            stream_next_offsets: Arc::new(PLRwLock::new(std::collections::HashMap::new())),
            stream_fin_offsets: Arc::new(PLRwLock::new(std::collections::HashMap::new())),
            stream_receivers: Arc::new(PLRwLock::new(std::collections::HashMap::new())),
            max_data: Arc::new(std::sync::atomic::AtomicU64::new(initial_max_data)),
            recv_window_size: initial_max_data,
            recv_received_total: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            max_stream_data: Arc::new(std::sync::atomic::AtomicU64::new(initial_max_stream_data)),
            max_streams,
            peer_max_streams: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            peer_max_stream_data: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            peer_max_data: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            recv_data: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            peer_stream_max_data: Arc::new(dashmap::DashMap::new()),
            recv_stream_data: Arc::new(dashmap::DashMap::new()),
            recv_stream_consumed: Arc::new(dashmap::DashMap::new()),
            local_stream_max_data: Arc::new(dashmap::DashMap::new()),
            stream_send_locks: Arc::new(dashmap::DashMap::new()),
            send_flow_lock: Arc::new(tokio::sync::Mutex::new(())),
            stream_notify: Arc::new(Notify::new()),
            window_update_pending: Arc::new(AtomicBool::new(false)),
            key_update_lock: Arc::new(tokio::sync::Mutex::new(())),
            crypto_send_lock: Arc::new(tokio::sync::Mutex::new(())),
            hedt: Arc::new(HedtScheduler::new(hedt_config)),
            previous_crypto: Arc::new(PLRwLock::new(None)),
            sent_data: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            recv_consumed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            key_phase: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            send_shutdown: Arc::new(AtomicBool::new(false)),
            peer_send_shutdown: Arc::new(AtomicBool::new(false)),
            retry_token: Arc::new(PLRwLock::new(Vec::new())),
        });
        
        conn.bus.register_conn(conn.conn_id);
        conn.sender.set_notify(send_notify.clone());
        if let Some(plugin) = path_scheduler_plugin {
            conn.sender.multi_path().set_scheduler_plugin(plugin);
        }
        
        if multi_path_enabled {
            conn.sender.add_path(socket.clone(), remote_addr).ok();
        }
        
        conn.start_receive_loop();
        conn.start_send_loop();
        conn.start_keepalive_loop();
        conn.start_cleanup_loop();
        conn.start_stats_loop();
        conn.start_path_probe_loop();
        conn.start_flow_sync_loop();
        
        if let Some(nat) = &conn.nat_traversal {
            let nat_clone = nat.clone();
            nat_clone.start_probe_loop();
            let nat_clone = nat.clone();
            nat_clone.start_refresh_loop();
        }
        
        if start_handshake {
            conn.perform_key_exchange_and_handshake().await?;
        }
        
        Ok(conn)
    }
    
    pub(crate) async fn accept_resumed_with_bus(
        bus: Arc<PacketBus>, remote_addr: SocketAddr, conn_id: u64,
        mut config: ArkTPConfig, ticket: &SessionTicket,
    ) -> Result<Arc<Self>> {
        let key = Self::consume_session_ticket(ticket)?;
        config.encryption_key = Some(key.clone());
        config.key_exchange_method = KeyExchangeMethod::PreSharedKey;
        config.authentication = AuthenticationConfig::PreSharedKey;
        let conn = Self::connect_with_id_and_bus(bus.socket(), bus.clone(), remote_addr, conn_id, config, false).await?;
        conn.install_session_key(key)?;
        conn.set_state(ConnectionState::Established);
        conn.send_control_frame(PacketType::HandshakeDone, &[]).await?;
        conn.send_flow_control().await?;
        for (packet, src) in bus.take_pending(conn_id) {
            if packet.len() >= PacketHeader::SIZE {
                let kind = PacketType::from(packet[0]);
                if matches!(kind, PacketType::Data | PacketType::Stream) { bus.inject(packet, src); }
            }
        }
        Ok(conn)
    }

    pub(crate) async fn accept_with_bus(
        bus: Arc<PacketBus>,
        remote_addr: SocketAddr,
        conn_id: u64,
        config: ArkTPConfig,
        initial_packet: Bytes,
    ) -> Result<Arc<Self>> {
        let conn = Self::connect_with_id_and_bus(
            bus.socket(), bus.clone(), remote_addr, conn_id, config, false
        ).await?;
        // The first datagram was consumed by the listener. Clear its short-lived
        // backlog entry, then re-inject exactly once after the connection subscriber exists.
        let _ = bus.take_pending(conn_id);
        bus.inject(initial_packet, remote_addr);
        let deadline = Instant::now() + conn.handshake_timeout();
        while Instant::now() < deadline {
            if *conn.state.read() == ConnectionState::Established { return Ok(conn); }
            if *conn.state.read() == ConnectionState::Reset { return Err(ArkTPError::HandshakeFailed); }
            sleep(Duration::from_millis(5)).await;
        }
        Err(ArkTPError::KeyAgreementTimeout)
    }

    fn handshake_timeout(&self) -> Duration { self.config_handshake_timeout() }

    fn config_handshake_timeout(&self) -> Duration { self.handshake_timeout }

    async fn send_control_frame(&self, pkt_type: PacketType, payload: &[u8]) -> Result<()> {
        let _crypto_guard = self.crypto_send_lock.lock().await;
        let h = PacketHeader::new(pkt_type, 0, self.conn_id);
        let body = if self.encryption_enabled { self.crypto.read().encrypt(payload, &h.encode())? } else { payload.to_vec() };
        let mut packet = Vec::with_capacity(PacketHeader::SIZE + body.len());
        packet.extend_from_slice(&h.encode());
        packet.extend_from_slice(&body);
        self.bus.send_to(&packet, self.remote_addr_value()).await?;
        *self.last_activity.write() = Instant::now();
        Ok(())
    }

    fn decrypt_control(&self, payload: &[u8], header: &PacketHeader) -> Option<Vec<u8>> {
        if !self.encryption_enabled { return Some(payload.to_vec()); }
        self.crypto.read().decrypt(payload, &header.encode())
            .or_else(|_| self.previous_crypto.read().as_ref().and_then(|c| c.decrypt(payload, &header.encode()).ok()).ok_or(ArkTPError::DecryptionError("control decrypt failed".into())))
            .ok()
    }

    async fn send_ack_if_due(
        &self,
        src: SocketAddr,
        pending_acks: &mut u32,
        last_ack_sent: &mut Instant,
        pending_ack_since: &mut Option<Instant>,
        force: bool,
    ) -> Result<()> {
        if *pending_acks == 0 { return Ok(()); }
        let now = Instant::now();
        let due = force || *pending_acks >= 3 || now.duration_since(*last_ack_sent) >= Duration::from_millis(ACK_INTERVAL_MS);
        if !due { return Ok(()); }
        let _crypto_guard = self.crypto_send_lock.lock().await;
        let ack_seq = self.receiver.next_seq();
        let sack_blocks = self.receiver.get_sack_blocks();
        let delay_us = pending_ack_since.take()
            .map(|t| now.duration_since(t).as_micros().min(u32::MAX as u128) as u32)
            .unwrap_or(0);
        let mut ah = PacketHeader::new(PacketType::Ack, 0, self.conn_id);
        ah.ack = ack_seq.0;
        let plain = encode_ack(ack_seq, &sack_blocks, delay_us,
            self.stats.ecn_ect0.load(Ordering::Relaxed),
            self.stats.ecn_ect1.load(Ordering::Relaxed),
            self.stats.ecn_ce.load(Ordering::Relaxed));
        let ack_payload = if self.encryption_enabled {
            self.crypto.read().encrypt(&plain, &ah.encode())?
        } else { plain };
        let mut packet = Vec::with_capacity(PacketHeader::SIZE + ack_payload.len());
        packet.extend_from_slice(&ah.encode());
        packet.extend_from_slice(&ack_payload);
        self.bus.send_to(&packet, src).await?;
        *pending_acks = 0;
        *last_ack_sent = now;
        Ok(())
    }

    async fn send_flow_control(&self) -> Result<()> {
        let max_data = self.max_data.load(Ordering::Acquire);
        self.send_control_frame(PacketType::MaxData, &max_data.to_be_bytes()).await?;
        let max_stream_data = self.max_stream_data.load(Ordering::Acquire);
        let mut stream_payload = Vec::with_capacity(16);
        stream_payload.extend_from_slice(&0u64.to_be_bytes());
        stream_payload.extend_from_slice(&max_stream_data.to_be_bytes());
        self.send_control_frame(PacketType::MaxStreamData, &stream_payload).await?;
        self.send_control_frame(PacketType::MaxStreams, &self.max_streams.to_be_bytes()).await?;
        Ok(())
    }

    async fn perform_key_exchange_and_handshake(&self) -> Result<()> {
        *self.state.write() = ConnectionState::KeyExchanging;
        let mut retries = 0;
        let mut last_key_exchange = Instant::now();
        
        loop {
            let state = *self.state.read();
            match state {
                ConnectionState::Established => {
                    info!("Secure connection {} established", self.conn_id);
                    return Ok(());
                }
                ConnectionState::Reset => {
                    return Err(ArkTPError::ConnectionReset);
                }
                ConnectionState::Closed => {
                    return Err(ArkTPError::ConnectionClosed);
                }
                _ => {}
            }
            
            if Instant::now().duration_since(self.created_at) > Duration::from_millis(KEY_EXCHANGE_TIMEOUT_MS) {
                return Err(ArkTPError::KeyAgreementTimeout);
            }
            
            if last_key_exchange.elapsed() > Duration::from_millis(SYN_RETRY_INTERVAL_MS) {
                if retries >= MAX_RETRIES {
                    return Err(ArkTPError::KeyExchangeFailed("Max retries exceeded".to_string()));
                }
                
                self.send_key_exchange().await?;
                last_key_exchange = Instant::now();
                retries += 1;
                debug!("Retransmitting key exchange (attempt {}/{})", retries, MAX_RETRIES);
            }
            
            sleep(Duration::from_millis(20)).await;
        }
    }
    
    async fn send_key_exchange(&self) -> Result<()> {
        let mut key_exchange_msg = self.key_exchange_manager.initiate_key_exchange(self.conn_id);
        key_exchange_msg.retry_token = self.retry_token.read().clone();
        let ke_data = key_exchange_msg.encode();
        
        let header = PacketHeader {
            pkt_type: PacketType::KeyExchange as u8,
            flags: 0,
            seq: rand::random::<u32>(),
            ack: 0,
            conn_id: self.conn_id,
            timestamp: now_ms(),
        };
        
        let mut packet = Vec::with_capacity(PacketHeader::SIZE + ke_data.len());
        packet.extend_from_slice(&header.encode());
        packet.extend_from_slice(&ke_data);
        
        self.bus.send_to(&packet, self.remote_addr_value()).await?;
        debug!("Sent key exchange to {}", self.remote_addr_value());
        Ok(())
    }
    
    fn start_receive_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        let mut rx = self.bus.subscribe();
        tokio::spawn(async move {
            let mut last_ack_sent = Instant::now();
            let mut pending_acks = 0u32;
            let mut pending_ack_since: Option<Instant> = None;
            while let Some(conn) = weak.upgrade() {
                if !conn.running.load(Ordering::Relaxed) { break; }
                match rx.recv().await {
                    Ok((bytes, src)) => {
                        *conn.last_activity.write() = Instant::now();
                        let n = bytes.len();
                        if n < PacketHeader::SIZE { continue; }
                        if let Some(header) = PacketHeader::decode(&bytes[..PacketHeader::SIZE]) {
                            if header.conn_id != conn.conn_id {
                                continue;
                            }
                            let current_remote = conn.remote_addr_value();
                            if src != current_remote && conn.migration_enabled {
                                match PacketType::from(header.pkt_type) {
                                    PacketType::PathResponse | PacketType::PathChallenge | PacketType::KeepAlive | PacketType::KeepAliveAck => {}
                                    _ => {
                                        let token = rand::random::<u64>();
                                        *conn.path_challenge.write() = Some((token, src));
                                        let h = PacketHeader::new(PacketType::PathChallenge, 0, conn.conn_id);
                                        let mut out = Vec::with_capacity(PacketHeader::SIZE + 8);
                                        out.extend_from_slice(&h.encode());
                                        out.extend_from_slice(&token.to_be_bytes());
                                        let _ = conn.bus.send_to(&out, src).await;
                                        continue;
                                    }
                                }
                            }
                            
                            let payload = &bytes[PacketHeader::SIZE..n];
                            
                            match PacketType::from(header.pkt_type) {
                                PacketType::HandshakeDone => {
                                    if conn.decrypt_control(payload, &header).map(|p| p.is_empty()).unwrap_or(false) && *conn.state.read() == ConnectionState::KeyExchanging {
                                        conn.set_state(ConnectionState::Established);
                                        conn.bus.clear_pending(conn.conn_id);
                                        let _ = conn.send_flow_control().await;
                                    }
                                }
                                PacketType::Retry => {
                                    if !payload.is_empty() {
                                        *conn.retry_token.write() = payload.to_vec();
                                        let _ = conn.send_key_exchange().await;
                                    }
                                }
                                PacketType::KeyExchange => {
                                    if let Some(ke_msg) = KeyExchangeMessage::decode(payload) {
                                        debug!("Received key exchange from {}", src);
                                        
                                        match conn.key_exchange_manager.respond_to_key_exchange(
                                            &ke_msg,
                                            conn.conn_id,
                                        ) {
                                            Ok(response) => {
                                                let response_data = response.encode();
                                                let response_header = PacketHeader {
                                                    pkt_type: PacketType::KeyExchangeAck as u8,
                                                    flags: 0,
                                                    seq: header.seq,
                                                    ack: 0,
                                                    conn_id: conn.conn_id,
                                                    timestamp: now_ms(),
                                                };
                                                
                                                let mut packet = Vec::with_capacity(
                                                    PacketHeader::SIZE + response_data.len()
                                                );
                                                packet.extend_from_slice(&response_header.encode());
                                                packet.extend_from_slice(&response_data);
                                                
                                                let _ = conn.bus.send_to(&packet, src).await;
                                                
                                                if let Some(key) = conn.key_exchange_manager.get_session_key() {
                                                    *conn.crypto.write() = CryptoContext::new(&key);
                                                }
                                                
                                                conn.set_state(ConnectionState::Established);
                                                conn.bus.clear_pending(conn.conn_id);
                                                let _ = conn.send_flow_control().await;
                                                if conn.tofu_enabled { if let Some(fp) = conn.key_exchange_manager.get_peer_fingerprint() { tofu_store().insert(src, fp); } }
                                                conn.stats.key_exchanges_completed.fetch_add(1, Ordering::Relaxed);
                                                info!("Key exchange completed for connection {}", conn.conn_id);
                                            }
                                            Err(e) => {
                                                conn.stats.key_exchanges_failed.fetch_add(1, Ordering::Relaxed);
                                                error!("Key exchange failed: {}", e);
                                            }
                                        }
                                    }
                                }
                                PacketType::KeyExchangeAck => {
                                    if let Some(ke_msg) = KeyExchangeMessage::decode(payload) {
                                        debug!("Received key exchange ack from {}", src);
                                        
                                        let verification = conn.key_exchange_manager.key_verification.read().clone();
                                        if conn.key_exchange_manager.complete_key_exchange(
                                            &ke_msg,
                                            conn.conn_id,
                                            &verification,
                                        ).is_ok() {
                                            if let Some(key) = conn.key_exchange_manager.get_session_key() {
                                                *conn.crypto.write() = CryptoContext::new(&key);
                                            }
                                            
                                            conn.set_state(ConnectionState::Established);
                                            conn.bus.clear_pending(conn.conn_id);
                                            let _ = conn.send_flow_control().await;
                                            if conn.tofu_enabled { if let Some(fp) = conn.key_exchange_manager.get_peer_fingerprint() { tofu_store().insert(src, fp); } }
                                            conn.stats.key_exchanges_completed.fetch_add(1, Ordering::Relaxed);
                                            info!("Key exchange completed for connection {}", conn.conn_id);
                                        }
                                    }
                                }
                                PacketType::Data => {
                                    let decrypted = if conn.encryption_enabled {
                                        let current = conn.crypto.read().decrypt(payload, &header.encode());
                                        let result = current.or_else(|_| conn.previous_crypto.read().as_ref().ok_or(ArkTPError::DecryptionError("no previous key".into())).and_then(|c| c.decrypt(payload, &header.encode())));
                                        match result {
                                            Ok(data) => {
                                                conn.stats.decrypted_packets.fetch_add(1, Ordering::Relaxed);
                                                data
                                            }
                                            Err(e) => {
                                                conn.stats.failed_decryptions.fetch_add(1, Ordering::Relaxed);
                                                debug!("Failed to decrypt packet: {}", e);
                                                continue;
                                            }
                                        }
                                    } else { payload.to_vec() };

                                    let data = Bytes::from(decrypted);
                                    let total = conn.recv_received_total.load(Ordering::Acquire);
                                    if total.saturating_add(data.len() as u64) > conn.max_data.load(Ordering::Acquire) {
                                        continue;
                                    }
                                    conn.recv_received_total.fetch_add(data.len() as u64, Ordering::AcqRel);
                                    conn.recv_data.fetch_add(data.len() as u64, Ordering::AcqRel);
                                    let seq = SeqNum::new(header.seq);
                                    if conn.receiver.on_data_packet(seq, data, None) {
                                        conn.recv_notify.notify_waiters();
                                        if pending_acks == 0 { pending_ack_since = Some(Instant::now()); }
                                        pending_acks += 1;
                                        let _ = conn.send_ack_if_due(src, &mut pending_acks, &mut last_ack_sent, &mut pending_ack_since, false).await;
                                    } else {
                                        continue;
                                    }
                                }
                                PacketType::Ack => {
                                    if payload.is_empty() && header.ack != 0 {
                                        let st = *conn.state.read();
                                        if st == ConnectionState::FinWait1 { *conn.state.write() = ConnectionState::FinWait2; }
                                        else if st == ConnectionState::LastAck { *conn.state.write() = ConnectionState::Closed; conn.running.store(false, Ordering::Release); }
                                    }
                                    let decrypted = if conn.encryption_enabled {
                                        conn.crypto.read().decrypt(payload, &header.encode()).or_else(|_| conn.previous_crypto.read().as_ref().ok_or(ArkTPError::DecryptionError("no previous key".into())).and_then(|c| c.decrypt(payload, &header.encode()))).ok()
                                    } else {
                                        Some(payload.to_vec())
                                    };
                                    
                                    if let Some(decrypted) = decrypted {
                                        if let Some((ack_info, sack_blocks)) = decode_ack(&decrypted) {
                                            conn.sender.on_ack(Instant::now(), ack_info.ack, &sack_blocks, None);
                                        }
                                    }
                                }
                                PacketType::KeepAlive => {
                                    let h = PacketHeader::new(PacketType::KeepAliveAck, header.seq, conn.conn_id);
                                    let _ = conn.bus.send_to(&h.encode(), src).await;
                                }
                                PacketType::KeepAliveAck => {}
                                PacketType::PathProbe => {
                                    let h = PacketHeader::new(PacketType::PathProbeAck, header.seq, conn.conn_id);
                                    let _ = conn.bus.send_to(&h.encode(), src).await;
                                }
                                PacketType::PathProbeAck => {}
                                PacketType::MtuProbe => {
                                    if payload.len() >= 8 {
                                        let token = &payload[..8];
                                        let h = PacketHeader::new(PacketType::MtuProbeAck, 0, conn.conn_id);
                                        let mut out = Vec::with_capacity(PacketHeader::SIZE + 8);
                                        out.extend_from_slice(&h.encode());
                                        out.extend_from_slice(token);
                                        let _ = conn.bus.send_to(&out, src).await;
                                    }
                                }
                                PacketType::MtuProbeAck => {
                                    if payload.len() == 8 {
                                        let token = u64::from_be_bytes(payload.try_into().unwrap());
                                        if let Some((_, (candidate, notify))) = conn.pmtu_probes.remove(&token) {
                                            let _ = conn.sender.set_mtu(candidate);
                                            notify.notify_waiters();
                                        }
                                    }
                                }
                                PacketType::PathChallenge => {
                                    if payload.len() == 8 {
                                        let token = u64::from_be_bytes(payload.try_into().unwrap());
                                        let mut h = PacketHeader::new(PacketType::PathResponse, 0, conn.conn_id);
                                        h.seq = token as u32;
                                        let mut out = Vec::with_capacity(PacketHeader::SIZE + 8);
                                        out.extend_from_slice(&h.encode());
                                        out.extend_from_slice(&token.to_be_bytes());
                                        let _ = conn.bus.send_to(&out, src).await;
                                    }
                                }
                                PacketType::PathResponse => {
                                    if payload.len() == 8 {
                                        let token = u64::from_be_bytes(payload.try_into().unwrap());
                                        if conn.path_challenge.read().as_ref().map(|(t,a)| *t == token && *a == src).unwrap_or(false) {
                                            conn.update_remote_addr(src);
                                            if let Some(path) = conn.sender.multi_path().get_path(0) { path.update_remote_addr(src); }
                                            *conn.path_challenge.write() = None;
                                            conn.migration_notify.notify_waiters();
                                        }
                                    }
                                }
                                PacketType::KeyUpdate => {
                                    if conn.encryption_enabled {
                                        let decrypted = conn.crypto.read().decrypt(payload, &header.encode())
                                            .or_else(|_| conn.previous_crypto.read().as_ref().ok_or(ArkTPError::DecryptionError("no previous key".into())).and_then(|c| c.decrypt(payload, &header.encode())));
                                        if let Ok(plain) = decrypted {
                                            if plain.len() == 8 {
                                                let phase = u64::from_be_bytes(plain.try_into().unwrap());
                                                let _guard = conn.key_update_lock.lock().await;
                                                if phase > conn.key_phase.load(Ordering::Acquire) {
                                                    if let Some(old) = conn.get_session_key() {
                                                        if let Ok(new_key) = old.derive_session_key(conn.conn_id ^ phase, b"ArkTP-key-update") {
                                                            let old_ctx = conn.crypto.read().clone();
                                                            *conn.previous_crypto.write() = Some(old_ctx);
                                                            conn.crypto.write().rotate(&new_key);
                                                            conn.key_phase.store(phase, Ordering::Release);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                PacketType::MaxStreamData => {
                                    let Some(control) = conn.decrypt_control(payload, &header) else { continue; };
                                    if control.len() == 16 {
                                        let id = u64::from_be_bytes(control[..8].try_into().unwrap());
                                        let v = u64::from_be_bytes(control[8..16].try_into().unwrap());
                                        conn.peer_stream_max_data.entry(id).and_modify(|x| *x = (*x).max(v)).or_insert(v);
                                        if id == 0 { conn.peer_max_stream_data.fetch_max(v, Ordering::AcqRel); }
                                        conn.flow_notify.notify_waiters();
                                    } else if control.len() == 8 {
                                        let v = u64::from_be_bytes(control.try_into().unwrap());
                                        conn.peer_max_stream_data.fetch_max(v, Ordering::AcqRel);
                                        conn.peer_stream_max_data.entry(0).and_modify(|x| *x = (*x).max(v)).or_insert(v);
                                        conn.flow_notify.notify_waiters();
                                    }
                                }
                                PacketType::MaxStreams => {
                                    let Some(control) = conn.decrypt_control(payload, &header) else { continue; };
                                    if control.len() == 8 {
                                        conn.peer_max_streams.fetch_max(u64::from_be_bytes(control.try_into().unwrap()), Ordering::AcqRel);
                                        conn.flow_notify.notify_waiters();
                                    }
                                }
                                PacketType::MaxData => {
                                    let Some(control) = conn.decrypt_control(payload, &header) else { continue; };
                                    if control.len() == 8 {
                                        let v = u64::from_be_bytes(control.try_into().unwrap());
                                        conn.peer_max_data.fetch_max(v, Ordering::AcqRel);
                                        conn.flow_notify.notify_waiters();
                                    }
                                }
                                PacketType::Fec => {
                                    if let Some(fec) = FecPacket::decode(&bytes[..n]) {
                                        conn.receiver.on_fec_packet(fec, None);
                                    }
                                }
                                PacketType::Stream => {
                                    let plain = if conn.encryption_enabled {
                                        match conn.crypto.read().decrypt(payload, &header.encode()).or_else(|_| conn.previous_crypto.read().as_ref().ok_or(ArkTPError::DecryptionError("no previous key".into())).and_then(|c| c.decrypt(payload, &header.encode()))) { Ok(v) => v, Err(_) => continue }
                                    } else { payload.to_vec() };
                                    if let Some(frame) = StreamFrame::decode(&plain) {
                                        if frame.stream_id == 0 || frame.stream_id >= conn.max_streams { continue; }
                                        let end = frame.offset.saturating_add(frame.data.len() as u64);
                                        let stream_used = conn.recv_stream_data.get(&frame.stream_id).map(|v| *v).unwrap_or(0);
                                        let stream_limit = conn.local_stream_max_data.get(&frame.stream_id).map(|v| *v).unwrap_or(conn.max_stream_data.load(Ordering::Acquire));
                                        if let Some(bufs) = conn.stream_buffers.read().get(&frame.stream_id) {
                                            if bufs.range(..=frame.offset).next_back().map(|(off, b)| off.saturating_add(b.len() as u64) > frame.offset).unwrap_or(false) ||
                                               bufs.range(frame.offset..).next().map(|(off, _)| *off < end).unwrap_or(false) { continue; }
                                        }
                                        if end > stream_limit ||
                                           conn.recv_received_total.load(Ordering::Acquire).saturating_add(frame.data.len() as u64) > conn.max_data.load(Ordering::Acquire) ||
                                           end < stream_used { continue; }
                                        conn.recv_received_total.fetch_add(frame.data.len() as u64, Ordering::AcqRel);
                                        conn.recv_data.fetch_add(frame.data.len() as u64, Ordering::AcqRel);
                                        conn.recv_stream_data.insert(frame.stream_id, end);
                                        conn.ensure_incoming_stream(frame.stream_id);
                                        conn.on_stream_frame(frame);
                                        if pending_acks == 0 { pending_ack_since = Some(Instant::now()); }
                                        pending_acks += 1;
                                        let _ = conn.send_ack_if_due(src, &mut pending_acks, &mut last_ack_sent, &mut pending_ack_since, false).await;
                                    }
                                }
                                PacketType::Extension => {
                                    if let Some(ext) = ExtensionFrame::decode(payload) {
                                        if ext.kind == 2 { conn.peer_send_shutdown.store(true, Ordering::Release); conn.recv_notify.notify_waiters(); }
                                    }
                                }
                                PacketType::ConnectionClose => {
                                    let ack = PacketHeader::new(PacketType::Ack, 0, conn.conn_id).encode();
                                    let _ = conn.bus.send_to(&ack, src).await;
                                    *conn.state.write() = ConnectionState::CloseWait;
                                    conn.running.store(false, Ordering::Relaxed);
                                }
                                PacketType::Fin => {
                                    let mut h = PacketHeader::new(PacketType::Ack, 0, conn.conn_id);
                                    h.ack = header.seq;
                                    let _ = conn.bus.send_to(&h.encode(), src).await;
                                    let st = *conn.state.read();
                                    if st == ConnectionState::FinWait2 {
                                        *conn.state.write() = ConnectionState::TimeWait;
                                        let c = conn.clone();
                                        tokio::spawn(async move {
                                            sleep(Duration::from_millis(MAX_RTO_MS * 2)).await;
                                            *c.state.write() = ConnectionState::Closed;
                                            c.running.store(false, Ordering::Release);
                                        });
                                    } else {
                                        *conn.state.write() = ConnectionState::CloseWait;
                                        let mut fin = PacketHeader::new(PacketType::Fin, 0, conn.conn_id); fin.seq = rand::random::<u32>(); let fin = fin.encode();
                                        let _ = conn.bus.send_to(&fin, src).await;
                                        *conn.state.write() = ConnectionState::LastAck;
                                    }
                                }
                                PacketType::Reset => {
                                    *conn.state.write() = ConnectionState::Reset;
                                    conn.running.store(false, Ordering::Relaxed);
                                    error!("Secure connection {} reset", conn.conn_id);
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
    


    fn config_migration_enabled(&self) -> bool { self.migration_enabled }

    fn ensure_incoming_stream(self: &Arc<Self>, stream_id: u64) {
        if stream_id == 0 || self.recv_streams.read().contains_key(&stream_id) { return; }
        let (tx, rx) = flume::bounded(256);
        self.recv_streams.write().insert(stream_id, tx);
        self.local_stream_max_data.insert(stream_id, self.max_stream_data.load(Ordering::Acquire));
        self.stream_receivers.write().insert(stream_id, rx);
        self.stream_notify.notify_one();
    }

    fn on_stream_frame(&self, frame: StreamFrame) {
        let end = frame.offset.saturating_add(frame.data.len() as u64);
        if frame.fin { self.stream_fin_offsets.write().insert(frame.stream_id, end); }
        self.stream_buffers.write().entry(frame.stream_id).or_default()
            .entry(frame.offset).or_insert(Bytes::from(frame.data));
        self.drain_stream(frame.stream_id);
    }

    fn drain_stream(&self, stream_id: u64) {
        let mut next = *self.stream_next_offsets.read().get(&stream_id).unwrap_or(&0);
        let sender = self.recv_streams.read().get(&stream_id).cloned();
        let Some(entry) = sender else { return; };
        loop {
            let data = {
                let mut buffers = self.stream_buffers.write();
                buffers.get_mut(&stream_id).and_then(|b| b.remove(&next))
            };
            let Some(data) = data else { break; };
            match entry.try_send(data.clone()) {
                Ok(()) => { next = next.saturating_add(data.len() as u64); }
                Err(flume::TrySendError::Full(data)) => {
                    self.stream_buffers.write().entry(stream_id).or_default().insert(next, data);
                    break;
                }
                Err(flume::TrySendError::Disconnected(_)) => break,
            }
        }
        self.stream_next_offsets.write().insert(stream_id, next);
        if self.stream_fin_offsets.read().get(&stream_id).copied() == Some(next)
            && self.stream_buffers.read().get(&stream_id).map(|b| b.is_empty()).unwrap_or(true) {
            if let Some(sender) = self.recv_streams.read().get(&stream_id).cloned() {
                if sender.is_empty() { self.recv_streams.write().remove(&stream_id); }
            }
            self.recv_stream_data.remove(&stream_id);
            self.recv_stream_consumed.remove(&stream_id);
            self.local_stream_max_data.remove(&stream_id);
            self.stream_next_offsets.write().remove(&stream_id);
            self.stream_fin_offsets.write().remove(&stream_id);
        }
    }

    async fn send_pending_packets(&self) {
        if self.window_update_pending.load(Ordering::Acquire) {
            if self.advertise_window(0).await.is_ok() { self.window_update_pending.store(false, Ordering::Release); }
        }
        if self.encryption_enabled && self.crypto.read().needs_key_update() {
            let _ = self.key_update().await;
        }

        let packets = self.sender.get_packets_to_send(Instant::now());
        let mut large_jobs = Vec::new();

        // HEDT: small packets are encrypted/sent immediately. Large packets
        // are handed to a bounded background crypto pool, so a slow large
        // AEAD operation cannot hold up latency-sensitive control or small
        // application packets. All resulting packets still use the same
        // congestion-control and pacing decisions made by the sender above.
        for (data, seq, is_retransmit, path_id) in packets {
            let packet_type = self.sender.stream_id_for(seq).map(|_| PacketType::Stream).unwrap_or(PacketType::Data);
            let mut header = PacketHeader {
                pkt_type: packet_type as u8,
                flags: if is_retransmit { 1 } else { 0 },
                seq: seq.0,
                ack: 0,
                conn_id: self.conn_id,
                timestamp: 0,
            };
            if self.ecn_enabled { header.set_ecn(1); }
            let header_bytes = header.encode();

            if self.encryption_enabled && self.hedt.is_large(data.len(), true) {
                // Serialise only the snapshot of the active key phase. The
                // expensive AEAD operation happens after the lock is released.
                let _crypto_guard = self.crypto_send_lock.lock().await;
                let crypto = self.crypto.read().clone();
                if let Some(job) = self.hedt.submit_large(crypto, data.clone(), header_bytes).await {
                    self.stats.hedt_large_offloaded.fetch_add(1, Ordering::Relaxed);
                    large_jobs.push((job, header, path_id));
                    continue;
                }
            }

            // Small packets take the immediate path and never wait for
            // another packet's crypto operation. A large packet can also
            // reach this branch when the bounded HEDT pool is saturated;
            // that is a deliberate overload fallback, not a small fast-path
            // hit.
            if self.encryption_enabled && !self.hedt.is_large(data.len(), true) {
                self.hedt.record_small();
                self.stats.hedt_small_fast_path.fetch_add(1, Ordering::Relaxed);
            }
            let payload = if self.encryption_enabled {
                let _crypto_guard = self.crypto_send_lock.lock().await;
                match self.crypto.read().encrypt(&data, &header_bytes) {
                    Ok(encrypted) => {
                        self.stats.encrypted_packets.fetch_add(1, Ordering::Relaxed);
                        encrypted
                    }
                    Err(e) => { error!("Encryption failed: {}", e); continue; }
                }
            } else {
                data.to_vec()
            };
            let mut packet = Vec::with_capacity(PacketHeader::SIZE + payload.len());
            packet.extend_from_slice(&header_bytes);
            packet.extend_from_slice(&payload);
            self.send_data_packet(packet, path_id).await;
        }

        // Large packets are released as soon as their crypto jobs finish.
        // There is no FIFO dependency between a large packet and a later
        // small packet, so a completed large job may re-enter the send path
        // immediately while unfinished jobs continue in the background.
        while !large_jobs.is_empty() {
            let mut i = 0;
            let mut progressed = false;
            while i < large_jobs.len() {
                let result = large_jobs[i].0.try_finish();
                if let Some(result) = result {
                    let (_, header, path_id) = large_jobs.swap_remove(i);
                    progressed = true;
                    match result {
                            Ok(encrypted) => {
                                self.stats.hedt_large_completed.fetch_add(1, Ordering::Relaxed);
                                self.stats.encrypted_packets.fetch_add(1, Ordering::Relaxed);
                                let mut packet = Vec::with_capacity(PacketHeader::SIZE + encrypted.len());
                                packet.extend_from_slice(&header.encode());
                                packet.extend_from_slice(&encrypted);
                                self.send_data_packet(packet, path_id).await;
                    }
                    Err(e) => error!("HEDT encryption failed: {}", e),
                }
                    continue;
                }
                i += 1;
            }
            if large_jobs.is_empty() { break; }
            if !progressed {
                let (job, header, path_id) = large_jobs.swap_remove(0);
                match self.hedt.finish(job).await {
                    Ok(encrypted) => {
                        self.stats.hedt_large_completed.fetch_add(1, Ordering::Relaxed);
                        self.stats.encrypted_packets.fetch_add(1, Ordering::Relaxed);
                        let mut packet = Vec::with_capacity(PacketHeader::SIZE + encrypted.len());
                        packet.extend_from_slice(&header.encode());
                        packet.extend_from_slice(&encrypted);
                        self.send_data_packet(packet, path_id).await;
                    }
                    Err(e) => error!("HEDT encryption failed: {}", e),
                }
            }
        }

        let fec_packets = self.sender.get_fec_packets();
        for (fec_packet, path_id) in fec_packets {
            let packet = fec_packet.encode(self.conn_id);
            if let Some(path) = self.sender.multi_path().get_path(path_id) {
                if let Err(e) = path.socket.send_to(&packet, path.remote_addr()).await {
                    error!("Failed to send FEC packet on path {}: {}", path_id, e);
                }
            } else if let Err(e) = self.bus.send_to(&packet, self.remote_addr_value()).await {
                error!("Failed to send FEC packet: {}", e);
            }
        }
    }

    async fn send_data_packet(&self, packet: Vec<u8>, path_id: u32) {
        if let Some(path) = self.sender.multi_path().get_path(path_id) {
            if let Err(e) = path.socket.send_to(&packet, path.remote_addr()).await {
                error!("Failed to send data packet on path {}: {}", path_id, e);
            }
        } else if let Err(e) = self.bus.send_to(&packet, self.remote_addr_value()).await {
            error!("Failed to send data packet: {}", e);
        }
    }

    fn start_send_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(SEND_LOOP_INTERVAL_MS));
            while let Some(conn) = weak.upgrade() {
                if !conn.running.load(Ordering::Relaxed) { break; }
                tokio::select! {
                    _ = interval.tick() => {
                        conn.send_pending_packets().await;
                    }
                    _ = conn.send_notify.notified() => {
                        conn.send_pending_packets().await;
                    }
                }
            }
        });
    }

    fn start_path_probe_loop(self: &Arc<Self>) {
        if !self.multi_path_enabled {
            return;
        }
        
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(PATH_PROBE_INTERVAL_MS));
            
            while let Some(conn) = weak.upgrade() {
                if !conn.running.load(Ordering::Relaxed) { break; }
                interval.tick().await;
                
                let probe = PacketHeader {
                    pkt_type: PacketType::PathProbe as u8,
                    flags: 0,
                    seq: rand::random::<u32>(),
                    ack: 0,
                    conn_id: conn.conn_id,
                    timestamp: 0,
                };
                
                let packet = probe.encode();
                let _ = conn.bus.send_to(&packet, conn.remote_addr_value()).await;
            }
        });
    }
    
    fn start_keepalive_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            loop {
                let Some(conn) = weak.upgrade() else { break; };
                if !conn.running.load(Ordering::Relaxed) { break; }
                let delay = conn.keep_alive_interval.read().clone();
                let Some(delay) = delay else {
                    sleep(Duration::from_secs(1)).await;
                    continue;
                };
                sleep(delay).await;
                if !conn.running.load(Ordering::Relaxed) { break; }
                
                let header = PacketHeader {
                    pkt_type: PacketType::KeepAlive as u8,
                    flags: 0,
                    seq: 0,
                    ack: 0,
                    conn_id: conn.conn_id,
                    timestamp: 0,
                };
                
                let packet = header.encode();
                if conn.bus.send_to(&packet, conn.remote_addr_value()).await.is_ok() {
                    *conn.last_activity.write() = Instant::now();
                }
            }
        });
    }
    
    fn start_cleanup_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            
            while let Some(conn) = weak.upgrade() {
                if !conn.running.load(Ordering::Relaxed) { break; }
                interval.tick().await;
                conn.sender.cleanup_acked();
                if let Some(idle) = *conn.idle_timeout.read() {
                    if conn.last_activity.read().elapsed() >= idle {
                        *conn.state.write() = ConnectionState::Closed;
                        conn.running.store(false, Ordering::Release);
                        break;
                    }
                }
            }
        });
    }
    
    fn start_stats_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(STATS_UPDATE_INTERVAL_MS));
            
            while let Some(conn) = weak.upgrade() {
                if !conn.running.load(Ordering::Relaxed) { break; }
                interval.tick().await;
                let elapsed = Instant::now().duration_since(conn.created_at).as_secs();
                conn.stats.connection_time.store(elapsed, Ordering::Relaxed);
            }
        });
    }
    
    fn start_flow_sync_loop(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            for _ in 0..8 {
                tokio::time::sleep(Duration::from_millis(50)).await;
                let Some(conn) = weak.upgrade() else { return; };
                if !conn.running.load(Ordering::Acquire) { return; }
                if *conn.state.read() == ConnectionState::Established { let _ = conn.send_flow_control().await; }
            }
        });
    }

    pub async fn migrate(&self, new_addr: SocketAddr) -> Result<()> {
        if !self.migration_enabled { return Err(ArkTPError::Protocol("connection migration disabled".into())); }
        if new_addr == self.remote_addr_value() { return Ok(()); }
        let token = rand::random::<u64>();
        *self.path_challenge.write() = Some((token, new_addr));
        let h = PacketHeader::new(PacketType::PathChallenge, 0, self.conn_id);
        let mut packet = Vec::with_capacity(PacketHeader::SIZE + 8);
        packet.extend_from_slice(&h.encode());
        packet.extend_from_slice(&token.to_be_bytes());
        self.bus.send_to(&packet, new_addr).await?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if self.remote_addr_value() == new_addr { return Ok(()); }
            if !self.running.load(Ordering::Acquire) { return Err(ArkTPError::ConnectionClosed); }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if timeout(remaining.min(Duration::from_millis(250)), self.migration_notify.notified()).await.is_err() { continue; }
        }
        *self.path_challenge.write() = None;
        Err(ArkTPError::PathValidationFailed)
    }

    pub async fn add_path(&self, socket: Arc<UdpSocket>) -> Result<u32> {
        if !self.multi_path_enabled { return Err(ArkTPError::Protocol("Multipath not enabled".into())); }
        let path_id = self.sender.add_path(socket, self.remote_addr_value())?;
        let path = self.sender.multi_path().get_path(path_id).ok_or(ArkTPError::NoAvailablePath)?;
        self.receiver.add_path(path.socket.clone(), self.remote_addr_value())?;
        Ok(path_id)
    }

    pub async fn open_stream(self: &Arc<Self>, stream_id: u64) -> Result<ArkTPStream> {
        if stream_id == 0 { return Err(ArkTPError::Protocol("stream 0 is reserved".into())); }
        loop {
            let max = self.peer_max_streams.load(Ordering::Acquire);
            if max == 0 {
                if !self.running.load(Ordering::Acquire) { return Err(ArkTPError::ConnectionClosed); }
                self.flow_notify.notified().await;
                continue;
            }
            if stream_id >= max { return Err(ArkTPError::FlowControlBlocked); }
            if self.recv_streams.read().contains_key(&stream_id) { return Err(ArkTPError::Protocol("stream already exists".into())); }
            let (tx, rx) = flume::bounded(256);
            self.recv_streams.write().insert(stream_id, tx);
            self.local_stream_max_data.insert(stream_id, self.max_stream_data.load(Ordering::Acquire));
            return Ok(ArkTPStream { conn: self.clone(), stream_id, rx, send_closed: Arc::new(AtomicBool::new(false)) });
        }
    }

    pub async fn accept_stream(self: &Arc<Self>) -> Result<ArkTPStream> {
        loop {
            if let Some(id) = self.stream_receivers.read().keys().next().copied() {
                if let Some(rx) = self.stream_receivers.write().remove(&id) {
                    return Ok(ArkTPStream { conn: self.clone(), stream_id: id, rx, send_closed: Arc::new(AtomicBool::new(false)) });
                }
            }
            if !self.running.load(Ordering::Acquire) { return Err(ArkTPError::ConnectionClosed); }
            self.stream_notify.notified().await;
        }
    }

    fn try_recv_now(&self) -> Result<Option<Bytes>> {
        let pending = {
            let mut p = self.recv_pending.write();
            if p.is_empty() { None } else { let v=p.clone(); *p=Bytes::new(); Some(v) }
        };
        if pending.is_some() { return Ok(pending); }
        match self.recv_channel.as_ref().ok_or(ArkTPError::ConnectionClosed)?.try_recv() {
            Ok(v) => Ok(Some(v)),
            Err(flume::TryRecvError::Empty) => Ok(None),
            Err(flume::TryRecvError::Disconnected) => Err(ArkTPError::ConnectionClosed),
        }
    }

    fn peer_stream_limit(&self, stream_id: u64) -> u64 {
        self.peer_stream_max_data.get(&stream_id)
            .map(|v| *v)
            .or_else(|| self.peer_stream_max_data.get(&0).map(|v| *v))
            .or_else(|| { let v = self.peer_max_stream_data.load(Ordering::Acquire); (v != 0).then_some(v) })
            .unwrap_or(0)
    }

    pub async fn send_early_data(&self, data: &[u8]) -> Result<usize> {
        if data.is_empty() { return Ok(0); }
        let max = self.sender.mtu() as usize - PacketHeader::SIZE - TAG_SIZE;
        if data.len() > max { return Err(ArkTPError::PacketTooLarge { max }); }
        if data.len() > 16 * 1024 { return Err(ArkTPError::Protocol("0-RTT early data exceeds 16 KiB anti-amplification limit".into())); }
        self.sender.enqueue_async(Bytes::copy_from_slice(data)).await?;
        self.sent_data.fetch_add(data.len() as u64, Ordering::Release);
        self.send_notify.notify_one();
        Ok(data.len())
    }

    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        self.send_async(data).await
    }

    pub async fn send_async(&self, data: &[u8]) -> Result<usize> {
        if *self.state.read() != ConnectionState::Established || self.send_shutdown.load(Ordering::Acquire) { return Err(ArkTPError::ConnectionClosed); }
        let max_payload = (self.sender.mtu() as usize)
            .saturating_sub(PacketHeader::SIZE + TAG_SIZE);
        if data.len() > max_payload { return Err(ArkTPError::PacketTooLarge { max: max_payload }); }
        loop {
            let guard = self.send_flow_lock.lock().await;
            let used = self.sent_data.load(Ordering::Acquire);
            let limit = self.peer_max_data.load(Ordering::Acquire);
            if used.saturating_add(data.len() as u64) <= limit {
                self.sender.enqueue_async(Bytes::copy_from_slice(data)).await?;
                self.sent_data.fetch_add(data.len() as u64, Ordering::Release);
                drop(guard);
                self.send_notify.notify_one();
                return Ok(data.len());
            }
            drop(guard);
            if !self.running.load(Ordering::Acquire) { return Err(ArkTPError::ConnectionClosed); }
            self.flow_notify.notified().await;
        }
    }

    pub async fn send_all(&self, mut data: &[u8]) -> Result<()> {
        let max = self.sender.mtu() as usize - PacketHeader::SIZE - TAG_SIZE;
        while !data.is_empty() {
            let n = data.len().min(max.max(1));
            self.send_async(&data[..n]).await?;
            data = &data[n..];
        }
        Ok(())
    }

    pub async fn send_batch(&self, data: &[Bytes]) -> Result<Vec<SeqNum>> {
        if *self.state.read() != ConnectionState::Established || self.send_shutdown.load(Ordering::Acquire) { return Err(ArkTPError::ConnectionClosed); }
        let total: usize = data.iter().map(|b| b.len()).sum();
        let _guard = self.send_flow_lock.lock().await;
        let used = self.sent_data.load(Ordering::Acquire);
        if used.saturating_add(total as u64) > self.peer_max_data.load(Ordering::Acquire) {
            return Err(ArkTPError::FlowControlBlocked);
        }
        let max_payload = self.sender.mtu() as usize - PacketHeader::SIZE - TAG_SIZE;
        if data.iter().any(|b| b.len() > max_payload) { return Err(ArkTPError::PacketTooLarge { max: max_payload }); }
        let seqs = self.sender.enqueue_batch(data)?;
        self.sent_data.fetch_add(total as u64, Ordering::Relaxed);
        self.send_notify.notify_one();
        Ok(seqs)
    }

    async fn advertise_window(&self, _consumed: usize) -> Result<()> {
        let used = self.recv_consumed.load(Ordering::Acquire);
        let max = used.saturating_add(self.recv_window_size);
        self.max_data.store(max, Ordering::Release);
        self.send_control_frame(PacketType::MaxData, &max.to_be_bytes()).await?;
        self.window_update_pending.store(false, Ordering::Release);
        Ok(())
    }

    pub async fn recv(&self) -> Result<Bytes> {
        let pending_out = {
            let mut pending = self.recv_pending.write();
            if pending.is_empty() { None } else {
                let out = pending.clone();
                *pending = Bytes::new();
                Some(out)
            }
        };
        if let Some(out) = pending_out {
            self.account_consumed(out.len());
            self.advertise_window(out.len()).await?;
            return Ok(out);
        }
        let channel = self.recv_channel.as_ref().ok_or(ArkTPError::ConnectionClosed)?;
        if self.peer_send_shutdown.load(Ordering::Acquire) && channel.is_empty() { return Err(ArkTPError::ConnectionClosed); }
        match *self.recv_timeout.read() {
            Some(d) => match timeout(d, channel.recv_async()).await {
                Ok(Ok(data)) => { self.account_consumed(data.len()); self.advertise_window(data.len()).await?; Ok(data) },
                Ok(Err(_)) => Err(ArkTPError::ConnectionClosed),
                Err(_) => Err(ArkTPError::Timeout),
            },
            None => match channel.recv_async().await {
                Ok(data) => { self.account_consumed(data.len()); self.advertise_window(data.len()).await?; Ok(data) }
                Err(_) => Err(ArkTPError::ConnectionClosed),
            },
        }
    }

    pub async fn recv_exact(&self, len: usize) -> Result<Bytes> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let chunk = self.recv().await?;
            let need = len - out.len();
            let take = chunk.len().min(need);
            out.extend_from_slice(&chunk[..take]);
            if take < chunk.len() {
                *self.recv_pending.write() = chunk.slice(take..);
            }
        }
        Ok(Bytes::from(out))
    }

    pub fn split(self: &Arc<Self>) -> (SendHalf, RecvHalf) {
        (SendHalf { conn: self.clone() }, RecvHalf { conn: self.clone() })
    }

    pub async fn shutdown_send(&self) -> Result<()> {
        if self.send_shutdown.swap(true, Ordering::AcqRel) { return Ok(()); }
        let h = PacketHeader::new(PacketType::Extension, 0, self.conn_id);
        let ext = ExtensionFrame { kind: 2, value: Vec::new() }.encode();
        let mut p = Vec::with_capacity(PacketHeader::SIZE + ext.len());
        p.extend_from_slice(&h.encode());
        p.extend_from_slice(&ext);
        self.bus.send_to(&p, self.remote_addr_value()).await?;
        Ok(())
    }

    pub async fn close(&self) -> Result<()> {
        let st = *self.state.read();
        if matches!(st, ConnectionState::Closed | ConnectionState::TimeWait) { return Ok(()); }
        *self.state.write() = ConnectionState::FinWait1;
        let mut fin = PacketHeader::new(PacketType::Fin, 0, self.conn_id);
        fin.seq = rand::random::<u32>();
        self.bus.send_to(&fin.encode(), self.remote_addr_value()).await?;
        let deadline = Instant::now() + Duration::from_millis(MAX_RTO_MS * 2);
        while Instant::now() < deadline {
            if matches!(*self.state.read(), ConnectionState::TimeWait | ConnectionState::Closed) { break; }
            sleep(Duration::from_millis(10)).await;
        }
        if *self.state.read() != ConnectionState::Closed {
            *self.state.write() = ConnectionState::TimeWait;
            sleep(Duration::from_millis(MAX_RTO_MS)).await;
            *self.state.write() = ConnectionState::Closed;
        }
        self.running.store(false, Ordering::Release);
        Ok(())
    }

    pub async fn key_update(&self) -> Result<()> {
        let _guard = self.key_update_lock.lock().await;
        self.hedt.drain().await;
        let _crypto_guard = self.crypto_send_lock.lock().await;
        let phase = self.key_phase.fetch_add(1, Ordering::AcqRel) + 1;
        let old_key = self.get_session_key().ok_or(ArkTPError::KeyExchangeFailed("no session key".into()))?;
        let new_key = old_key.derive_session_key(self.conn_id ^ phase, b"ArkTP-key-update")?;
        let h = PacketHeader::new(PacketType::KeyUpdate, 0, self.conn_id);
        let payload = self.crypto.read().encrypt(&phase.to_be_bytes(), &h.encode())?;
        let mut packet = Vec::with_capacity(PacketHeader::SIZE + payload.len());
        packet.extend_from_slice(&h.encode());
        packet.extend_from_slice(&payload);
        self.bus.send_to(&packet, self.remote_addr_value()).await?;
        let old_ctx = self.crypto.read().clone();
        *self.previous_crypto.write() = Some(old_ctx);
        self.crypto.write().rotate(&new_key);
        Ok(())
    }

    pub(crate) fn install_session_key(&self, key: EncryptionKey) -> Result<()> {
        *self.crypto.write() = CryptoContext::new(&key);
        *self.previous_crypto.write() = None;
        Ok(())
    }

    pub(crate) fn verify_session_ticket(ticket: &SessionTicket) -> bool {
        if !ticket.is_well_formed() { return false; }
        let mut mac = Hmac::<Sha256>::new_from_slice(session_ticket_secret()).expect("valid HMAC key");
        mac.update(b"ArkTP-session-ticket-v1");
        mac.update(&ticket.expires_at_ms.to_be_bytes());
        mac.update(&ticket.token[..ticket.token.len().saturating_sub(16)]);
        let expected = mac.finalize().into_bytes();
        ticket.token[ticket.token.len().saturating_sub(16)..] == expected[..16]
    }

    pub fn export_session_ticket(&self, lifetime: Duration) -> Result<SessionTicket> {
        cleanup_session_tickets();
        if session_ticket_store().len() >= 100_000 { return Err(ArkTPError::ResourceExhausted); }
        let key = self.get_session_key().ok_or(ArkTPError::SessionResumptionFailed)?;
        let expiry = now_ms().saturating_add(lifetime.as_millis() as u64);
        let mut token = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut token);
        let mut mac = Hmac::<Sha256>::new_from_slice(session_ticket_secret()).expect("valid HMAC key");
        mac.update(b"ArkTP-session-ticket-v1");
        mac.update(&expiry.to_be_bytes());
        mac.update(&token);
        token.extend_from_slice(&mac.finalize().into_bytes()[..16]);
        session_ticket_store().insert(token.clone(), (key, expiry));
        Ok(SessionTicket { token, expires_at_ms: expiry })
    }

    pub fn consume_session_ticket(ticket: &SessionTicket) -> Result<EncryptionKey> {
        cleanup_session_tickets();
        if !Self::verify_session_ticket(ticket) { return Err(ArkTPError::SessionResumptionFailed); }
        let Some((_, (key, expiry))) = session_ticket_store().remove(&ticket.token) else {
            return Err(ArkTPError::SessionResumptionFailed);
        };
        if expiry < now_ms() || expiry != ticket.expires_at_ms { return Err(ArkTPError::SessionResumptionFailed); }
        Ok(key)
    }

    pub fn resume_from_ticket(ticket: &SessionTicket) -> Result<EncryptionKey> {
        cleanup_session_tickets();
        if !ticket.is_well_formed() { return Err(ArkTPError::SessionResumptionFailed); }
        let Some(entry) = session_ticket_store().get(&ticket.token) else { return Err(ArkTPError::SessionResumptionFailed); };
        if entry.1 < now_ms() || entry.1 != ticket.expires_at_ms { return Err(ArkTPError::SessionResumptionFailed); }
        Ok(entry.0.clone())
    }

    pub async fn probe_mtu(&self, candidate: u16) -> Result<bool> {
        if candidate < 576 { return Err(ArkTPError::InvalidConfig("MTU must be >= 576".into())); }
        if candidate <= self.sender.mtu() { return Ok(true); }
        let token = rand::random::<u64>();
        let notify = Arc::new(Notify::new());
        self.pmtu_probes.insert(token, (candidate, notify.clone()));
        let h = PacketHeader::new(PacketType::MtuProbe, token as u32, self.conn_id);
        let mut packet = Vec::with_capacity(candidate as usize);
        packet.extend_from_slice(&h.encode());
        packet.extend_from_slice(&token.to_be_bytes());
        packet.resize(candidate as usize, 0);
        match self.bus.send_to(&packet, self.remote_addr_value()).await {
            Ok(_) => {
                if timeout(Duration::from_secs(1), notify.notified()).await.is_ok() { Ok(self.sender.mtu() >= candidate) }
                else { self.pmtu_probes.remove(&token); Ok(false) }
            }
            Err(ArkTPError::Io(e)) => {
                self.pmtu_probes.remove(&token);
                if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) || e.raw_os_error() == Some(10040) { Ok(false) } else { Err(ArkTPError::Io(e)) }
            }
            Err(e) => { self.pmtu_probes.remove(&token); Err(e) }
        }
    }

    pub fn update_runtime_config(&self, config: &ArkTPConfig) -> Result<()> {
        config.validate()?;
        *self.recv_timeout.write() = config.recv_timeout;
        *self.idle_timeout.write() = config.idle_timeout;
        *self.keep_alive_interval.write() = config.keep_alive_interval;
        self.sender.set_mtu(config.mtu)?;
        Ok(())
    }

    pub fn stats(&self) -> Arc<ArkTPStats> {
        self.stats.clone()
    }
    
    #[inline]
    fn account_consumed(&self, n: usize) {
        self.recv_consumed.fetch_add(n as u64, Ordering::AcqRel);
        self.window_update_pending.store(true, Ordering::Release);
        self.flow_notify.notify_waiters();
    }

    pub(crate) fn packet_bus(&self) -> Arc<PacketBus> { self.bus.clone() }
    pub(crate) fn set_state(&self, state: ConnectionState) { *self.state.write() = state; }
    pub(crate) fn is_running(&self) -> bool { self.running.load(Ordering::Acquire) }

    fn remote_addr_value(&self) -> SocketAddr { *self.remote_addr.read() }
    pub fn remote_addr(&self) -> SocketAddr { self.remote_addr_value() }
    pub fn update_remote_addr(&self, addr: SocketAddr) { *self.remote_addr.write() = addr; }
    
    pub fn conn_id(&self) -> u64 {
        self.conn_id
    }
    
    pub async fn state(&self) -> ConnectionState {
        *self.state.read()
    }
    
    pub async fn path_count(&self) -> usize {
        self.sender.multi_path().path_count()
    }
    
    pub async fn path_stats(&self) -> Vec<(u32, f64, Duration, f64)> {
        self.sender.multi_path().paths().iter().map(|p| {
            (p.id, p.quality.read().score, p.quality.read().rtt, p.quality.read().loss_rate)
        }).collect()
    }
    
    pub fn get_session_key(&self) -> Option<EncryptionKey> {
        self.key_exchange_manager.get_session_key()
    }
    
    pub fn get_key_exchange_method(&self) -> Option<KeyExchangeMethod> {
        self.key_exchange_manager.get_negotiated_method()
    }
    
    pub fn get_nat_traversal(&self) -> Option<Arc<NatTraversal>> {
        self.nat_traversal.clone()
    }
    
    pub fn get_smart_cache(&self) -> Arc<SmartCache> {
        self.smart_cache.clone()
    }
    
    pub fn get_parallel_pipeline(&self) -> Arc<ParallelPipeline> {
        self.parallel_pipeline.clone()
    }
}

