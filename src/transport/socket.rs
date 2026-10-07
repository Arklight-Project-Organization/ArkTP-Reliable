use std::{
    net::SocketAddr,
    sync::{Arc, Weak, OnceLock},
};
use tokio::net::UdpSocket;
use tokio::sync::broadcast;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use bytes::Bytes;

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use rayon::prelude::*;

use crate::*;

// ==================== Shared UDP packet bus ====================
/// Tokio permits only one reliable receiver loop per UDP socket. ArkTP therefore
/// demultiplexes datagrams once and broadcasts them to connections. This also
/// makes listeners and multiple concurrent connections safe on one port.
static BUS_REGISTRY: OnceLock<dashmap::DashMap<SocketAddr, Weak<PacketBus>>> = OnceLock::new();



static RETRY_SECRET: OnceLock<[u8; 32]> = OnceLock::new();
fn retry_secret() -> &'static [u8; 32] {
    RETRY_SECRET.get_or_init(rand::random)
}
pub(crate) fn make_retry_token(src: SocketAddr, conn_id: u64) -> Vec<u8> {
    let bucket = now_ms() / 10_000;
    let mut mac = Hmac::<Sha256>::new_from_slice(retry_secret()).expect("valid HMAC key");
    mac.update(src.to_string().as_bytes());
    mac.update(&conn_id.to_be_bytes());
    mac.update(&bucket.to_be_bytes());
    mac.finalize().into_bytes().to_vec()
}
pub(crate) fn verify_retry_token(token: &[u8], src: SocketAddr, conn_id: u64) -> bool {
    for bucket in [now_ms()/10_000, (now_ms()/10_000).saturating_sub(1)] {
        let mut mac = Hmac::<Sha256>::new_from_slice(retry_secret()).expect("valid HMAC key");
        mac.update(src.to_string().as_bytes());
        mac.update(&conn_id.to_be_bytes());
        mac.update(&bucket.to_be_bytes());
        if mac.verify_slice(token).is_ok() { return true; }
    }
    false
}

pub(crate) struct PacketBus {
    socket: Arc<UdpSocket>,
    tx: broadcast::Sender<(Bytes, SocketAddr)>,
    pending: Arc<dashmap::DashMap<u64, std::collections::VecDeque<(Bytes, SocketAddr, std::time::Instant)>>>,
    active: Arc<dashmap::DashMap<u64, ()>>,
}
impl PacketBus {
    pub(crate) fn new(socket: Arc<UdpSocket>) -> Arc<Self> {
        let addr = socket.local_addr().ok();
        if let Some(addr) = addr {
            if let Some(bus) = BUS_REGISTRY.get_or_init(dashmap::DashMap::new).get(&addr).and_then(|w| w.upgrade()) {
                return bus;
            }
        }
        let (tx, _) = broadcast::channel(4096);
        let bus = Arc::new(Self { socket: socket.clone(), tx: tx.clone(), pending: Arc::new(dashmap::DashMap::new()), active: Arc::new(dashmap::DashMap::new()) });
        if let Some(addr) = addr {
            BUS_REGISTRY.get_or_init(dashmap::DashMap::new).insert(addr, Arc::downgrade(&bus));
        }
        let reader_socket = socket.clone();
        let reader_tx = tx.clone();
        let reader_pending = bus.pending.clone();
        let reader_active = bus.active.clone();
        let reader_bus = Arc::downgrade(&bus);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_ENCRYPTED_PACKET_SIZE];
            loop {
                if reader_bus.upgrade().is_none() { break; }
                match reader_socket.recv_from(&mut buf).await {
                    Ok((n, src)) => {
                        let bytes = Bytes::copy_from_slice(&buf[..n]);
                        if bytes.len() >= PacketHeader::SIZE {
                            if let Some(h) = PacketHeader::decode_any(&bytes) {
                                if reader_active.contains_key(&h.conn_id) { let _ = reader_tx.send((bytes, src)); continue; }
                                if reader_pending.len() >= 8192 && !reader_pending.contains_key(&h.conn_id) {
                                    if let Some(entry) = reader_pending.iter().next() { let id = *entry.key(); drop(entry); reader_pending.remove(&id); }
                                }
                                let mut q = reader_pending.entry(h.conn_id).or_insert_with(std::collections::VecDeque::new);
                                let now = std::time::Instant::now();
                                while q.front().map(|(_, _, t)| now.duration_since(*t) > std::time::Duration::from_secs(2)).unwrap_or(false) { q.pop_front(); }
                                q.push_back((bytes.clone(), src, now));
                                while q.len() > 32 { q.pop_front(); }
                            }
                        }
                        let _ = reader_tx.send((bytes, src));
                    }
                    Err(_) => break,
                }
            }
        });
        bus
    }
    pub(crate) fn register_conn(&self, conn_id: u64) { self.active.insert(conn_id, ()); }
    pub(crate) fn unregister_conn(&self, conn_id: u64) { self.active.remove(&conn_id); self.pending.remove(&conn_id); }
    pub(crate) fn subscribe(&self) -> broadcast::Receiver<(Bytes, SocketAddr)> { self.tx.subscribe() }
    pub(crate) fn clear_pending(&self, conn_id: u64) { let _ = self.pending.remove(&conn_id); }
    pub(crate) fn take_pending(&self, conn_id: u64) -> Vec<(Bytes, SocketAddr)> {
        let Some((_, mut q)) = self.pending.remove(&conn_id) else { return Vec::new(); };
        let now = std::time::Instant::now();
        q.retain(|(_, _, t)| now.duration_since(*t) <= std::time::Duration::from_secs(2));
        q.into_iter().map(|(b,a,_)| (b,a)).collect()
    }
    pub(crate) fn inject(&self, data: Bytes, src: SocketAddr) { let _ = self.tx.send((data, src)); }
    pub(crate) fn socket(&self) -> Arc<UdpSocket> { self.socket.clone() }
    pub(crate) async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize> {
        Ok(self.socket.send_to(data, addr).await?)
    }
}
struct ListenerCore {
    bus: Arc<PacketBus>,
    config: ArkTPConfigHandle,
    accept_rx: tokio::sync::Mutex<broadcast::Receiver<(Bytes, SocketAddr)>>,
    pending: std::sync::atomic::AtomicUsize,
    seen: dashmap::DashMap<u64, std::time::Instant>,
}
impl ListenerCore {
    fn reserve_pending(&self, max: usize) -> bool {
        self.pending.fetch_update(std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire, |n| {
            (n < max).then_some(n + 1)
        }).is_ok()
    }
    fn release_pending(&self) { self.pending.fetch_sub(1, std::sync::atomic::Ordering::AcqRel); }
    fn cleanup_seen(&self) {
        let now = std::time::Instant::now();
        self.seen.retain(|_, seen_at| now.duration_since(*seen_at) < std::time::Duration::from_secs(60));
    }
}

pub struct ArkTPListener {
    core: Arc<ListenerCore>,
}
impl Clone for ArkTPListener { fn clone(&self) -> Self { Self { core: self.core.clone() } } }
impl ArkTPListener {
    pub async fn accept(&self) -> Result<Arc<ArkTPConnection>> {
        loop {
            self.core.cleanup_seen();
            let (packet, src) = {
                let mut rx = self.core.accept_rx.lock().await;
                rx.recv().await.map_err(|_| ArkTPError::ListenerClosed)?
            };
            if packet.len() < PacketHeader::SIZE { continue; }
            let Some(header) = PacketHeader::decode_any(&packet) else { continue; };
            if PacketHeader::version_from_wire(packet[1]) != PacketHeader::VERSION {
                let h = PacketHeader::new(PacketType::Extension, 0, header.conn_id);
                let ext = ExtensionFrame { kind: 1, value: vec![PacketHeader::VERSION] }.encode();
                let mut out = Vec::with_capacity(PacketHeader::SIZE + ext.len());
                out.extend_from_slice(&h.encode());
                out.extend_from_slice(&ext);
                let _ = self.core.bus.send_to(&out, src).await;
                continue;
            }

            if PacketType::from(header.pkt_type) == PacketType::NewToken {
                if !self.core.config.get().enable_session_resumption { continue; }
                let Some(ticket) = SessionTicket::decode(&packet[PacketHeader::SIZE..]) else { continue; };
                if header.conn_id == 0 || !ticket.is_well_formed() || !ArkTPConnection::verify_session_ticket(&ticket) {
                    let _ = self.core.bus.send_to(&PacketHeader::new(PacketType::Reset, 0, header.conn_id).encode(), src).await;
                    continue;
                }
                if self.core.seen.contains_key(&header.conn_id) { continue; }
                if !self.core.reserve_pending(self.core.config.get().max_pending_connections) { return Err(ArkTPError::PendingConnectionsFull); }
                self.core.seen.insert(header.conn_id, std::time::Instant::now());
                let result = ArkTPConnection::accept_resumed_with_bus(
                    self.core.bus.clone(), src, header.conn_id, self.core.config.get(), &ticket
                ).await;
                self.core.release_pending();
                match result {
                    Ok(conn) => return Ok(conn),
                    Err(_) => { self.core.seen.remove(&header.conn_id); continue; }
                }
            }

            if header.conn_id == 0 || PacketType::from(header.pkt_type) != PacketType::KeyExchange { continue; }
            let Some(ke) = KeyExchangeMessage::decode(&packet[PacketHeader::SIZE..]) else { continue; };
            if !verify_retry_token(&ke.retry_token, src, header.conn_id) {
                let retry = make_retry_token(src, header.conn_id);
                let h = PacketHeader::new(PacketType::Retry, 0, header.conn_id);
                let mut out = Vec::with_capacity(PacketHeader::SIZE + retry.len());
                out.extend_from_slice(&h.encode());
                out.extend_from_slice(&retry);
                let _ = self.core.bus.send_to(&out, src).await;
                continue;
            }
            if self.core.seen.contains_key(&header.conn_id) { continue; }
            let config = self.core.config.get();
            if !self.core.reserve_pending(config.max_pending_connections) { continue; }
            self.core.seen.insert(header.conn_id, std::time::Instant::now());
            let result = ArkTPConnection::accept_with_bus(
                self.core.bus.clone(), src, header.conn_id, config, packet.clone()
            ).await;
            self.core.release_pending();
            match result {
                Ok(c) => return Ok(c),
                Err(e) => {
                    self.core.seen.remove(&header.conn_id);
                    let _ = self.core.bus.send_to(&PacketHeader::new(PacketType::Reset, 0, header.conn_id).encode(), src).await;
                    if matches!(e, ArkTPError::AuthenticationFailed | ArkTPError::HandshakeFailed | ArkTPError::ReplayDetected) { continue; }
                }
            }
        }
    }
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> { self.core.bus.socket.local_addr() }
}

// ==================== 简单Socket包装 ====================
pub struct ArkTPSocket {
    socket: Arc<UdpSocket>,
    bus: Arc<PacketBus>,
    conn: Option<Arc<ArkTPConnection>>,
    config: ArkTPConfig,
    config_handle: ArkTPConfigHandle,
    aggregator: Option<Arc<ConnectionAggregator>>,
    listener: Arc<ListenerCore>,
}

impl ArkTPSocket {
    /// Bind using the default reliable profile.
    pub async fn bind(addr: &str) -> Result<Self> {
        Self::bind_with_config(addr, ArkTPConfig::default()).await
    }

    /// Bind once and keep one PacketBus for the entire endpoint lifetime.
    /// `socket2` is used here so modern UDP deployments can opt into
    /// reuse/dual-stack behavior without rebuilding the transport.
    pub async fn bind_with_config(addr: &str, config: ArkTPConfig) -> Result<Self> {
        config.validate()?;
        let parsed: SocketAddr = addr.parse()
            .map_err(|_| ArkTPError::Protocol("Invalid bind address".into()))?;
        let domain = if parsed.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        };
        let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        sock.set_reuse_address(true)?;
        sock.set_send_buffer_size(config.udp_send_buffer_size)?;
        sock.set_recv_buffer_size(config.udp_receive_buffer_size)?;
        #[cfg(unix)]
        {
            // Reuse-port is deliberately best-effort. Platforms differ and
            // failure must not make a perfectly valid UDP listener unusable.
            let _ = sock.set_reuse_port(true);
        }
        if parsed.is_ipv6() {
            let _ = sock.set_only_v6(false);
        }
        sock.bind(&parsed.into())?;
        sock.set_nonblocking(true)?;
        let socket = UdpSocket::from_std(sock.into())?;
        let socket = Arc::new(socket);
        let bus = PacketBus::new(socket.clone());
        let config_handle = ArkTPConfigHandle::new(config.clone())?;
        let listener = Arc::new(ListenerCore {
            bus: bus.clone(),
            config: config_handle.clone(),
            accept_rx: tokio::sync::Mutex::new(bus.subscribe()),
            pending: std::sync::atomic::AtomicUsize::new(0),
            seen: dashmap::DashMap::new(),
        });
        Ok(Self {
            socket,
            bus,
            conn: None,
            config,
            config_handle,
            aggregator: None,
            listener,
        })
    }
    
    pub async fn accept(&self) -> Result<Arc<ArkTPConnection>> { ArkTPListener { core: self.listener.clone() }.accept().await }

    pub fn listen(&self) -> Result<ArkTPListener> {
        self.config.validate()?;
        Ok(ArkTPListener { core: self.listener.clone() })
    }

    async fn connect_0rtt_inner(&mut self, addr: &str, ticket: &SessionTicket, early_data: Option<&[u8]>) -> Result<()> {
        let cfg = self.config_handle.get();
        if !cfg.enable_session_resumption { return Err(ArkTPError::SessionResumptionFailed); }
        if early_data.is_some() && !cfg.enable_0rtt { return Err(ArkTPError::InvalidConfig("0-RTT is disabled".into())); }
        let remote_addr: SocketAddr = addr.parse().map_err(|_| ArkTPError::Protocol("Invalid address".into()))?;
        let key = match ArkTPConnection::resume_from_ticket(ticket) {
            Ok(key) => key,
            Err(_) if early_data.is_none() => return self.connect(addr).await,
            Err(e) => return Err(e),
        };
        let mut config = self.config_handle.get();
        config.encryption_key = Some(key.clone());
        config.key_exchange_method = KeyExchangeMethod::PreSharedKey;
        config.authentication = AuthenticationConfig::PreSharedKey;
        let conn_id = rand::random::<u64>().max(1);
        let conn = ArkTPConnection::connect_with_id_and_bus(self.socket.clone(), self.bus.clone(), remote_addr, conn_id, config, false).await?;
        conn.install_session_key(key)?;
        conn.set_state(ConnectionState::KeyExchanging);
        let h = PacketHeader::new(PacketType::NewToken, 0, conn_id);
        let ticket_data = ticket.encode();
        let mut p = Vec::with_capacity(PacketHeader::SIZE + ticket_data.len());
        p.extend_from_slice(&h.encode());
        p.extend_from_slice(&ticket_data);
        conn.packet_bus().send_to(&p, remote_addr).await?;
        if let Some(data) = early_data { conn.send_early_data(data).await?; }
        let deadline = tokio::time::Instant::now() + self.config_handle.get().handshake_timeout;
        while tokio::time::Instant::now() < deadline {
            if conn.state().await == ConnectionState::Established { self.conn = Some(conn); return Ok(()); }
            if !conn.is_running() { break; }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let _ = conn.close().await;
        if early_data.is_none() {
            return self.connect(addr).await;
        }
        Err(ArkTPError::SessionResumptionFailed)
    }

    pub async fn connect_0rtt(&mut self, addr: &str, ticket: &SessionTicket) -> Result<()> {
        if !self.config_handle.get().enable_0rtt { return Err(ArkTPError::InvalidConfig("0-RTT is disabled".into())); }
        self.connect_0rtt_inner(addr, ticket, None).await
    }

    pub async fn connect_0rtt_with_data(&mut self, addr: &str, ticket: &SessionTicket, data: &[u8]) -> Result<()> {
        self.connect_0rtt_inner(addr, ticket, Some(data)).await
    }

    pub async fn connect_with_ticket(&mut self, addr: &str, ticket: &SessionTicket) -> Result<()> {
        self.connect_0rtt_inner(addr, ticket, None).await
    }

    pub async fn connect(&mut self, addr: &str) -> Result<()> {
        let remote_addr: SocketAddr = addr.parse()
            .map_err(|_| ArkTPError::Protocol("Invalid address".to_string()))?;
        
        let conn = ArkTPConnection::connect_with_bus(
            self.socket.clone(), self.bus.clone(), remote_addr, self.config_handle.get(),
        ).await?;
        
        self.conn = Some(conn);
        Ok(())
    }
    
    pub async fn connect_aggregated(&mut self, addrs: &[String]) -> Result<()> {
        if !self.config.enable_connection_aggregation {
            return Err(ArkTPError::Protocol("Connection aggregation not enabled".to_string()));
        }
        
        let aggregator = Arc::new(ConnectionAggregator::new());
        
        for addr in addrs {
            let remote_addr: SocketAddr = addr.parse()
                .map_err(|_| ArkTPError::Protocol("Invalid address".to_string()))?;
            
            let conn = ArkTPConnection::connect_with_bus(
                self.socket.clone(), self.bus.clone(), remote_addr, self.config_handle.get(),
            ).await?;
            
            aggregator.add_connection(conn)?;
        }
        
        let agg_clone = aggregator.clone();
        agg_clone.start_health_check_loop();
        
        self.aggregator = Some(aggregator);
        Ok(())
    }
    
    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        if let Some(aggregator) = &self.aggregator {
            aggregator.send(data).await
        } else if let Some(conn) = &self.conn {
            conn.send(data).await
        } else {
            Err(ArkTPError::ConnectionClosed)
        }
    }
    
    pub async fn send_batch(&self, data: &[Bytes]) -> Result<Vec<SeqNum>> {
        if let Some(aggregator) = &self.aggregator {
            aggregator.send_batch(data).await
        } else if let Some(conn) = &self.conn {
            conn.send_batch(data).await
        } else {
            Err(ArkTPError::ConnectionClosed)
        }
    }
    
    pub async fn recv(&self) -> Result<Bytes> {
        if let Some(aggregator) = &self.aggregator {
            aggregator.recv_any().await
        } else if let Some(conn) = &self.conn {
            conn.recv().await
        } else {
            Err(ArkTPError::ConnectionClosed)
        }
    }
    
    pub fn with_config(mut self, config: ArkTPConfig) -> Self {
        let _ = self.config_handle.reload(config.clone());
        self.config = config;
        self
    }

    pub fn config(&self) -> ArkTPConfig { self.config_handle.get() }
    pub fn reload_config(&mut self, config: ArkTPConfig) -> Result<()> {
        config.validate()?;
        self.config_handle.reload(config.clone())?;
        if let Some(conn) = &self.conn { conn.update_runtime_config(&config)?; }
        self.config = config;
        Ok(())
    }
    
    pub async fn open_stream(&self, stream_id: u64) -> Result<ArkTPStream> {
        self.conn.as_ref().ok_or(ArkTPError::ConnectionClosed)?.open_stream(stream_id).await
    }

    pub async fn accept_stream(&self) -> Result<ArkTPStream> {
        self.conn.as_ref().ok_or(ArkTPError::ConnectionClosed)?.accept_stream().await
    }

    pub fn split(&self) -> Result<(SendHalf, RecvHalf)> {
        self.conn.as_ref().map(|c| c.split()).ok_or(ArkTPError::ConnectionClosed)
    }

    /// Explicitly rotate the application key. This is useful for long-lived
    /// sessions and for applications that want a deterministic rotation
    /// boundary instead of waiting for the automatic nonce threshold.
    pub async fn migrate(&self, new_addr: SocketAddr) -> Result<()> {
        self.conn.as_ref().ok_or(ArkTPError::ConnectionClosed)?.migrate(new_addr).await
    }

    pub async fn key_update(&self) -> Result<()> {
        self.conn.as_ref().ok_or(ArkTPError::ConnectionClosed)?.key_update().await
    }

    pub fn stats(&self) -> Option<Arc<ArkTPStats>> {
        self.conn.as_ref().map(|c| c.stats())
    }
    
    pub async fn close(&self) -> Result<()> {
        if let Some(conn) = &self.conn {
            conn.close().await?;
        }
        Ok(())
    }
    
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    
    pub async fn probe_mtu(&self, candidate: u16) -> Result<bool> {
        self.conn.as_ref().ok_or(ArkTPError::ConnectionClosed)?.probe_mtu(candidate).await
    }

    pub async fn add_path(&self, socket: Arc<UdpSocket>) -> Result<u32> {
        if let Some(conn) = &self.conn {
            conn.add_path(socket).await
        } else {
            Err(ArkTPError::ConnectionClosed)
        }
    }
    
    pub fn get_session_key(&self) -> Option<EncryptionKey> {
        self.conn.as_ref().and_then(|c| c.get_session_key())
    }
    
    pub fn get_key_exchange_method(&self) -> Option<KeyExchangeMethod> {
        self.conn.as_ref().and_then(|c| c.get_key_exchange_method())
    }
    
    pub fn get_nat_traversal(&self) -> Option<Arc<NatTraversal>> {
        self.conn.as_ref().and_then(|c| c.get_nat_traversal())
    }
    
    pub fn get_aggregator(&self) -> Option<Arc<ConnectionAggregator>> {
        self.aggregator.clone()
    }
}

