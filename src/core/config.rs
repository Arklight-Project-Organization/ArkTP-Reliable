use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};

// 加密相关

// 后量子密码学

// 性能优化

use crate::*;


fn default_recv_timeout() -> Option<Duration> { Some(Duration::from_secs(30)) }
fn default_handshake_timeout() -> Duration { Duration::from_secs(5) }

mod duration_millis_required {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S: Serializer>(value: &Duration, s: S) -> Result<S::Ok, S::Error> { s.serialize_u64(value.as_millis() as u64) }
    pub fn deserialize<'de, D>(d: D) -> Result<Duration, D::Error> where D: Deserializer<'de> {
        Ok(Duration::from_millis(u64::deserialize(d)?))
    }
}
mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;
    pub fn serialize<S>(value: &Option<Duration>, s: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        match value { Some(d) => s.serialize_some(&d.as_millis()), None => s.serialize_none() }
    }
    pub fn deserialize<'de, D>(d: D) -> Result<Option<Duration>, D::Error>
    where D: Deserializer<'de> {
        let v = Option::<u64>::deserialize(d)?;
        Ok(v.map(Duration::from_millis))
    }
}


// ==================== 配置 ====================

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AuthenticationConfig {
    None,
    /// HMAC-based mutual authentication. The key is never put on the wire.
    PreSharedKey,
    /// Verify a pinned application identity/fingerprint.
    PinnedPublicKey { fingerprint: Vec<u8> },
    /// Record the first peer fingerprint and require it on subsequent handshakes.
    Tofu,
}
impl Default for AuthenticationConfig { fn default() -> Self { Self::None } }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CongestionAlgorithm {
    Reno,
    Bbr,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ArkTPConfig {
    pub mtu: u16,
    pub max_retries: u32,
    pub send_buffer_size: usize,
    pub receive_buffer_size: usize,
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub max_streams: u64,
    pub congestion_control: CongestionAlgorithm,
    pub fec_enabled: bool,
    pub fec_group_size: usize,
    #[serde(skip)]
    pub stats: Option<Arc<ArkTPStats>>,
    pub aggressive_retransmit: bool,
    pub enable_multipath: bool,
    pub max_paths: usize,
    pub encryption_key: Option<EncryptionKey>,
    pub enable_encryption: bool,
    pub key_exchange_method: KeyExchangeMethod,
    pub auto_generate_key: bool,
    pub enable_post_quantum: bool,
    pub enable_nat_traversal: bool,
    pub enable_parallel_pipeline: bool,
    pub enable_smart_cache: bool,
    pub enable_connection_aggregation: bool,
    pub enable_smart_fec: bool,
    /// Maximum time recv() waits. None means wait forever.
    #[serde(with = "duration_millis", default = "default_recv_timeout")]
    pub recv_timeout: Option<Duration>,
    /// Time allowed for the handshake.
    #[serde(with = "duration_millis_required", default = "default_handshake_timeout")]
    pub handshake_timeout: Duration,
    /// Maximum number of pending inbound handshakes.
    pub max_pending_connections: usize,
    /// Enable connection migration/path validation.
    pub enable_connection_migration: bool,
    /// Enable session tickets / PSK resumption.
    pub enable_session_resumption: bool,
    /// Allow 0-RTT application data after a valid ticket.
    pub enable_0rtt: bool,
    /// Initial packet payload MTU. DPLPMTUD can lower/raise this value.
    pub enable_pmtud: bool,
    /// Enable ECN-capable packets and ACK ECN counters.
    pub enable_ecn: bool,
    /// Keep the UDP socket queues large enough for high-BDP paths.
    pub udp_send_buffer_size: usize,
    pub udp_receive_buffer_size: usize,
    /// Maximum datagrams emitted by one scheduler turn.
    pub max_batch_packets: usize,
    /// Enable congestion-controller pacing instead of timer-only bursts.
    pub enable_pacing: bool,
    /// High-Efficiency Data Transmission: offload large-packet encryption so small packets are not delayed by crypto work.
    pub hedt_enabled: bool,
    /// HEDT classifies packets by final encoded size. Default: 1380 bytes.
    pub hedt_threshold: usize,
    /// Maximum concurrent large-packet encryption jobs.
    pub hedt_max_inflight: usize,
    /// Idle connection timeout. `None` disables idle expiry.
    #[serde(with = "duration_millis", default)]
    pub idle_timeout: Option<Duration>,
    /// Optional keep-alive probe interval.
    #[serde(with = "duration_millis", default)]
    pub keep_alive_interval: Option<Duration>,
    /// Maximum amount of user-space receive reassembly state per connection.
    pub max_reassembly_bytes: usize,
    /// Application identity verification mode.
    pub authentication: AuthenticationConfig,
    /// Optional runtime congestion algorithm plugin.
    #[serde(skip)]
    pub congestion_plugin: Option<std::sync::Arc<dyn CongestionControl>>,
    /// Optional path scheduler plugin.
    #[serde(skip)]
    pub path_scheduler_plugin: Option<std::sync::Arc<dyn PathSchedulerPlugin>>,
    /// Optional FEC plugin.
    #[serde(skip)]
    pub fec_plugin: Option<std::sync::Arc<dyn FecPlugin>>,
}

impl std::fmt::Debug for ArkTPConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArkTPConfig")
            .field("mtu", &self.mtu)
            .field("max_retries", &self.max_retries)
            .field("send_buffer_size", &self.send_buffer_size)
            .field("receive_buffer_size", &self.receive_buffer_size)
            .field("initial_max_data", &self.initial_max_data)
            .field("initial_max_stream_data", &self.initial_max_stream_data)
            .field("max_streams", &self.max_streams)
            .field("congestion_control", &self.congestion_control)
            .field("fec_enabled", &self.fec_enabled)
            .field("enable_encryption", &self.enable_encryption)
            .field("key_exchange_method", &self.key_exchange_method)
            .field("authentication", &self.authentication)
            .field("recv_timeout", &self.recv_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .field("max_pending_connections", &self.max_pending_connections)
            .field("enable_connection_migration", &self.enable_connection_migration)
            .field("enable_session_resumption", &self.enable_session_resumption)
            .field("enable_0rtt", &self.enable_0rtt)
            .field("enable_pmtud", &self.enable_pmtud)
            .field("enable_ecn", &self.enable_ecn)
            .field("udp_send_buffer_size", &self.udp_send_buffer_size)
            .field("udp_receive_buffer_size", &self.udp_receive_buffer_size)
            .field("max_batch_packets", &self.max_batch_packets)
            .field("enable_pacing", &self.enable_pacing)
            .field("hedt_enabled", &self.hedt_enabled)
            .field("hedt_threshold", &self.hedt_threshold)
            .field("hedt_max_inflight", &self.hedt_max_inflight)
            .field("idle_timeout", &self.idle_timeout)
            .field("keep_alive_interval", &self.keep_alive_interval)
            .field("max_reassembly_bytes", &self.max_reassembly_bytes)
            .field("has_congestion_plugin", &self.congestion_plugin.is_some())
            .field("has_path_scheduler_plugin", &self.path_scheduler_plugin.is_some())
            .field("has_fec_plugin", &self.fec_plugin.is_some())
            .finish()
    }
}

impl Default for ArkTPConfig {
    fn default() -> Self {
        Self {
            mtu: DEFAULT_MTU,
            max_retries: MAX_RETRIES,
            send_buffer_size: 4096,
            receive_buffer_size: 4096,
            initial_max_data: 64 * 1024 * 1024,
            initial_max_stream_data: 16 * 1024 * 1024,
            max_streams: 1024,
            congestion_control: CongestionAlgorithm::Bbr,
            fec_enabled: true,
            fec_group_size: FEC_GROUP_SIZE,
            stats: None,
            aggressive_retransmit: true,
            enable_multipath: true,
            max_paths: 4,
            encryption_key: None,
            enable_encryption: true,
            key_exchange_method: KeyExchangeMethod::HybridX25519Kyber,
            auto_generate_key: true,
            enable_post_quantum: true,
            enable_nat_traversal: true,
            enable_parallel_pipeline: true,
            enable_smart_cache: true,
            enable_connection_aggregation: true,
            enable_smart_fec: true,
            recv_timeout: default_recv_timeout(),
            handshake_timeout: default_handshake_timeout(),
            max_pending_connections: MAX_PENDING_CONNECTIONS,
            enable_connection_migration: true,
            enable_session_resumption: true,
            enable_0rtt: false,
            enable_pmtud: true,
            enable_ecn: false,
            udp_send_buffer_size: 4 * 1024 * 1024,
            udp_receive_buffer_size: 4 * 1024 * 1024,
            max_batch_packets: 64,
            enable_pacing: true,
            hedt_enabled: true,
            hedt_threshold: 1380,
            hedt_max_inflight: 4,
            idle_timeout: Some(Duration::from_secs(120)),
            keep_alive_interval: Some(Duration::from_secs(20)),
            max_reassembly_bytes: 64 * 1024 * 1024,
            authentication: AuthenticationConfig::None,
            congestion_plugin: None,
            path_scheduler_plugin: None,
            fec_plugin: None,
        }
    }
}

impl ArkTPConfig {
    pub fn validate(&self) -> Result<()> {
        if self.mtu < 576 {
            return Err(ArkTPError::InvalidConfig("MTU out of range".to_string()));
        }
        
        if matches!(&self.authentication, AuthenticationConfig::PreSharedKey) && self.encryption_key.is_none() {
            return Err(ArkTPError::InvalidConfig("PreSharedKey authentication requires encryption_key".into()));
        }
        if self.initial_max_data == 0 || self.initial_max_stream_data == 0 || self.max_streams == 0 {
            return Err(ArkTPError::InvalidConfig("flow-control limits must be non-zero".into()));
        }
        if self.send_buffer_size == 0 || self.receive_buffer_size == 0 {
            return Err(ArkTPError::InvalidConfig("Buffer size cannot be zero".to_string()));
        }
        if self.udp_send_buffer_size < 64 * 1024 || self.udp_receive_buffer_size < 64 * 1024 {
            return Err(ArkTPError::InvalidConfig("UDP socket buffers are too small".into()));
        }
        if self.hedt_threshold < PacketHeader::SIZE + TAG_SIZE + 8 {
            return Err(ArkTPError::InvalidConfig("hedt_threshold must fit inside the configured MTU".into()));
        }
        if self.hedt_max_inflight == 0 || self.hedt_max_inflight > 64 {
            return Err(ArkTPError::InvalidConfig("hedt_max_inflight must be in 1..=64".into()));
        }
        if self.max_batch_packets == 0 || self.max_batch_packets > 4096 {
            return Err(ArkTPError::InvalidConfig("max_batch_packets must be in 1..=4096".into()));
        }
        if self.max_reassembly_bytes < self.mtu as usize * 4 {
            return Err(ArkTPError::InvalidConfig("max_reassembly_bytes is too small for the configured MTU".into()));
        }
        
        if self.fec_enabled && self.fec_group_size < 2 {
            return Err(ArkTPError::InvalidConfig("FEC group size must be at least 2".to_string()));
        }
        
        if self.max_pending_connections == 0 { return Err(ArkTPError::InvalidConfig("max_pending_connections cannot be zero".into())); }
        if self.max_paths > MAX_PATHS {
            return Err(ArkTPError::InvalidConfig(format!("Max paths cannot exceed {}", MAX_PATHS)));
        }
        
        if !self.enable_post_quantum {
            match self.key_exchange_method {
                KeyExchangeMethod::PostQuantumKyber | KeyExchangeMethod::HybridX25519Kyber => {
                    return Err(ArkTPError::InvalidConfig(
                        "Post-quantum key exchange requires enable_post_quantum=true".to_string(),
                    ));
                }
                _ => {}
            }
        }

        Ok(())
    }
}



/// Thread-safe configuration snapshot used for hot reload. Existing
/// connections explicitly call `update_runtime_config`; new connections
/// automatically use the latest snapshot.
#[derive(Clone)]
pub struct ArkTPConfigHandle {
    inner: Arc<parking_lot::RwLock<ArkTPConfig>>,
}
impl ArkTPConfigHandle {
    pub fn new(config: ArkTPConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { inner: Arc::new(parking_lot::RwLock::new(config)) })
    }
    pub fn get(&self) -> ArkTPConfig { self.inner.read().clone() }
    pub fn reload(&self, config: ArkTPConfig) -> Result<()> {
        config.validate()?;
        *self.inner.write() = config;
        Ok(())
    }
}
