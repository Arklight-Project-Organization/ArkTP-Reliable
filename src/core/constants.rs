
// 加密相关

// 后量子密码学

// 性能优化


// ==================== 常量定义 ====================
pub const DEFAULT_MTU: u16 = 1420;
pub const MAX_RETRIES: u32 = 12;
pub const MIN_RTO_MS: u64 = 20;
pub const MAX_RTO_MS: u64 = 5000;
pub const ACK_INTERVAL_MS: u64 = 10;
pub const FEC_GROUP_SIZE: usize = 8;
pub const HANDSHAKE_TIMEOUT_MS: u64 = 3000;
pub const KEY_EXCHANGE_TIMEOUT_MS: u64 = 5000;
pub const KEEPALIVE_INTERVAL_MS: u64 = 3000;
pub const SEND_LOOP_INTERVAL_MS: u64 = 2;
pub const MAX_SEQ_WINDOW: u32 = 1048576;
pub const CLEANUP_INTERVAL_SECS: u64 = 10;
pub const MAX_PENDING_CONNECTIONS: usize = 5000;
pub const SYN_RETRY_INTERVAL_MS: u64 = 200;
pub const AGGRESSIVE_RETRANSMIT_MULTIPLIER: f64 = 0.5;
pub const FAST_RETRANSMIT_THRESHOLD: u32 = 2;
pub const ADAPTIVE_FEC_MIN_GROUPS: usize = 2;
pub const ADAPTIVE_FEC_MAX_GROUPS: usize = 32;
pub const MAX_PATHS: usize = 16;
pub const PATH_QUALITY_INTERVAL_MS: u64 = 500;
pub const PATH_PROBE_INTERVAL_MS: u64 = 2000;
pub const MIN_PATH_QUALITY: f64 = 0.05;
pub const MAX_ENCRYPTED_PACKET_SIZE: usize = 65536;
pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const TAG_SIZE: usize = 16;
pub const SALT_SIZE: usize = 32;
pub const MAX_BATCH_SIZE: usize = 64;
pub const BUFFER_POOL_SIZE: usize = 1024;
pub const MAX_IN_FLIGHT_PACKETS: u32 = 10000;
pub const STATS_UPDATE_INTERVAL_MS: u64 = 500;
pub const X25519_KEY_SIZE: usize = 32;
pub const KEY_VERIFICATION_SIZE: usize = 32;

// 并行处理常量
pub const PARALLEL_ENCRYPTION_THREADS: usize = 4;
pub const PARALLEL_FEC_THREADS: usize = 4;
pub const PARALLEL_PATH_SELECTION_THREADS: usize = 2;
pub const PIPELINE_BUFFER_SIZE: usize = 256;

// 智能缓存常量
pub const ENCRYPTION_CACHE_SIZE: usize = 1024;
pub const PATH_CACHE_SIZE: usize = 256;
pub const FEC_CACHE_SIZE: usize = 512;
pub const ROUTE_CACHE_SIZE: usize = 1024;

// 后量子密码常量
pub const KYBER_PUBLIC_KEY_SIZE: usize = pqc_kyber::KYBER_PUBLICKEYBYTES;
pub const KYBER_SECRET_KEY_SIZE: usize = pqc_kyber::KYBER_SECRETKEYBYTES;
pub const KYBER_CIPHERTEXT_SIZE: usize = pqc_kyber::KYBER_CIPHERTEXTBYTES;
pub const KYBER_SHARED_SECRET_SIZE: usize = pqc_kyber::KYBER_SSBYTES;
pub const DILITHIUM_PUBLIC_KEY_SIZE: usize = pqc_dilithium::PUBLICKEYBYTES;
pub const DILITHIUM_SECRET_KEY_SIZE: usize = pqc_dilithium::SECRETKEYBYTES;
pub const DILITHIUM_SIGNATURE_SIZE: usize = pqc_dilithium::SIGNBYTES;

// NAT穿透常量
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun1.l.google.com:19302",
    "stun2.l.google.com:19302",
];
pub const NAT_PROBE_INTERVAL_MS: u64 = 5000;
pub const NAT_REFRESH_INTERVAL_MS: u64 = 30000;

// 多连接聚合常量
pub const MAX_AGGREGATED_CONNECTIONS: usize = 8;
pub const CONNECTION_HEALTH_CHECK_INTERVAL_MS: u64 = 1000;
pub const CONNECTION_FAILOVER_THRESHOLD: f64 = 0.7;

