use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化

use crate::*;

// ==================== 统计信息 ====================
#[derive(Debug, Clone)]
pub struct ArkTPStats {
    pub packets_sent: Arc<AtomicU64>,
    pub packets_retransmitted: Arc<AtomicU64>,
    pub packets_lost: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub rtt_avg: Arc<AtomicU64>,
    pub cwnd: Arc<AtomicU64>,
    pub packets_received: Arc<AtomicU64>,
    pub bytes_received: Arc<AtomicU64>,
    pub connection_time: Arc<AtomicU64>,
    pub loss_rate: Arc<AtomicU64>,
    pub fec_recovered: Arc<AtomicU64>,
    pub active_paths: Arc<AtomicU64>,
    pub total_bandwidth: Arc<AtomicU64>,
    pub encrypted_packets: Arc<AtomicU64>,
    pub decrypted_packets: Arc<AtomicU64>,
    pub failed_decryptions: Arc<AtomicU64>,
    pub queue_length: Arc<AtomicU64>,
    pub in_flight: Arc<AtomicU64>,
    pub key_exchanges_completed: Arc<AtomicU64>,
    pub key_exchanges_failed: Arc<AtomicU64>,
    pub cache_hits: Arc<AtomicU64>,
    pub cache_misses: Arc<AtomicU64>,
    pub parallel_operations: Arc<AtomicU64>,
    pub nat_traversals: Arc<AtomicU64>,
    pub aggregated_connections: Arc<AtomicU64>,
    pub rtt_min: Arc<AtomicU64>,
    pub rtt_max: Arc<AtomicU64>,
    pub ecn_ce: Arc<AtomicU64>,
    pub ecn_ect0: Arc<AtomicU64>,
    pub ecn_ect1: Arc<AtomicU64>,
    pub hedt_small_fast_path: Arc<AtomicU64>,
    pub hedt_large_offloaded: Arc<AtomicU64>,
    pub hedt_large_completed: Arc<AtomicU64>,
    pub hedt_large_fallback_inline: Arc<AtomicU64>,
}

impl ArkTPStats {
    pub fn new() -> Self {
        Self {
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_retransmitted: Arc::new(AtomicU64::new(0)),
            packets_lost: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            rtt_avg: Arc::new(AtomicU64::new(0)),
            cwnd: Arc::new(AtomicU64::new(0)),
            packets_received: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            connection_time: Arc::new(AtomicU64::new(0)),
            loss_rate: Arc::new(AtomicU64::new(0)),
            fec_recovered: Arc::new(AtomicU64::new(0)),
            active_paths: Arc::new(AtomicU64::new(0)),
            total_bandwidth: Arc::new(AtomicU64::new(0)),
            encrypted_packets: Arc::new(AtomicU64::new(0)),
            decrypted_packets: Arc::new(AtomicU64::new(0)),
            failed_decryptions: Arc::new(AtomicU64::new(0)),
            queue_length: Arc::new(AtomicU64::new(0)),
            in_flight: Arc::new(AtomicU64::new(0)),
            key_exchanges_completed: Arc::new(AtomicU64::new(0)),
            key_exchanges_failed: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            parallel_operations: Arc::new(AtomicU64::new(0)),
            nat_traversals: Arc::new(AtomicU64::new(0)),
            aggregated_connections: Arc::new(AtomicU64::new(0)),
            rtt_min: Arc::new(AtomicU64::new(u64::MAX)),
            rtt_max: Arc::new(AtomicU64::new(0)),
            ecn_ce: Arc::new(AtomicU64::new(0)),
            ecn_ect0: Arc::new(AtomicU64::new(0)),
            ecn_ect1: Arc::new(AtomicU64::new(0)),
            hedt_small_fast_path: Arc::new(AtomicU64::new(0)),
            hedt_large_offloaded: Arc::new(AtomicU64::new(0)),
            hedt_large_completed: Arc::new(AtomicU64::new(0)),
            hedt_large_fallback_inline: Arc::new(AtomicU64::new(0)),
        }
    }
}



impl ArkTPStats {
    /// Prometheus text exposition without requiring a global exporter.
    pub fn prometheus(&self) -> String {
        let g = |v: &Arc<AtomicU64>| v.load(Ordering::Relaxed);
        format!(
            "# TYPE arktp_packets_sent counter\narktp_packets_sent {}\n\
# TYPE arktp_packets_received counter\narktp_packets_received {}\n\
# TYPE arktp_bytes_sent counter\narktp_bytes_sent {}\n\
# TYPE arktp_bytes_received counter\narktp_bytes_received {}\n\
# TYPE arktp_rtt_ms gauge\narktp_rtt_ms {}\n\
# TYPE arktp_rtt_min_ms gauge\narktp_rtt_min_ms {}\n\
# TYPE arktp_rtt_max_ms gauge\narktp_rtt_max_ms {}\n\
# TYPE arktp_cwnd gauge\narktp_cwnd {}\n\
# TYPE arktp_ecn_ce counter\narktp_ecn_ce {}\n# TYPE arktp_hedt_small_fast_path counter\narktp_hedt_small_fast_path {}\n# TYPE arktp_hedt_large_offloaded counter\narktp_hedt_large_offloaded {}\n# TYPE arktp_hedt_large_completed counter\narktp_hedt_large_completed {}\n# TYPE arktp_hedt_large_fallback_inline counter\narktp_hedt_large_fallback_inline {}\n",
            g(&self.packets_sent), g(&self.packets_received), g(&self.bytes_sent),
            g(&self.bytes_received), g(&self.rtt_avg),
            if g(&self.rtt_min) == u64::MAX { 0 } else { g(&self.rtt_min) },
            g(&self.rtt_max), g(&self.cwnd), g(&self.ecn_ce),
            g(&self.hedt_small_fast_path), g(&self.hedt_large_offloaded), g(&self.hedt_large_completed), g(&self.hedt_large_fallback_inline)
        )
    }
}
