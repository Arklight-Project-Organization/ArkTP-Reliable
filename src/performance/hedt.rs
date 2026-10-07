//! High-Efficiency Data Transmission (HEDT).
//!
//! HEDT is a local send-path scheduling optimization. It is deliberately not
//! a wire-protocol feature: peers do not need to negotiate it.
//!
//! The key idea is to keep latency-sensitive small packets out of the crypto
//! critical path of large packets. Large packets are encrypted in a bounded
//! background pool while small packets can continue through the immediate
//! path. All packets still pass through the same congestion-control, pacing,
//! retransmission and accounting machinery, so HEDT does not bypass bandwidth
//! governance.

use std::sync::{atomic::{AtomicU64, AtomicUsize, Ordering}, Arc};
use bytes::Bytes;
use tokio::sync::{Semaphore, oneshot};

use crate::{CryptoContext, Result, ArkTPError, PacketHeader, TAG_SIZE};

/// Default encoded-packet threshold requested by ArkTP Reliable.
pub const HEDT_DEFAULT_THRESHOLD: usize = 1380;
/// Avoid unbounded background crypto work under overload.
pub const HEDT_DEFAULT_MAX_INFLIGHT: usize = 4;

#[derive(Debug, Clone, Copy)]
pub struct HedtConfig {
    pub enabled: bool,
    /// Classification is based on the final encoded packet size, including
    /// the packet header and AEAD tag when encryption is enabled.
    pub threshold: usize,
    /// Maximum number of large-packet encryption jobs concurrently running.
    pub max_inflight: usize,
}

impl Default for HedtConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold: HEDT_DEFAULT_THRESHOLD,
            max_inflight: HEDT_DEFAULT_MAX_INFLIGHT,
        }
    }
}

#[derive(Debug, Default)]
pub struct HedtStats {
    pub small_fast_path: AtomicU64,
    pub large_offloaded: AtomicU64,
    pub large_completed: AtomicU64,
    pub large_fallback_inline: AtomicU64,
    pub bytes_offloaded: AtomicU64,
}

pub struct HedtScheduler {
    cfg: HedtConfig,
    permits: Arc<Semaphore>,
    inflight: Arc<AtomicUsize>,
    pub stats: Arc<HedtStats>,
}

pub struct HedtJob {
    rx: oneshot::Receiver<Result<Vec<u8>>>,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl HedtJob {
    pub fn try_finish(&mut self) -> Option<Result<Vec<u8>>> {
        match self.rx.try_recv() {
            Ok(result) => {
                self.permit.take();
                Some(result)
            }
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => {
                self.permit.take();
                Some(Err(ArkTPError::EncryptionError("HEDT worker stopped".into())))
            }
        }
    }
}

impl HedtScheduler {
    pub fn new(cfg: HedtConfig) -> Self {
        let max = cfg.max_inflight.max(1);
        Self {
            cfg,
            permits: Arc::new(Semaphore::new(max)),
            inflight: Arc::new(AtomicUsize::new(0)),
            stats: Arc::new(HedtStats::default()),
        }
    }

    pub fn config(&self) -> HedtConfig { self.cfg }
    pub fn inflight(&self) -> usize { self.inflight.load(Ordering::Acquire) }

    #[inline]
    pub fn is_large(&self, payload_len: usize, encrypted: bool) -> bool {
        if !self.cfg.enabled { return false; }
        let encoded = PacketHeader::SIZE + payload_len + if encrypted { TAG_SIZE + 8 } else { 0 };
        encoded > self.cfg.threshold
    }

    /// Submit a large packet to the bounded blocking crypto pool.
    ///
    /// `CryptoContext` is clone-safe: its cipher and nonce counter are shared,
    /// so nonce allocation remains atomic even while jobs execute concurrently.
    pub async fn submit_large(
        &self,
        crypto: CryptoContext,
        plaintext: Bytes,
        aad: [u8; PacketHeader::SIZE],
    ) -> Option<HedtJob> {
        if !self.cfg.enabled || !self.is_large(plaintext.len(), true) {
            return None;
        }

        let permit = match self.permits.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.stats.large_fallback_inline.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };

        self.inflight.fetch_add(1, Ordering::AcqRel);
        self.stats.large_offloaded.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_offloaded.fetch_add(plaintext.len() as u64, Ordering::Relaxed);

        let (tx, rx) = oneshot::channel();
        let inflight = self.inflight.clone();
        let stats = self.stats.clone();
        tokio::task::spawn_blocking(move || {
            let result = crypto.encrypt(&plaintext, &aad);
            if result.is_ok() {
                stats.large_completed.fetch_add(1, Ordering::Relaxed);
            }
            inflight.fetch_sub(1, Ordering::AcqRel);
            let _ = tx.send(result);
        });

        Some(HedtJob { rx, permit: Some(permit) })
    }

    pub async fn finish(&self, job: HedtJob) -> Result<Vec<u8>> {
        let HedtJob { rx, permit } = job;
        let result = rx.await.map_err(|_| ArkTPError::EncryptionError("HEDT worker stopped".into()))?;
        drop(permit);
        result
    }

    /// Wait until all offloaded encryption work has completed. This is used
    /// before key rotation so an old-key job cannot finish after the rotation.
    pub async fn drain(&self) {
        while self.inflight() != 0 {
            tokio::task::yield_now().await;
        }
    }

    pub fn record_small(&self) {
        self.stats.small_fast_path.fetch_add(1, Ordering::Relaxed);
    }
}
