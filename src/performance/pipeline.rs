use bytes::Bytes;

// 加密相关
use chacha20poly1305::aead::{Aead, KeyInit};
use sha2::Digest;

// 后量子密码学

// 性能优化
use rayon::prelude::*;

use crate::*;

// ==================== 并行处理管线 ====================
pub struct ParallelPipeline {
    encryption_pool: rayon::ThreadPool,
    fec_pool: rayon::ThreadPool,
    path_selection_pool: rayon::ThreadPool,
}

impl ParallelPipeline {
    pub fn new() -> Self {
        Self {
            encryption_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(PARALLEL_ENCRYPTION_THREADS)
                .thread_name(|i| format!("arktp-encrypt-{}", i))
                .build()
                .unwrap(),
            fec_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(PARALLEL_FEC_THREADS)
                .thread_name(|i| format!("arktp-fec-{}", i))
                .build()
                .unwrap(),
            path_selection_pool: rayon::ThreadPoolBuilder::new()
                .num_threads(PARALLEL_PATH_SELECTION_THREADS)
                .thread_name(|i| format!("arktp-path-{}", i))
                .build()
                .unwrap(),
        }
    }
    
    pub fn encrypt_batch(
        &self,
        crypto: &CryptoContext,
        data: &[Bytes],
        aad: &[u8],
    ) -> Vec<Result<Vec<u8>>> {
        self.encryption_pool.install(|| {
            data.par_iter()
                .map(|d| crypto.encrypt(d, aad))
                .collect()
        })
    }
    
    pub fn decrypt_batch(
        &self,
        crypto: &CryptoContext,
        data: &[Vec<u8>],
        aad: &[u8],
    ) -> Vec<Result<Vec<u8>>> {
        self.encryption_pool.install(|| {
            data.par_iter()
                .map(|d| crypto.decrypt(d, aad))
                .collect()
        })
    }
    
    pub fn fec_encode_batch(
        &self,
        fec: &mut AdaptiveFecEncoder,
        packets: &[(SeqNum, Bytes)],
    ) -> Vec<Option<Vec<FecPacket>>> {
        // AdaptiveFecEncoder is intentionally sequential because it owns the
        // current FEC group. Parallelizing calls would destroy packet ordering
        // and require an additional lock around every packet.
        packets.iter()
            .map(|(seq, data)| fec.push(*seq, data.clone()))
            .collect()
    }
    
    pub fn select_paths_batch(
        &self,
        multi_path: &MultiPathManager,
        count: usize,
    ) -> Vec<u32> {
        self.path_selection_pool.install(|| {
            (0..count)
                .into_par_iter()
                .map(|_| {
                    match multi_path.select_path() {
                        Ok(idx) => multi_path.paths().get(idx).map(|p| p.id).unwrap_or(0),
                        Err(_) => 0,
                    }
                })
                .collect()
        })
    }
}

