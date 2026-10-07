use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use bytes::BufMut;

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use lru::LruCache;
use moka::sync::Cache as MokaCache;

use crate::*;

// ==================== 智能缓存 ====================
pub struct SmartCache {
    encryption_cache: MokaCache<u64, Arc<CryptoContext>>,
    path_cache: MokaCache<u64, u32>,
    fec_cache: MokaCache<u64, Arc<Vec<FecPacket>>>,
    route_cache: LruCache<u64, RouteInfo>,
    stats: CacheStats,
}

#[derive(Debug, Clone)]
pub struct RouteInfo {
    path_id: u32,
    timestamp: Instant,
    quality_score: f64,
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub encryption_hits: Arc<AtomicU64>,
    pub encryption_misses: Arc<AtomicU64>,
    pub path_hits: Arc<AtomicU64>,
    pub path_misses: Arc<AtomicU64>,
    pub fec_hits: Arc<AtomicU64>,
    pub fec_misses: Arc<AtomicU64>,
    pub route_hits: Arc<AtomicU64>,
    pub route_misses: Arc<AtomicU64>,
}

impl CacheStats {
    fn new() -> Self {
        Self {
            encryption_hits: Arc::new(AtomicU64::new(0)),
            encryption_misses: Arc::new(AtomicU64::new(0)),
            path_hits: Arc::new(AtomicU64::new(0)),
            path_misses: Arc::new(AtomicU64::new(0)),
            fec_hits: Arc::new(AtomicU64::new(0)),
            fec_misses: Arc::new(AtomicU64::new(0)),
            route_hits: Arc::new(AtomicU64::new(0)),
            route_misses: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl SmartCache {
    pub fn new() -> Self {
        Self {
            encryption_cache: MokaCache::builder()
                .max_capacity(ENCRYPTION_CACHE_SIZE as u64)
                .time_to_live(Duration::from_secs(300))
                .build(),
            path_cache: MokaCache::builder()
                .max_capacity(PATH_CACHE_SIZE as u64)
                .time_to_live(Duration::from_secs(30))
                .build(),
            fec_cache: MokaCache::builder()
                .max_capacity(FEC_CACHE_SIZE as u64)
                .time_to_live(Duration::from_secs(10))
                .build(),
            route_cache: LruCache::new(std::num::NonZeroUsize::new(ROUTE_CACHE_SIZE).unwrap()),
            stats: CacheStats::new(),
        }
    }
    
    #[inline]
    pub fn get_encryption(&self, key: u64) -> Option<Arc<CryptoContext>> {
        match self.encryption_cache.get(&key) {
            Some(ctx) => {
                self.stats.encryption_hits.fetch_add(1, Ordering::Relaxed);
                Some(ctx)
            }
            None => {
                self.stats.encryption_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
    
    #[inline]
    pub fn put_encryption(&self, key: u64, ctx: Arc<CryptoContext>) {
        self.encryption_cache.insert(key, ctx);
    }
    
    #[inline]
    pub fn get_path(&self, key: u64) -> Option<u32> {
        match self.path_cache.get(&key) {
            Some(path) => {
                self.stats.path_hits.fetch_add(1, Ordering::Relaxed);
                Some(path)
            }
            None => {
                self.stats.path_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
    
    #[inline]
    pub fn put_path(&self, key: u64, path_id: u32) {
        self.path_cache.insert(key, path_id);
    }
    
    #[inline]
    pub fn get_fec(&self, key: u64) -> Option<Arc<Vec<FecPacket>>> {
        match self.fec_cache.get(&key) {
            Some(fec) => {
                self.stats.fec_hits.fetch_add(1, Ordering::Relaxed);
                Some(fec)
            }
            None => {
                self.stats.fec_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
    
    #[inline]
    pub fn put_fec(&self, key: u64, fec: Arc<Vec<FecPacket>>) {
        self.fec_cache.insert(key, fec);
    }
    
    #[inline]
    pub fn get_route(&mut self, key: u64) -> Option<RouteInfo> {
        match self.route_cache.get(&key) {
            Some(route) => {
                self.stats.route_hits.fetch_add(1, Ordering::Relaxed);
                Some(route.clone())
            }
            None => {
                self.stats.route_misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }
    
    #[inline]
    pub fn put_route(&mut self, key: u64, route: RouteInfo) {
        self.route_cache.put(key, route);
    }
    
    pub fn stats(&self) -> CacheStats {
        self.stats.clone()
    }
}

