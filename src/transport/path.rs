use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use log::info;

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use dashmap::DashMap;
use parking_lot::RwLock as PLRwLock;
use rayon::prelude::*;

use crate::*;

// ==================== 路径质量评估 ====================
#[derive(Debug, Clone)]
pub struct PathQuality {
    pub rtt: Duration,
    pub loss_rate: f64,
    pub bandwidth: f64,
    pub jitter: f64,
    pub score: f64,
    pub last_update: Instant,
    pub rtt_history: VecDeque<Duration>,
}

impl PathQuality {
    fn new() -> Self {
        Self {
            rtt: Duration::from_millis(50),
            loss_rate: 0.0,
            bandwidth: 0.0,
            jitter: 0.0,
            score: 0.0,
            last_update: Instant::now(),
            rtt_history: VecDeque::with_capacity(32),
        }
    }
    
    #[inline]
    fn update(&mut self, rtt: Duration, loss_rate: f64, bandwidth: f64) {
        self.rtt = rtt;
        self.loss_rate = loss_rate;
        self.bandwidth = bandwidth;
        self.last_update = Instant::now();
        
        self.rtt_history.push_back(rtt);
        if self.rtt_history.len() > 32 {
            self.rtt_history.pop_front();
        }
        
        if self.rtt_history.len() > 1 {
            let mut sum = 0.0;
            let mut prev: Option<f64> = None;
            for rtt in &self.rtt_history {
                if let Some(p) = prev {
                    sum += (rtt.as_secs_f64() - p).abs();
                }
                prev = Some(rtt.as_secs_f64());
            }
            self.jitter = sum / (self.rtt_history.len() - 1) as f64;
        }
        
        let rtt_score = if rtt.as_millis() > 0 {
            (1000.0 / rtt.as_millis() as f64).min(20.0)
        } else {
            20.0
        };
        
        let loss_score = (1.0 - loss_rate).max(0.0) * 20.0;
        let bw_score = (bandwidth / 1_000_000.0).min(20.0);
        let jitter_score = (1.0 / (1.0 + self.jitter * 10.0)) * 10.0;
        
        self.score = rtt_score * 0.3 + loss_score * 0.3 + bw_score * 0.2 + jitter_score * 0.2;
    }
}

// ==================== 网络路径 ====================
#[derive(Debug)]
pub struct NetworkPath {
    pub id: u32,
    pub local_addr: SocketAddr,
    pub remote_addr: Arc<PLRwLock<SocketAddr>>,
    pub socket: Arc<UdpSocket>,
    pub quality: Arc<PLRwLock<PathQuality>>,
    pub active: AtomicBool,
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
}

impl NetworkPath {
    pub fn new(id: u32, socket: Arc<UdpSocket>, remote_addr: SocketAddr) -> Self {
        let local_addr = socket.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
        Self {
            id,
            local_addr,
            remote_addr: Arc::new(PLRwLock::new(remote_addr)),
            socket,
            quality: Arc::new(PLRwLock::new(PathQuality::new())),
            active: AtomicBool::new(true),
            packets_sent: AtomicU64::new(0),
            packets_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
        }
    }
    
    #[inline]
    pub fn record_send(&self, size: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(size as u64, Ordering::Relaxed);
    }
    
    #[inline]
    pub fn record_receive(&self, size: usize) {
        self.packets_received.fetch_add(1, Ordering::Relaxed);
        self.bytes_received.fetch_add(size as u64, Ordering::Relaxed);
    }
    
    #[inline]
    pub fn remote_addr(&self) -> SocketAddr { *self.remote_addr.read() }
    pub fn update_remote_addr(&self, addr: SocketAddr) { *self.remote_addr.write() = addr; }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

// ==================== 多路径管理器 ====================
pub trait PathSchedulerPlugin: Send + Sync {
    fn select_path(&self, paths: &[Arc<NetworkPath>]) -> Option<usize>;
}
pub struct MultiPathManager {
    paths: Arc<PLRwLock<Vec<Arc<NetworkPath>>>>,
    path_stats: Arc<DashMap<u32, PathStats>>,
    scheduler: Arc<PLRwLock<PathScheduler>>,
    plugin: Arc<PLRwLock<Option<Arc<dyn PathSchedulerPlugin>>>>,
    active_paths: Arc<AtomicUsize>,
}

#[derive(Debug)]
pub struct PathStats {
    rtt_samples: VecDeque<Duration>,
    loss_count: AtomicU64,
    total_sent: AtomicU64,
    bandwidth_samples: VecDeque<(Instant, f64)>,
    last_packet_time: Instant,
}

impl PathStats {
    fn new() -> Self {
        Self {
            rtt_samples: VecDeque::with_capacity(64),
            loss_count: AtomicU64::new(0),
            total_sent: AtomicU64::new(0),
            bandwidth_samples: VecDeque::with_capacity(64),
            last_packet_time: Instant::now(),
        }
    }
    
    #[inline]
    fn update_rtt(&mut self, rtt: Duration) {
        self.rtt_samples.push_back(rtt);
        if self.rtt_samples.len() > 64 {
            self.rtt_samples.pop_front();
        }
    }
    
    #[inline]
    fn update_bandwidth(&mut self, now: Instant, bytes: usize) {
        self.bandwidth_samples.push_back((now, bytes as f64));
        if self.bandwidth_samples.len() > 64 {
            self.bandwidth_samples.pop_front();
        }
        
        while let Some((t, _)) = self.bandwidth_samples.front() {
            if now.duration_since(*t) > Duration::from_secs(5) {
                self.bandwidth_samples.pop_front();
            } else {
                break;
            }
        }
    }
    
    #[inline]
    fn avg_rtt(&self) -> Duration {
        if self.rtt_samples.is_empty() {
            return Duration::from_millis(50);
        }
        let sum: u128 = self.rtt_samples.iter().map(|d| d.as_micros()).sum();
        Duration::from_micros((sum / self.rtt_samples.len() as u128) as u64)
    }
    
    #[inline]
    fn loss_rate(&self) -> f64 {
        let total = self.total_sent.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.loss_count.load(Ordering::Relaxed) as f64 / total as f64
    }
    
    #[inline]
    fn bandwidth(&self) -> f64 {
        if self.bandwidth_samples.is_empty() {
            return 0.0;
        }
        let total: f64 = self.bandwidth_samples.iter().map(|(_, b)| *b).sum();
        total / self.bandwidth_samples.len() as f64
    }
}

#[derive(Debug, Clone)]
pub enum PathScheduler {
    Adaptive,
    WeightedFair,
    LowLatency,
    HighThroughput,
}

impl PathScheduler {
    fn new() -> Self {
        PathScheduler::Adaptive
    }
    
    #[inline]
    fn select_path(&self, paths: &[Arc<NetworkPath>]) -> Option<usize> {
        if paths.is_empty() {
            return None;
        }
        
        let active_paths: Vec<usize> = paths.iter()
            .enumerate()
            .filter(|(_, p)| p.is_active())
            .map(|(i, _)| i)
            .collect();
        
        if active_paths.is_empty() {
            return None;
        }
        
        match self {
            PathScheduler::Adaptive => {
                let total_score: f64 = active_paths.iter()
                    .map(|&i| paths[i].quality.read().score)
                    .sum();
                
                if total_score <= 0.0 {
                    return Some(active_paths[0]);
                }
                
                let mut r = rand::random::<f64>() * total_score;
                for &i in &active_paths {
                    r -= paths[i].quality.read().score;
                    if r <= 0.0 {
                        return Some(i);
                    }
                }
                Some(active_paths[active_paths.len() - 1])
            }
            PathScheduler::WeightedFair => {
                let total_weight: f64 = active_paths.iter()
                    .map(|&i| {
                        let q = paths[i].quality.read();
                        q.bandwidth.max(1.0)
                    })
                    .sum();
                
                let mut r = rand::random::<f64>() * total_weight;
                for &i in &active_paths {
                    let q = paths[i].quality.read();
                    r -= q.bandwidth.max(1.0);
                    if r <= 0.0 {
                        return Some(i);
                    }
                }
                Some(active_paths[0])
            }
            PathScheduler::LowLatency => {
                active_paths.into_iter()
                    .min_by(|&a, &b| {
                        paths[a].quality.read().rtt.cmp(&paths[b].quality.read().rtt)
                    })
            }
            PathScheduler::HighThroughput => {
                active_paths.into_iter()
                    .max_by(|&a, &b| {
                        paths[a].quality.read().bandwidth.partial_cmp(&paths[b].quality.read().bandwidth).unwrap()
                    })
            }
        }
    }
}

impl MultiPathManager {
    pub fn new() -> Self {
        Self {
            paths: Arc::new(PLRwLock::new(Vec::with_capacity(MAX_PATHS))),
            path_stats: Arc::new(DashMap::new()),
            scheduler: Arc::new(PLRwLock::new(PathScheduler::new())),
            plugin: Arc::new(PLRwLock::new(None)),
            active_paths: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    pub fn add_path(&self, socket: Arc<UdpSocket>, remote_addr: SocketAddr) -> Result<u32> {
        let mut paths = self.paths.write();
        if paths.len() >= MAX_PATHS {
            return Err(ArkTPError::Protocol("Too many paths".to_string()));
        }
        
        let id = paths.len() as u32;
        let path = Arc::new(NetworkPath::new(id, socket, remote_addr));
        self.path_stats.insert(id, PathStats::new());
        paths.push(path);
        self.active_paths.fetch_add(1, Ordering::Relaxed);
        
        info!("Added network path {} ({} -> {})", id, paths[id as usize].local_addr, remote_addr);
        Ok(id)
    }
    
    pub fn remove_path(&self, path_id: u32) {
        if let Some(path) = self.paths.read().get(path_id as usize) {
            path.active.store(false, Ordering::Relaxed);
            self.active_paths.fetch_sub(1, Ordering::Relaxed);
            info!("Removed network path {}", path_id);
        }
    }
    
    #[inline]
    pub fn select_path(&self) -> Result<usize> {
        if let Some(plugin) = self.plugin.read().as_ref() {
            if let Some(id) = plugin.select_path(&self.paths.read()) { return Ok(id); }
        }
        let scheduler = self.scheduler.read();
        scheduler.select_path(&self.paths.read())
            .ok_or(ArkTPError::NoAvailablePath)
    }

    pub fn set_scheduler_plugin(&self, plugin: Arc<dyn PathSchedulerPlugin>) {
        *self.plugin.write() = Some(plugin);
    }
    
    pub fn update_path_quality(&self, path_id: u32, rtt: Duration, loss: bool) {
        if let Some(mut stats) = self.path_stats.get_mut(&path_id) {
            stats.update_rtt(rtt);
            if loss {
                stats.loss_count.fetch_add(1, Ordering::Relaxed);
            }
            stats.total_sent.fetch_add(1, Ordering::Relaxed);
            stats.last_packet_time = Instant::now();
            
            if let Some(path) = self.paths.read().get(path_id as usize) {
                let mut quality = path.quality.write();
                quality.update(
                    stats.avg_rtt(),
                    stats.loss_rate(),
                    stats.bandwidth(),
                );
            }
        }
    }
    
    #[inline]
    pub fn record_send(&self, path_id: u32, size: usize) {
        if let Some(path) = self.paths.read().get(path_id as usize) {
            path.record_send(size);
            if let Some(mut stats) = self.path_stats.get_mut(&path_id) {
                stats.update_bandwidth(Instant::now(), size);
            }
        }
    }
    
    #[inline]
    pub fn record_receive(&self, path_id: u32, size: usize) {
        if let Some(path) = self.paths.read().get(path_id as usize) {
            path.record_receive(size);
        }
    }
    
    pub fn get_best_paths(&self, count: usize) -> Vec<usize> {
        let paths = self.paths.read();
        let mut active: Vec<usize> = paths.iter()
            .enumerate()
            .filter(|(_, p)| p.is_active())
            .map(|(i, _)| i)
            .collect();
        
        active.sort_by(|&a, &b| {
            paths[b].quality.read().score.partial_cmp(&paths[a].quality.read().score).unwrap()
        });
        
        active.truncate(count);
        active
    }
    
    #[inline]
    pub fn path_count(&self) -> usize {
        self.active_paths.load(Ordering::Relaxed)
    }
    
    #[inline]
    pub fn get_path(&self, path_id: u32) -> Option<Arc<NetworkPath>> {
        self.paths.read().get(path_id as usize).cloned()
    }
    
    #[inline]
    pub fn paths(&self) -> Vec<Arc<NetworkPath>> {
        self.paths.read().clone()
    }
    
    pub fn rtt_percentiles(&self, path_id: u32) -> Option<(Duration, Duration, Duration)> {
        let stats = self.path_stats.get(&path_id)?;
        if stats.rtt_samples.is_empty() { return None; }
        let mut v: Vec<u128> = stats.rtt_samples.iter().map(|d| d.as_micros()).collect();
        v.sort_unstable();
        let at = |q: f64| -> Duration {
            let idx = ((v.len() - 1) as f64 * q).round() as usize;
            Duration::from_micros(v[idx] as u64)
        };
        Some((Duration::from_micros(*v.first().unwrap() as u64), at(0.50), at(0.99)))
    }

    pub fn set_scheduler(&self, scheduler: PathScheduler) {
        *self.scheduler.write() = scheduler;
    }
}

