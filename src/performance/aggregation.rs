use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::time::{sleep, interval};
use futures::stream::{FuturesUnordered, StreamExt};
use bytes::Bytes;
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



#[derive(Debug, Clone)]
pub struct ConnectionHealthRecord {
    pub conn_id: u64,
    pub latency: Duration,
    pub loss_rate: f64,
    pub bandwidth: f64,
    pub score: f64,
    pub updated_at: u64,
}

pub trait AggregationDirectory: Send + Sync {
    fn publish(&self, record: ConnectionHealthRecord);
    fn snapshot(&self) -> Vec<ConnectionHealthRecord>;
}

#[derive(Default)]
pub struct InMemoryAggregationDirectory {
    records: DashMap<u64, ConnectionHealthRecord>,
}
impl AggregationDirectory for InMemoryAggregationDirectory {
    fn publish(&self, record: ConnectionHealthRecord) { self.records.insert(record.conn_id, record); }
    fn snapshot(&self) -> Vec<ConnectionHealthRecord> { self.records.iter().map(|r| r.value().clone()).collect() }
}

// ==================== 多连接聚合 ====================
pub struct ConnectionAggregator {
    connections: Arc<PLRwLock<Vec<Arc<ArkTPConnection>>>>,
    health_scores: Arc<DashMap<u64, ConnectionHealth>>,
    scheduler: Arc<PLRwLock<AggregationScheduler>>,
    active_connections: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
pub struct ConnectionHealth {
    latency: Duration,
    loss_rate: f64,
    bandwidth: f64,
    score: f64,
    last_check: Instant,
    consecutive_failures: u32,
}

impl ConnectionHealth {
    fn new() -> Self {
        Self {
            latency: Duration::from_millis(50),
            loss_rate: 0.0,
            bandwidth: 0.0,
            score: 100.0,
            last_check: Instant::now(),
            consecutive_failures: 0,
        }
    }
    
    fn update(&mut self, latency: Duration, loss_rate: f64, bandwidth: f64) {
        self.latency = latency;
        self.loss_rate = loss_rate;
        self.bandwidth = bandwidth;
        self.last_check = Instant::now();
        
        let latency_score = (1000.0 / latency.as_millis().max(1) as f64).min(100.0);
        let loss_score = (1.0 - loss_rate) * 100.0;
        let bw_score = (bandwidth / 1_000_000.0).min(100.0);
        
        self.score = latency_score * 0.4 + loss_score * 0.4 + bw_score * 0.2;
    }
    
    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.score *= 0.5;
    }
    
    fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }
    
    fn is_healthy(&self) -> bool {
        self.consecutive_failures < 3 && self.score > 10.0
    }
}

#[derive(Debug, Clone)]
pub enum AggregationScheduler {
    RoundRobin { next: usize },
    WeightedRoundRobin,
    BestConnection,
    AdaptiveLoadBalancing,
}

impl AggregationScheduler {
    fn new() -> Self {
        AggregationScheduler::AdaptiveLoadBalancing
    }
    
    fn select_connection(&mut self, connections: &[Arc<ArkTPConnection>], health_scores: &DashMap<u64, ConnectionHealth>) -> Option<usize> {
        if connections.is_empty() {
            return None;
        }
        
        let healthy: Vec<usize> = connections.iter()
            .enumerate()
            .filter(|(_i, conn)| {
                let conn_id = conn.conn_id();
                health_scores.get(&conn_id)
                    .map(|h| h.is_healthy())
                    .unwrap_or(true)
            })
            .map(|(i, _)| i)
            .collect();
        
        if healthy.is_empty() {
            return None;
        }
        
        match self {
            AggregationScheduler::RoundRobin { next } => {
                let idx = *next % healthy.len();
                *next += 1;
                Some(healthy[idx])
            }
            AggregationScheduler::WeightedRoundRobin => {
                let total_weight: f64 = healthy.iter()
                    .map(|&i| {
                        let conn_id = connections[i].conn_id();
                        health_scores.get(&conn_id)
                            .map(|h| h.score)
                            .unwrap_or(50.0)
                    })
                    .sum();
                
                if total_weight <= 0.0 {
                    return Some(healthy[0]);
                }
                
                let mut r = rand::random::<f64>() * total_weight;
                for &i in &healthy {
                    let conn_id = connections[i].conn_id();
                    let weight = health_scores.get(&conn_id)
                        .map(|h| h.score)
                        .unwrap_or(50.0);
                    r -= weight;
                    if r <= 0.0 {
                        return Some(i);
                    }
                }
                Some(healthy[healthy.len() - 1])
            }
            AggregationScheduler::BestConnection => {
                healthy.into_iter()
                    .max_by(|&a, &b| {
                        let score_a = health_scores.get(&connections[a].conn_id())
                            .map(|h| h.score)
                            .unwrap_or(0.0);
                        let score_b = health_scores.get(&connections[b].conn_id())
                            .map(|h| h.score)
                            .unwrap_or(0.0);
                        score_a.partial_cmp(&score_b).unwrap()
                    })
            }
            AggregationScheduler::AdaptiveLoadBalancing => {
                let total_score: f64 = healthy.iter()
                    .map(|&i| {
                        let conn_id = connections[i].conn_id();
                        let health = health_scores.get(&conn_id)
                            .map(|h| h.score)
                            .unwrap_or(50.0);
                        let load = connections[i].stats().in_flight.load(Ordering::Relaxed) as f64;
                        health / (load + 1.0)
                    })
                    .sum();
                
                if total_score <= 0.0 {
                    return Some(healthy[0]);
                }
                
                let mut r = rand::random::<f64>() * total_score;
                for &i in &healthy {
                    let conn_id = connections[i].conn_id();
                    let health = health_scores.get(&conn_id)
                        .map(|h| h.score)
                        .unwrap_or(50.0);
                    let load = connections[i].stats().in_flight.load(Ordering::Relaxed) as f64;
                    r -= health / (load + 1.0);
                    if r <= 0.0 {
                        return Some(i);
                    }
                }
                Some(healthy[healthy.len() - 1])
            }
        }
    }
}

impl ConnectionAggregator {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(PLRwLock::new(Vec::with_capacity(MAX_AGGREGATED_CONNECTIONS))),
            health_scores: Arc::new(DashMap::new()),
            scheduler: Arc::new(PLRwLock::new(AggregationScheduler::new())),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }
    
    pub fn add_connection(&self, connection: Arc<ArkTPConnection>) -> Result<()> {
        let mut connections = self.connections.write();
        if connections.len() >= MAX_AGGREGATED_CONNECTIONS {
            return Err(ArkTPError::ConnectionAggregationFailed("Too many connections".to_string()));
        }
        
        let conn_id = connection.conn_id();
        self.health_scores.insert(conn_id, ConnectionHealth::new());
        connections.push(connection);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        
        info!("Added connection {} to aggregator", conn_id);
        Ok(())
    }
    
    pub fn remove_connection(&self, conn_id: u64) {
        let mut connections = self.connections.write();
        if let Some(pos) = connections.iter().position(|c| c.conn_id() == conn_id) {
            connections.remove(pos);
            self.health_scores.remove(&conn_id);
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
            info!("Removed connection {} from aggregator", conn_id);
        }
    }
    
    pub async fn send(&self, data: &[u8]) -> Result<usize> {
        let conn = {
            let connections = self.connections.read();
            if connections.is_empty() { return Err(ArkTPError::NoAvailablePath); }
            let mut scheduler = self.scheduler.write();
            scheduler.select_connection(&connections, &self.health_scores)
                .map(|idx| connections[idx].clone())
        };
        match conn {
            Some(conn) => conn.send(data).await,
            None => Err(ArkTPError::ConnectionAggregationFailed("No healthy connection".to_string())),
        }
    }
    
    pub async fn send_batch(&self, data: &[Bytes]) -> Result<Vec<SeqNum>> {
        let conn = {
            let connections = self.connections.read();
            if connections.is_empty() { return Err(ArkTPError::NoAvailablePath); }
            let mut scheduler = self.scheduler.write();
            scheduler.select_connection(&connections, &self.health_scores)
                .map(|idx| connections[idx].clone())
        };
        match conn {
            Some(conn) => conn.send_batch(data).await,
            None => Err(ArkTPError::ConnectionAggregationFailed("No healthy connection".to_string())),
        }
    }
    
    pub async fn recv_any(&self) -> Result<Bytes> {
        loop {
            let conns = self.connections.read().clone();
            if conns.is_empty() { return Err(ArkTPError::NoAvailablePath); }
            let mut pending = FuturesUnordered::new();
            for conn in conns {
                pending.push(async move { conn.recv().await });
            }
            while let Some(result) = pending.next().await {
                match result {
                    Ok(data) => return Ok(data),
                    Err(ArkTPError::Timeout) => continue,
                    Err(ArkTPError::ConnectionClosed) => continue,
                    Err(e) => return Err(e),
                }
            }
            sleep(Duration::from_millis(5)).await;
        }
    }
    
    pub fn start_health_check_loop(self: Arc<Self>) {
        let weak = Arc::downgrade(&self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(CONNECTION_HEALTH_CHECK_INTERVAL_MS));
            loop {
                interval.tick().await;
                let Some(aggregator) = weak.upgrade() else { break; };
                let connections = aggregator.connections.read().clone();
                for conn in connections {
                    let conn_id = conn.conn_id();
                    let stats = conn.stats();
                    let latency = Duration::from_millis(stats.rtt_avg.load(Ordering::Relaxed));
                    let loss_rate = (stats.loss_rate.load(Ordering::Relaxed) as f64) / 10000.0;
                    let bandwidth = stats.total_bandwidth.load(Ordering::Relaxed) as f64;
                    if let Some(mut health) = aggregator.health_scores.get_mut(&conn_id) {
                        health.update(latency, loss_rate, bandwidth);
                        if stats.packets_lost.load(Ordering::Relaxed) > 0 {
                            health.record_failure();
                        } else {
                            health.record_success();
                        }
                    }
                }
            }
        });
    }
    
    pub fn connection_count(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }
    
    pub fn get_health_scores(&self) -> Vec<(u64, f64)> {
        self.health_scores.iter()
            .map(|entry| (*entry.key(), entry.value().score))
            .collect()
    }
}

