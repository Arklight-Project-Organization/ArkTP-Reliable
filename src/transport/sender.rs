use std::{
    collections::VecDeque,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    sync::Notify,
};
use bytes::Bytes;
use log::debug;

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use parking_lot::{RwLock as PLRwLock, Mutex as PLMutex};
use rayon::prelude::*;

use crate::*;

// ==================== 发送端 ====================
pub struct SendEntry {
    data: Bytes,
    seq: SeqNum,
    sent: Option<Instant>,
    retries: u32,
    acked: bool,
    last_sent: Option<Instant>,
    path_id: Option<u32>,
}

pub struct ArkTPSender {
    mtu: Arc<std::sync::atomic::AtomicU16>,
    max_retries: u32,
    conn_id: u64,
    send_queue: Arc<PLRwLock<VecDeque<SendEntry>>>,
    next_seq: Arc<AtomicU64>,
    in_flight: Arc<AtomicU64>,
    cc: Arc<PLRwLock<Box<dyn CongestionControl>>>,
    fec: Arc<PLRwLock<AdaptiveFecEncoder>>,
    fec_enabled: bool,
    stats: Arc<ArkTPStats>,
    notify: Arc<PLMutex<Option<Arc<Notify>>>>,
    loss_rate: Arc<PLRwLock<f64>>,
    multi_path: Arc<MultiPathManager>,
    stream_meta: Arc<PLRwLock<std::collections::HashMap<SeqNum, u64>>>,
    fec_plugin: Option<Arc<dyn FecPlugin>>,
    space_notify: Arc<Notify>,
    pacing: Arc<PLMutex<(Instant, f64)>>,
    pending_fec: Arc<PLMutex<VecDeque<(FecPacket, u32)>>>,
}

impl ArkTPSender {
    pub fn new(conn_id: u64) -> Self {
        Self::with_config(conn_id, ArkTPConfig::default())
    }

    pub fn with_config(conn_id: u64, config: ArkTPConfig) -> Self {
        let cc: Box<dyn CongestionControl> = if let Some(plugin) = &config.congestion_plugin {
            plugin.as_ref().clone_box()
        } else {
            match config.congestion_control {
                CongestionAlgorithm::Reno => Box::new(RenoCongestion::new()),
                CongestionAlgorithm::Bbr => Box::new(BbrCongestion::new()),
            }
        };
        
        Self {
            mtu: Arc::new(std::sync::atomic::AtomicU16::new(config.mtu)),
            max_retries: config.max_retries,
            conn_id,
            send_queue: Arc::new(PLRwLock::new(VecDeque::with_capacity(config.send_buffer_size))),
            next_seq: Arc::new(AtomicU64::new(1)),
            in_flight: Arc::new(AtomicU64::new(0)),
            cc: Arc::new(PLRwLock::new(cc)),
            fec: Arc::new(PLRwLock::new(AdaptiveFecEncoder::new(
                ADAPTIVE_FEC_MIN_GROUPS,
                ADAPTIVE_FEC_MAX_GROUPS
            ))),
            fec_enabled: config.fec_enabled,
            stats: config.stats.unwrap_or_else(|| Arc::new(ArkTPStats::new())),
            notify: Arc::new(PLMutex::new(None)),
            loss_rate: Arc::new(PLRwLock::new(0.0)),
            multi_path: Arc::new(MultiPathManager::new()),
            stream_meta: Arc::new(PLRwLock::new(std::collections::HashMap::new())),
            fec_plugin: config.fec_plugin.clone(),
            space_notify: Arc::new(Notify::new()),
            pacing: Arc::new(PLMutex::new((Instant::now(), 0.0))),
            pending_fec: Arc::new(PLMutex::new(VecDeque::new())),
        }
    }
    
    pub fn add_path(&self, socket: Arc<UdpSocket>, remote_addr: SocketAddr) -> Result<u32> {
        let path_id = self.multi_path.add_path(socket, remote_addr)?;
        self.stats.active_paths.store(self.multi_path.path_count() as u64, Ordering::Relaxed);
        Ok(path_id)
    }
    
    pub fn remove_path(&self, path_id: u32) {
        self.multi_path.remove_path(path_id);
        self.stats.active_paths.store(self.multi_path.path_count() as u64, Ordering::Relaxed);
    }

    pub fn enqueue(&self, data: Bytes) -> Result<SeqNum> {
        if data.is_empty() {
            return Err(ArkTPError::Protocol("Empty data".to_string()));
        }
        
        if data.len() > (self.mtu.load(Ordering::Relaxed) as usize - PacketHeader::SIZE - TAG_SIZE) {
            return Err(ArkTPError::PacketTooLarge {
                max: self.mtu.load(Ordering::Relaxed) as usize - PacketHeader::SIZE - TAG_SIZE,
            });
        }
        
        let mut queue = self.send_queue.write();
        if queue.len() >= queue.capacity() {
            return Err(ArkTPError::SendQueueFull);
        }
        
        let seq = SeqNum::new(self.next_seq.fetch_add(1, Ordering::Relaxed) as u32);
        
        queue.push_back(SendEntry {
            data,
            seq,
            sent: None,
            retries: 0,
            acked: false,
            last_sent: None,
            path_id: None,
        });
        
        self.stats.queue_length.store(queue.len() as u64, Ordering::Relaxed);
        drop(queue);
        
        if let Some(notify) = self.notify.lock().as_ref() {
            notify.notify_one();
        }
        
        Ok(seq)
    }
    
    pub async fn enqueue_async(&self, data: Bytes) -> Result<SeqNum> {
        loop {
            match self.enqueue(data.clone()) {
                Ok(v) => return Ok(v),
                Err(ArkTPError::SendQueueFull) => self.space_notify.notified().await,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn enqueue_stream(&self, stream_id: u64, frame: Bytes) -> Result<SeqNum> {
        let seq = self.enqueue(frame)?;
        self.stream_meta.write().insert(seq, stream_id);
        Ok(seq)
    }

    pub async fn enqueue_stream_async(&self, stream_id: u64, frame: Bytes) -> Result<SeqNum> {
        loop {
            match self.enqueue_stream(stream_id, frame.clone()) {
                Ok(v) => return Ok(v),
                Err(ArkTPError::SendQueueFull) => self.space_notify.notified().await,
                Err(e) => return Err(e),
            }
        }
    }

    pub fn stream_id_for(&self, seq: SeqNum) -> Option<u64> { self.stream_meta.read().get(&seq).copied() }

    pub fn enqueue_batch(&self, data: &[Bytes]) -> Result<Vec<SeqNum>> {
        let mut seqs = Vec::with_capacity(data.len());
        
        for d in data {
            seqs.push(self.enqueue(d.clone())?);
        }
        
        Ok(seqs)
    }

    pub fn on_ack(&self, now: Instant, ack_seq: SeqNum, sack_blocks: &[SackBlock], path_id: Option<u32>) {
        let mut acked_bytes = 0u64;
        let mut rtt_sample = None;

        let mut queue = self.send_queue.write();

        // First collect cumulative ACKs without mutating the queue while an
        // element is borrowed. Remove from the back afterwards so indices
        // remain valid.
        let mut cumulative_remove = Vec::new();
        for (i, entry) in queue.iter().enumerate() {
            if !entry.acked && entry.seq.is_before(ack_seq) {
                acked_bytes += entry.data.len() as u64;
                if rtt_sample.is_none() {
                    if let Some(sent) = entry.sent {
                        rtt_sample = Some(now.duration_since(sent));
                    }
                }
                cumulative_remove.push(i);
            }
        }
        for i in cumulative_remove.into_iter().rev() {
            queue.remove(i);
        }

        // SACK blocks are handled separately. An entry can only be present
        // once because cumulatively acknowledged entries were removed above.
        let mut sack_remove = Vec::new();
        for (i, entry) in queue.iter().enumerate() {
            if entry.acked {
                continue;
            }

            let sacked = sack_blocks.iter().any(|block| {
                !entry.seq.is_before(block.start) && !block.end.is_before(entry.seq)
            });

            if sacked {
                acked_bytes += entry.data.len() as u64;
                if rtt_sample.is_none() {
                    if let Some(sent) = entry.sent {
                        rtt_sample = Some(now.duration_since(sent));
                    }
                }
                sack_remove.push(i);
            }
        }
        for i in sack_remove.into_iter().rev() {
            queue.remove(i);
        }

        let live: std::collections::HashSet<SeqNum> = queue.iter().map(|e| e.seq).collect();
        self.stream_meta.write().retain(|seq, _| live.contains(seq));
        drop(queue);
        self.space_notify.notify_waiters();

        if acked_bytes > 0 {
            let _ = self.in_flight.fetch_update(
                Ordering::Relaxed,
                Ordering::Relaxed,
                |current| Some(current.saturating_sub(acked_bytes)),
            );
        }
        self.stats.in_flight.store(self.in_flight.load(Ordering::Relaxed), Ordering::Relaxed);

        let mut cc = self.cc.write();
        cc.on_ack(now, acked_bytes, rtt_sample);
        self.stats.cwnd.store(cc.cwnd() as u64, Ordering::Relaxed);
        drop(cc);

        if let Some(rtt) = rtt_sample {
            let ms = rtt.as_millis() as u64;
            self.stats.rtt_avg.store(ms, Ordering::Relaxed);
            self.stats.rtt_min.fetch_min(ms, Ordering::Relaxed);
            self.stats.rtt_max.fetch_max(ms, Ordering::Relaxed);

            if let Some(path_id) = path_id {
                self.multi_path.update_path_quality(path_id, rtt, false);
            }
        }

        let queue_len = self.send_queue.read().len();
        self.stats.queue_length.store(queue_len as u64, Ordering::Relaxed);
    }

    pub fn on_loss(&self, now: Instant) {
        let mut cc = self.cc.write();
        cc.on_loss(now);
        drop(cc);
        self.stats.packets_lost.fetch_add(1, Ordering::Relaxed);
    }
    
    pub fn get_packets_to_send(&self, now: Instant) -> Vec<(Bytes, SeqNum, bool, u32)> {
        let mut packets = Vec::with_capacity(MAX_BATCH_SIZE);
        let rto = self.cc.read().rto();
        
        let mut queue = self.send_queue.write();
        
        for entry in queue.iter_mut() {
            if entry.acked || entry.sent.is_none() {
                continue;
            }
            
            let sent_time = entry.sent.unwrap();
            let aggressive_rto = Duration::from_millis(
                (rto.as_millis() as f64 * AGGRESSIVE_RETRANSMIT_MULTIPLIER) as u64
            );
            let timeout = aggressive_rto * (1 << entry.retries.min(3));
            
            if now.duration_since(sent_time) > timeout {
                if entry.retries < self.max_retries {
                    entry.retries += 1;
                    entry.sent = Some(now);
                    entry.last_sent = Some(now);
                    
                    let path_id = self.select_retransmit_path(entry.path_id);
                    entry.path_id = Some(path_id);
                    
                    packets.push((entry.data.clone(), entry.seq, true, path_id));
                    self.stats.packets_retransmitted.fetch_add(1, Ordering::Relaxed);
                    
                    let mut cc = self.cc.write();
                    cc.on_timeout(now);
                    drop(cc);
                } else {
                    entry.acked = true;
                    self.stats.packets_lost.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        
        let mut sent_count = 0;
        // Keep one congestion-control write lock for the batch.
        let mut cc = self.cc.write();
        let pacing_rate = cc.pacing_rate_bytes(self.mtu.load(Ordering::Relaxed)).max(1.0);
        let mut pace = self.pacing.lock();
        let elapsed = now.duration_since(pace.0).as_secs_f64();
        pace.1 = (pace.1 + elapsed * pacing_rate).min((self.mtu.load(Ordering::Relaxed) as f64) * cc.cwnd());
        pace.0 = now;
        while cc.can_send(self.in_flight.load(Ordering::Relaxed) as u32, self.mtu.load(Ordering::Relaxed))
            && pace.1 >= 1.0 && sent_count < MAX_BATCH_SIZE {
            let mut found = false;
            
            for entry in queue.iter_mut() {
                if !entry.acked && entry.sent.is_none() {
                    entry.sent = Some(now);
                    entry.last_sent = Some(now);
                    let bytes_sent = entry.data.len() as u64;
                    self.in_flight.fetch_add(bytes_sent, Ordering::Relaxed);
                    cc.on_packet_sent(now, bytes_sent);
                    pace.1 = (pace.1 - bytes_sent as f64).max(0.0);

                    let path_id = self.select_best_path();
                    entry.path_id = Some(path_id);
                    
                    if self.fec_enabled {
                        let mut generated = Vec::new();
                        if let Some(plugin) = &self.fec_plugin {
                            generated.extend(plugin.encode(&[(entry.seq, entry.data.clone())]));
                        } else {
                            let mut fec = self.fec.write();
                            if let Some(fec_packets) = fec.push(entry.seq, entry.data.clone()) {
                                generated.extend(fec_packets);
                            }
                        }
                        if !generated.is_empty() {
                            let mut pending = self.pending_fec.lock();
                            for packet in generated {
                                if packet.encode(self.conn_id).len() <= self.mtu.load(Ordering::Relaxed) as usize {
                                    pending.push_back((packet, path_id));
                                }
                            }
                        }
                    }
                    
                    packets.push((entry.data.clone(), entry.seq, false, path_id));
                    self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                    self.stats.bytes_sent.fetch_add(entry.data.len() as u64, Ordering::Relaxed);
                    
                    self.multi_path.record_send(path_id, entry.data.len());
                    
                    sent_count += 1;
                    found = true;
                    break;
                }
            }
            
            if !found {
                break;
            }
        }
        
        drop(queue);
        
        self.stats.in_flight.store(self.in_flight.load(Ordering::Relaxed), Ordering::Relaxed);
        let queue_len = self.send_queue.read().len();
        self.stats.queue_length.store(queue_len as u64, Ordering::Relaxed);
        
        packets
    }
    
    fn select_best_path(&self) -> u32 {
        match self.multi_path.select_path() {
            Ok(path_idx) => {
                if let Some(path) = self.multi_path.paths().get(path_idx) {
                    path.id
                } else {
                    0
                }
            }
            Err(_) => 0,
        }
    }
    
    fn select_retransmit_path(&self, original_path: Option<u32>) -> u32 {
        let best_paths = self.multi_path.get_best_paths(3);
        
        if best_paths.len() >= 2 {
            for &path_idx in &best_paths {
                if let Some(path) = self.multi_path.paths().get(path_idx) {
                    if Some(path.id) != original_path {
                        return path.id;
                    }
                }
            }
        }
        
        if let Some(&path_idx) = best_paths.first() {
            if let Some(path) = self.multi_path.paths().get(path_idx) {
                return path.id;
            }
        }
        
        0
    }
    
    pub fn get_fec_packets(&self) -> Vec<(FecPacket, u32)> {
        if !self.fec_enabled {
            return Vec::new();
        }
        
        let mut fec_packets = Vec::new();
        let mut pending = self.pending_fec.lock();
        while let Some(item) = pending.pop_front() {
            fec_packets.push(item);
            if fec_packets.len() >= MAX_BATCH_SIZE { break; }
        }
        fec_packets
    }
    
    pub fn flush_fec(&self) -> Vec<(FecPacket, u32)> {
        if !self.fec_enabled || self.fec_plugin.is_some() { return Vec::new(); }
        let mut out = Vec::new();
        let mut fec = self.fec.write();
        if let Some(packets) = fec.flush() {
            let path_id = self.select_best_path();
            let mtu = self.mtu.load(Ordering::Relaxed) as usize;
            let mut pending = self.pending_fec.lock();
            for packet in packets {
                if packet.encode(self.conn_id).len() <= mtu {
                    pending.push_back((packet, path_id));
                }
            }
            while let Some(item) = pending.pop_front() { out.push(item); }
        }
        out
    }

    pub fn cleanup_acked(&self) {
        let mut queue = self.send_queue.write();
        let before = queue.len();
        let mut acked_seqs = Vec::new();
        queue.retain(|entry| { if entry.acked { acked_seqs.push(entry.seq); false } else { true } });
        if !acked_seqs.is_empty() {
            let mut meta = self.stream_meta.write();
            for seq in acked_seqs { meta.remove(&seq); }
        }
        if queue.len() < before {
            debug!("Cleaned up {} acked packets", before - queue.len());
        }
        drop(queue);
        
        let queue_len = self.send_queue.read().len();
        self.stats.queue_length.store(queue_len as u64, Ordering::Relaxed);
    }
    
    pub fn set_notify(&self, notify: Arc<Notify>) {
        *self.notify.lock() = Some(notify);
    }
    
    pub fn mtu(&self) -> u16 { self.mtu.load(Ordering::Relaxed) }
    pub fn set_mtu(&self, mtu: u16) -> Result<()> {
        if mtu < 576 { return Err(ArkTPError::InvalidConfig("MTU must be >= 576".into())); }
        let max = mtu as usize - PacketHeader::SIZE - TAG_SIZE;
        if self.send_queue.read().iter().any(|e| e.data.len() > max) {
            return Err(ArkTPError::PacketTooLarge { max });
        }
        self.mtu.store(mtu, Ordering::Relaxed);
        Ok(())
    }

    pub fn stats(&self) -> Arc<ArkTPStats> {
        self.stats.clone()
    }

    pub fn in_flight(&self) -> u32 {
        self.in_flight.load(Ordering::Relaxed) as u32
    }

    pub fn queue_len(&self) -> usize {
        self.send_queue.read().len()
    }
    
    pub fn fec_plugin(&self) -> Option<Arc<dyn FecPlugin>> { self.fec_plugin.clone() }

    pub fn notify_space(&self) -> Arc<Notify> { self.space_notify.clone() }

    pub fn set_congestion_control(&self, cc: Box<dyn CongestionControl>) {
        *self.cc.write() = cc;
    }

    pub fn pacing_rate(&self) -> f64 { self.cc.read().pacing_rate() }

    pub fn multi_path(&self) -> Arc<MultiPathManager> {
        self.multi_path.clone()
    }
}

