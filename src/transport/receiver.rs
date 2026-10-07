use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use bytes::Bytes;
use log::debug;

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use parking_lot::RwLock as PLRwLock;
use flume::Sender;
use rayon::prelude::*;

use crate::*;

// ==================== 接收端 ====================
pub struct ArkTPReceiver {
    conn_id: u64,
    max_buffer: usize,
    recv_buffer: Arc<PLRwLock<BTreeMap<SeqNum, Bytes>>>,
    next_seq: Arc<AtomicU64>,
    fec_groups: Arc<PLRwLock<HashMap<u32, FecGroup>>>,
    fec_enabled: bool,
    stats: Arc<ArkTPStats>,
    recv_channel: Sender<Bytes>,
    multi_path: Arc<MultiPathManager>,
}

pub struct FecGroup {
    seqs: Vec<SeqNum>,
    lengths: Vec<u16>,
    packets: HashMap<SeqNum, Bytes>,
    parity: Vec<Option<Bytes>>,
    updated_at: Instant,
}

impl ArkTPReceiver {
    pub fn new(conn_id: u64, recv_channel: Sender<Bytes>) -> Self {
        Self::with_config(conn_id, ArkTPConfig::default(), recv_channel)
    }

    pub fn with_config(
        conn_id: u64,
        config: ArkTPConfig,
        recv_channel: Sender<Bytes>,
    ) -> Self {
        Self {
            conn_id,
            max_buffer: config.receive_buffer_size,
            recv_buffer: Arc::new(PLRwLock::new(BTreeMap::new())),
            next_seq: Arc::new(AtomicU64::new(1)),
            fec_groups: Arc::new(PLRwLock::new(HashMap::new())),
            fec_enabled: config.fec_enabled,
            stats: config.stats.unwrap_or_else(|| Arc::new(ArkTPStats::new())),
            recv_channel,
            multi_path: Arc::new(MultiPathManager::new()),
        }
    }
    
    pub fn add_path(&self, socket: Arc<UdpSocket>, remote_addr: SocketAddr) -> Result<u32> {
        let path_id = self.multi_path.add_path(socket, remote_addr)?;
        self.stats.active_paths.store(self.multi_path.path_count() as u64, Ordering::Relaxed);
        Ok(path_id)
    }

    pub fn on_data_packet(&self, seq: SeqNum, data: Bytes, path_id: Option<u32>) -> bool {
        self.stats.packets_received.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_received.fetch_add(data.len() as u64, Ordering::Relaxed);
        
        if let Some(path_id) = path_id {
            self.multi_path.record_receive(path_id, data.len());
        }
        
        let next_seq = SeqNum::new(self.next_seq.load(Ordering::Relaxed) as u32);
        if !seq.in_window(next_seq, MAX_SEQ_WINDOW) {
            debug!("Packet {} outside window", seq);
            return false;
        }
        
        let mut buffer = self.recv_buffer.write();
        if !buffer.contains_key(&seq) && buffer.len() < self.max_buffer {
            buffer.insert(seq, data.clone());
            
            if self.fec_enabled {
                let mut fec_groups = self.fec_groups.write();
                for group in fec_groups.values_mut() {
                    if group.seqs.contains(&seq) && !group.packets.contains_key(&seq) {
                        group.packets.insert(seq, data.clone());
                        group.updated_at = Instant::now();
                    }
                }
            }
        }
        drop(buffer);
        
        self.try_deliver();
        true
    }
    
    pub fn on_fec_packet(&self, fec_packet: FecPacket, _path_id: Option<u32>) {
        if !self.fec_enabled {
            return;
        }

        let group_id = fec_packet.group_id;

        // Reject malformed/inconsistent sequence metadata before touching
        // receiver state. A FEC group must contain unique sequence numbers.
        let unique_count = fec_packet.seqs.iter().collect::<HashSet<_>>().len();
        if unique_count != fec_packet.seqs.len() {
            return;
        }

        // Snapshot data before taking fec_groups. The normal data path takes
        // recv_buffer -> fec_groups, so acquiring the locks in this order
        // prevents a lock-order inversion.
        let received: Vec<(SeqNum, Bytes)> = {
            let buffer = self.recv_buffer.read();
            fec_packet.seqs.iter()
                .filter_map(|seq| buffer.get(seq).map(|data| (*seq, data.clone())))
                .collect()
        };

        let now = Instant::now();
        let mut fec_groups = self.fec_groups.write();
        let group = fec_groups.entry(group_id).or_insert_with(|| FecGroup {
            seqs: fec_packet.seqs.clone(),
            lengths: fec_packet.lengths.clone(),
            packets: HashMap::new(),
            parity: Vec::new(),
            updated_at: now,
        });

        // Every parity packet for a group must describe exactly the same
        // source sequence set. Reject inconsistent metadata rather than
        // combining incompatible parity blocks.
        if group.seqs != fec_packet.seqs || group.lengths != fec_packet.lengths {
            return;
        }

        if group.parity.iter().flatten().any(|existing| existing.len() != fec_packet.parity.len()) {
            return;
        }

        for (seq, data) in received {
            group.packets.insert(seq, data);
        }

        if group.parity.len() <= fec_packet.parity_index as usize {
            group.parity.resize(fec_packet.parity_index as usize + 1, None);
        }
        group.parity[fec_packet.parity_index as usize] = Some(fec_packet.parity);
        group.updated_at = now;

        drop(fec_groups);
        self.try_recover(group_id);
    }

    fn try_recover(&self, group_id: u32) {
        let mut recovered_packets = Vec::new();
        
        let mut fec_groups = self.fec_groups.write();
        if let Some(group) = fec_groups.get(&group_id) {
            for (parity_index, parity) in group.parity.iter().enumerate() {
                if let Some(parity) = parity {
                    let missing_count = group.seqs.iter()
                        .filter(|seq| !group.packets.contains_key(seq))
                        .count();
                    
                    if missing_count == 1 {
                        let missing_seq = group.seqs.iter()
                            .find(|seq| !group.packets.contains_key(seq))
                            .copied();
                        
                        if let Some(seq) = missing_seq {
                            let max_len = parity.len();
                            let mut recovered = vec![0u8; max_len];
                            
                            if parity_index == 0 {
                                for (_, data) in &group.packets {
                                    for i in 0..data.len().min(max_len) {
                                        recovered[i] ^= data[i];
                                    }
                                }
                                for i in 0..max_len {
                                    recovered[i] ^= parity[i];
                                }
                            } else {
                                // The weighted parity uses the packet's position in
                                // group.seqs, not HashMap iteration order, and all
                                // arithmetic must be performed in GF(256).
                                for (packet_seq, data) in &group.packets {
                                    let data_index = match group.seqs.iter().position(|s| s == packet_seq) {
                                        Some(index) => index,
                                        None => continue,
                                    };
                                    let weight = (data_index + 1) as u8;
                                    for j in 0..data.len().min(max_len) {
                                        recovered[j] ^= ReedSolomonFec::galois_mul(data[j], weight);
                                    }
                                }
                                for i in 0..max_len {
                                    recovered[i] ^= parity[i];
                                }
                                let missing_index = match group.seqs.iter().position(|s| *s == seq) {
                                    Some(index) => index,
                                    None => continue,
                                };
                                let weight = (missing_index + 1) as u8;
                                let inverse = match ReedSolomonFec::galois_inverse(weight) {
                                    Some(value) => value,
                                    None => continue,
                                };
                                for byte in &mut recovered {
                                    *byte = ReedSolomonFec::galois_mul(*byte, inverse);
                                }
                            }
                            
                            let target_len = group.seqs.iter().position(|s| *s == seq)
                                .and_then(|i| group.lengths.get(i).copied())
                                .map(|v| v as usize)
                                .unwrap_or(recovered.len());
                            recovered.truncate(target_len.min(recovered.len()));
                            if !recovered.is_empty() {
                                recovered_packets.push((seq, Bytes::from(recovered)));
                                self.stats.fec_recovered.fetch_add(1, Ordering::Relaxed);
                                debug!("Recovered packet {} via FEC (parity {})", seq, parity_index);
                                // One missing packet needs only one successful
                                // parity equation; avoid counting/recovering it twice.
                                break;
                            }
                        }
                    }
                }
            }
        }
        
        // Mark recovered packets in the FEC group before deciding whether
        // the group can be discarded. Otherwise the same missing packet could
        // be recovered repeatedly whenever another parity packet arrives.
        if let Some(group) = fec_groups.get_mut(&group_id) {
            for (seq, data) in &recovered_packets {
                group.packets.insert(*seq, data.clone());
                group.updated_at = Instant::now();
            }
        }

        const FEC_GROUP_TTL: Duration = Duration::from_secs(10);

        // A group is useful while it has parity and is not fully recovered.
        // Keep a single-missing-packet group as well: another parity packet
        // may still arrive and provide a valid recovery attempt. Groups with
        // no parity or that have been complete are removed immediately;
        // incomplete groups are bounded by a TTL to prevent unbounded growth.
        let now = Instant::now();
        fec_groups.retain(|_, group| {
            let complete = group.seqs.iter().all(|seq| group.packets.contains_key(seq));
            let has_parity = group.parity.iter().any(|p| p.is_some());

            !complete && has_parity && now.duration_since(group.updated_at) <= FEC_GROUP_TTL
        });
        drop(fec_groups);
        
        if !recovered_packets.is_empty() {
            let mut buffer = self.recv_buffer.write();
            for (seq, data) in recovered_packets {
                if !buffer.contains_key(&seq) {
                    buffer.insert(seq, data);
                }
            }
        }
        
        self.try_deliver();
    }
    
    fn try_deliver(&self) {
        let mut buffer = self.recv_buffer.write();
        let mut next_seq = SeqNum::new(self.next_seq.load(Ordering::Relaxed) as u32);
        
        loop {
            let Some(data) = buffer.get(&next_seq).cloned() else { break; };
            match self.recv_channel.try_send(data) {
                Ok(()) => { buffer.remove(&next_seq); next_seq = next_seq.next(); }
                Err(flume::TrySendError::Full(_)) => break, // real backpressure: retain data
                Err(flume::TrySendError::Disconnected(_)) => break,
            }
        }
        
        self.next_seq.store(next_seq.0 as u64, Ordering::Relaxed);
    }
    
    pub fn notify_app_consumed(&self) { self.try_deliver(); }

    pub fn get_sack_blocks(&self) -> Vec<SackBlock> {
        let buffer = self.recv_buffer.read();
        let mut blocks = Vec::new();
        let mut in_block = false;
        let mut start = SeqNum::new(0);
        let mut prev = SeqNum::new(0);
        
        for &seq in buffer.keys() {
            if !in_block {
                start = seq;
                in_block = true;
            } else if seq.0 != prev.0.wrapping_add(1) {
                blocks.push(SackBlock { start, end: prev });
                start = seq;
            }
            prev = seq;
        }
        
        if in_block {
            blocks.push(SackBlock { start, end: prev });
        }
        
        blocks
    }
    
    pub fn should_send_ack(&self, now: Instant, last_ack_sent: &mut Instant) -> bool {
        if now.duration_since(*last_ack_sent) > Duration::from_millis(ACK_INTERVAL_MS) {
            *last_ack_sent = now;
            true
        } else {
            false
        }
    }
    
    pub fn next_seq(&self) -> SeqNum {
        SeqNum::new(self.next_seq.load(Ordering::Relaxed) as u32)
    }
    
    pub fn stats(&self) -> Arc<ArkTPStats> {
        self.stats.clone()
    }
    
    pub fn multi_path(&self) -> Arc<MultiPathManager> {
        self.multi_path.clone()
    }
}

