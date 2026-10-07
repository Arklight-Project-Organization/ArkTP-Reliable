use std::{
    collections::VecDeque,
    convert::TryInto,
    time::Instant,
};
use bytes::Bytes;

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use rayon::prelude::*;

use crate::*;

pub trait FecPlugin: Send + Sync {
    fn encode(&self, packets: &[(SeqNum, Bytes)]) -> Vec<FecPacket>;
    fn recover(&self, _packets: &mut Vec<(SeqNum, Bytes)>) -> bool { false }
}


// ==================== 自适应FEC ====================
#[derive(Clone)]
pub struct AdaptiveFecEncoder {
    min_group_size: usize,
    max_group_size: usize,
    current_group_size: usize,
    current_group: Vec<(SeqNum, Bytes)>,
    group_id: u32,
    loss_rate: f64,
    parity_packets: usize,
}

impl AdaptiveFecEncoder {
    pub fn new(min_group_size: usize, max_group_size: usize) -> Self {
        let min_group_size = min_group_size.max(2);
        let max_group_size = max_group_size.max(min_group_size);
        
        Self {
            min_group_size,
            max_group_size,
            current_group_size: min_group_size,
            current_group: Vec::with_capacity(min_group_size),
            group_id: 0,
            loss_rate: 0.0,
            parity_packets: 1,
        }
    }
    
    pub fn update_loss_rate(&mut self, loss_rate: f64) {
        self.loss_rate = loss_rate;
        
        if loss_rate > 0.1 {
            self.current_group_size = self.min_group_size;
            self.parity_packets = 2;
        } else if loss_rate > 0.05 {
            self.current_group_size = self.min_group_size;
            self.parity_packets = 1;
        } else if loss_rate > 0.01 {
            self.current_group_size = (self.min_group_size + self.max_group_size) / 2;
            self.parity_packets = 1;
        } else {
            self.current_group_size = self.max_group_size;
            self.parity_packets = 1;
        }
    }

    pub fn push(&mut self, seq: SeqNum, data: Bytes) -> Option<Vec<FecPacket>> {
        self.current_group.push((seq, data));
        
        if self.current_group.len() >= self.current_group_size {
            Some(self.create_fec_packets())
        } else {
            None
        }
    }
    
    pub fn flush(&mut self) -> Option<Vec<FecPacket>> {
        if self.current_group.is_empty() {
            return None;
        }
        Some(self.create_fec_packets())
    }
    
    /// Multiply two bytes in GF(2^8) using the AES polynomial x^8+x^4+x^3+x+1.
    /// This is used for the weighted parity packets.
    #[inline]
    fn galois_mul(mut a: u8, mut b: u8) -> u8 {
        let mut p = 0u8;
        for _ in 0..8 {
            if b & 1 != 0 { p ^= a; }
            let hi = a & 0x80;
            a <<= 1;
            if hi != 0 { a ^= 0x1b; }
            b >>= 1;
        }
        p
    }

    fn create_fec_packets(&mut self) -> Vec<FecPacket> {
        self.group_id = self.group_id.wrapping_add(1);
        let group_id = self.group_id;
        let seqs: Vec<SeqNum> = self.current_group.iter().map(|(s, _)| *s).collect();
        let lengths: Vec<u16> = self.current_group.iter().map(|(_, d)| d.len().min(u16::MAX as usize) as u16).collect();
        
        let max_len = self.current_group.iter().map(|(_, d)| d.len()).max().unwrap_or(0);
        
        let mut fec_packets = Vec::with_capacity(self.parity_packets);
        
        for parity_index in 0..self.parity_packets {
            let mut parity = vec![0u8; max_len];
            for (i, (_, data)) in self.current_group.iter().enumerate() {
                if parity_index == 0 {
                    for j in 0..data.len() {
                        parity[j] ^= data[j];
                    }
                } else {
                    let weight = (i + 1) as u8;
                    for j in 0..data.len() {
                        parity[j] ^= Self::galois_mul(data[j], weight);
                    }
                }
            }
            
            fec_packets.push(FecPacket {
                group_id,
                seqs: seqs.clone(),
                lengths: lengths.clone(),
                parity: Bytes::from(parity),
                parity_index: parity_index as u8,
            });
        }
        
        self.current_group.clear();
        fec_packets
    }
}

#[derive(Clone)]
pub struct FecPacket {
    pub group_id: u32,
    pub seqs: Vec<SeqNum>,
    /// Original payload length for every source sequence. This prevents XOR
    /// recovery from returning padding bytes when source packets have different
    /// lengths.
    pub lengths: Vec<u16>,
    pub parity: Bytes,
    pub parity_index: u8,
}

impl FecPacket {
    pub fn encode(&self, conn_id: u64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            PacketHeader::SIZE + 4 + 1 + 2 + self.seqs.len() * 6 + self.parity.len()
        );
        
        let header = PacketHeader {
            pkt_type: PacketType::Fec as u8,
            flags: 0,
            seq: 0,
            ack: 0,
            conn_id,
            timestamp: now_ms(),
        };
        
        buf.extend_from_slice(&header.encode());
        buf.extend_from_slice(&self.group_id.to_be_bytes());
        buf.push(self.parity_index);
        buf.extend_from_slice(&(self.seqs.len() as u16).to_be_bytes());
        if self.lengths.len() != self.seqs.len() { return Vec::new(); }
        for (seq, len) in self.seqs.iter().zip(&self.lengths) {
            buf.extend_from_slice(&seq.0.to_be_bytes());
            buf.extend_from_slice(&len.to_be_bytes());
        }
        buf.extend_from_slice(&self.parity);
        
        buf
    }
    
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < PacketHeader::SIZE + 7 {
            return None;
        }
        
        let group_id = u32::from_be_bytes(
            data[PacketHeader::SIZE..PacketHeader::SIZE + 4].try_into().ok()?
        );
        let parity_index = data[PacketHeader::SIZE + 4];
        let seq_count = u16::from_be_bytes(
            data[PacketHeader::SIZE + 5..PacketHeader::SIZE + 7].try_into().ok()?
        ) as usize;
        
        if seq_count == 0 {
            return None;
        }

        let mut seqs = Vec::with_capacity(seq_count);
        let mut lengths = Vec::with_capacity(seq_count);
        let mut offset = PacketHeader::SIZE + 7;
        for _ in 0..seq_count {
            if offset + 6 > data.len() {
                return None;
            }
            let seq = SeqNum::new(u32::from_be_bytes(
                data[offset..offset + 4].try_into().ok()?
            ));
            let len = u16::from_be_bytes(data[offset + 4..offset + 6].try_into().ok()?);
            seqs.push(seq);
            lengths.push(len);
            offset += 6;
        }
        
        if offset > data.len() {
            return None;
        }
        
        let parity = Bytes::copy_from_slice(&data[offset..]);
        
        Some(Self {
            group_id,
            seqs,
            lengths,
            parity,
            parity_index,
        })
    }
}

// ==================== 智能FEC（Reed-Solomon） ====================
pub struct ReedSolomonFec {
    data_shards: usize,
    parity_shards: usize,
    total_shards: usize,
    generator: Vec<Vec<u8>>,
}

impl ReedSolomonFec {
    pub fn new(data_shards: usize, parity_shards: usize) -> Self {
        let total_shards = data_shards + parity_shards;
        
        let mut generator = vec![vec![0u8; data_shards]; total_shards];
        for i in 0..total_shards {
            for j in 0..data_shards {
                generator[i][j] = Self::galois_pow(i as u8, j as u8);
            }
        }
        
        Self {
            data_shards,
            parity_shards,
            total_shards,
            generator,
        }
    }
    
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        if data.is_empty() {
            return Err(ArkTPError::FecRecoveryFailed("Empty data".to_string()));
        }
        
        let shard_size = (data.len() + self.data_shards - 1) / self.data_shards;
        let mut shards = vec![vec![0u8; shard_size]; self.total_shards];
        
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = std::cmp::min(start + shard_size, data.len());
            if start < data.len() {
                shards[i][..end - start].copy_from_slice(&data[start..end]);
            }
        }
        
        for i in self.data_shards..self.total_shards {
            for j in 0..shard_size {
                let mut sum = 0u8;
                for k in 0..self.data_shards {
                    sum ^= Self::galois_mul(self.generator[i][k], shards[k][j]);
                }
                shards[i][j] = sum;
            }
        }
        
        Ok(shards)
    }
    
    pub fn decode(&self, shards: &[Option<Vec<u8>>]) -> Result<Vec<u8>> {
        if shards.len() != self.total_shards {
            return Err(ArkTPError::FecRecoveryFailed("Invalid shard count".to_string()));
        }
        
        let available_shards: Vec<usize> = shards.iter()
            .enumerate()
            .filter(|(_, s)| s.is_some())
            .map(|(i, _)| i)
            .collect();
        
        if available_shards.len() < self.data_shards {
            return Err(ArkTPError::FecRecoveryFailed("Not enough shards for recovery".to_string()));
        }
        
        let shard_size = shards[available_shards[0]].as_ref().unwrap().len();
        let mut recovered_data = vec![0u8; self.data_shards * shard_size];
        
        let mut decode_matrix = vec![vec![0u8; self.data_shards]; self.data_shards];
        for i in 0..self.data_shards {
            decode_matrix[i].copy_from_slice(&self.generator[available_shards[i]][..self.data_shards]);
        }
        
        let inverse_matrix = Self::matrix_inverse(&decode_matrix)
            .ok_or(ArkTPError::FecRecoveryFailed("Matrix inversion failed".to_string()))?;
        
        for i in 0..self.data_shards {
            for j in 0..shard_size {
                let mut sum = 0u8;
                for k in 0..self.data_shards {
                    sum ^= Self::galois_mul(
                        inverse_matrix[i][k],
                        shards[available_shards[k]].as_ref().unwrap()[j]
                    );
                }
                recovered_data[i * shard_size + j] = sum;
            }
        }
        
        Ok(recovered_data)
    }
    
    fn matrix_inverse(matrix: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        let n = matrix.len();
        let mut augmented = vec![vec![0u8; n * 2]; n];
        
        for i in 0..n {
            for j in 0..n {
                augmented[i][j] = matrix[i][j];
            }
            augmented[i][n + i] = 1;
        }
        
        for col in 0..n {
            let mut pivot_row = None;
            for row in col..n {
                if augmented[row][col] != 0 {
                    pivot_row = Some(row);
                    break;
                }
            }
            
            let pivot_row = pivot_row?;
            
            if pivot_row != col {
                augmented.swap(col, pivot_row);
            }
            
            let pivot = augmented[col][col];
            let pivot_inv = Self::galois_inverse(pivot)?;
            for j in 0..n * 2 {
                augmented[col][j] = Self::galois_mul(augmented[col][j], pivot_inv);
            }
            
            for row in 0..n {
                if row != col {
                    let factor = augmented[row][col];
                    if factor != 0 {
                        for j in 0..n * 2 {
                            augmented[row][j] ^= Self::galois_mul(factor, augmented[col][j]);
                        }
                    }
                }
            }
        }
        
        let mut inverse = vec![vec![0u8; n]; n];
        for i in 0..n {
            for j in 0..n {
                inverse[i][j] = augmented[i][n + j];
            }
        }
        
        Some(inverse)
    }
    
    fn galois_pow(base: u8, exp: u8) -> u8 {
        let mut result = 1u8;
        let mut b = base;
        let mut e = exp;
        
        while e > 0 {
            if e & 1 == 1 {
                result = Self::galois_mul(result, b);
            }
            b = Self::galois_mul(b, b);
            e >>= 1;
        }
        
        result
    }
    
    pub(crate) fn galois_mul(a: u8, b: u8) -> u8 {
        let mut result = 0u8;
        let mut aa = a;
        let mut bb = b;
        
        while bb > 0 {
            if bb & 1 == 1 {
                result ^= aa;
            }
            let high_bit = aa & 0x80;
            aa <<= 1;
            if high_bit != 0 {
                aa ^= 0x1b;
            }
            bb >>= 1;
        }
        
        result
    }
    
    pub(crate) fn galois_inverse(a: u8) -> Option<u8> {
        if a == 0 {
            return None;
        }
        
        for i in 1..=255u8 {
            if Self::galois_mul(a, i) == 1 {
                return Some(i);
            }
        }
        
        None
    }
}

// ==================== 智能自适应FEC ====================
pub struct SmartAdaptiveFec {
    xor_fec: AdaptiveFecEncoder,
    rs_fec: Option<ReedSolomonFec>,
    current_mode: FecMode,
    loss_rate: f64,
    history: VecDeque<(Instant, f64)>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FecMode {
    Disabled,
    Xor,
    ReedSolomon,
    Hybrid,
}

impl SmartAdaptiveFec {
    pub fn new() -> Self {
        Self {
            xor_fec: AdaptiveFecEncoder::new(2, 32),
            rs_fec: None,
            current_mode: FecMode::Xor,
            loss_rate: 0.0,
            history: VecDeque::with_capacity(64),
        }
    }
    
    pub fn update_loss_rate(&mut self, loss_rate: f64) {
        self.loss_rate = loss_rate;
        self.history.push_back((Instant::now(), loss_rate));
        
        if self.history.len() > 64 {
            self.history.pop_front();
        }
        
        let avg_loss = self.history.iter()
            .map(|(_, l)| *l)
            .sum::<f64>() / self.history.len() as f64;
        
        self.current_mode = if avg_loss < 0.01 {
            FecMode::Xor
        } else if avg_loss < 0.05 {
            if self.rs_fec.is_none() {
                self.rs_fec = Some(ReedSolomonFec::new(8, 2));
            }
            FecMode::ReedSolomon
        } else {
            if self.rs_fec.is_none() {
                self.rs_fec = Some(ReedSolomonFec::new(8, 4));
            }
            FecMode::Hybrid
        };
    }
    
    pub fn encode(&mut self, data: &[u8], seq: SeqNum) -> Vec<FecPacket> {
        match self.current_mode {
            FecMode::Disabled => vec![],
            FecMode::Xor => {
                if let Some(packets) = self.xor_fec.push(seq, Bytes::copy_from_slice(data)) {
                    packets
                } else {
                    vec![]
                }
            }
            FecMode::ReedSolomon => {
                if let Some(rs) = &self.rs_fec {
                    if let Ok(shards) = rs.encode(data) {
                        shards.into_iter()
                            .enumerate()
                            .skip(rs.data_shards)
                            .map(|(i, parity)| FecPacket {
                                group_id: seq.0,
                                seqs: vec![seq],
                                lengths: vec![data.len().min(u16::MAX as usize) as u16],
                                parity: Bytes::from(parity),
                                parity_index: (i - rs.data_shards) as u8,
                            })
                            .collect()
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                }
            }
            FecMode::Hybrid => {
                let mut packets = vec![];
                
                if let Some(packets_xor) = self.xor_fec.push(seq, Bytes::copy_from_slice(data)) {
                    packets.extend(packets_xor);
                }
                
                if let Some(rs) = &self.rs_fec {
                    if let Ok(shards) = rs.encode(data) {
                        let rs_packets: Vec<FecPacket> = shards.into_iter()
                            .enumerate()
                            .skip(rs.data_shards)
                            .map(|(i, parity)| FecPacket {
                                group_id: seq.0,
                                seqs: vec![seq],
                                lengths: vec![data.len().min(u16::MAX as usize) as u16],
                                parity: Bytes::from(parity),
                                parity_index: (i - rs.data_shards + 2) as u8,
                            })
                            .collect();
                        packets.extend(rs_packets);
                    }
                }
                
                packets
            }
        }
    }
    
    pub fn get_mode(&self) -> FecMode {
        self.current_mode.clone()
    }
}

