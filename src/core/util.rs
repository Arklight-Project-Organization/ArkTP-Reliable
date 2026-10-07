use std::time::{SystemTime, UNIX_EPOCH};

// 加密相关

// 后量子密码学

// 性能优化
use rayon::prelude::*;

use crate::*;

// ==================== 工具函数 ====================
pub fn build_ack_packet(conn_id: u64, ack_seq: SeqNum, sack_blocks: &[SackBlock]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(PacketHeader::SIZE + 6 + sack_blocks.len() * 8);
    
    let header = PacketHeader {
        pkt_type: PacketType::Ack as u8,
        flags: 0,
        seq: 0,
        ack: ack_seq.0,
        conn_id,
        timestamp: now_ms(),
    };
    
    packet.extend_from_slice(&header.encode());
    packet.extend_from_slice(&encode_ack(ack_seq, sack_blocks, 0, 0, 0, 0));
    
    packet
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

