use std::convert::TryInto;
use serde::{Serialize, Deserialize};

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use rayon::prelude::*;

use crate::*;

// ==================== 协议定义 ====================
#[repr(u8)]
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum PacketType {
    Data = 0,
    Ack = 1,
    Fec = 2,
    KeepAlive = 3,
    KeepAliveAck = 4,
    Syn = 5,
    SynAck = 6,
    Fin = 7,
    Reset = 8,
    DataFec = 9,
    PathProbe = 10,
    PathProbeAck = 11,
    KeyExchange = 12,
    KeyExchangeAck = 13,
    BatchAck = 14,
    CongestionControl = 15,
    NatProbe = 16,
    NatProbeAck = 17,
    AggregatedData = 18,
    PathChallenge = 19,
    PathResponse = 20,
    MaxData = 21,
    MaxStreamData = 22,
    MaxStreams = 23,
    Stream = 24,
    ConnectionClose = 25,
    Retry = 26,
    HandshakeDone = 27,
    NewToken = 28,
    KeyUpdate = 29,
    Extension = 30,
    MtuProbe = 31,
    MtuProbeAck = 32,
}

impl From<u8> for PacketType {
    fn from(value: u8) -> Self {
        match value {
            0 => PacketType::Data,
            1 => PacketType::Ack,
            2 => PacketType::Fec,
            3 => PacketType::KeepAlive,
            4 => PacketType::KeepAliveAck,
            5 => PacketType::Syn,
            6 => PacketType::SynAck,
            7 => PacketType::Fin,
            8 => PacketType::Reset,
            9 => PacketType::DataFec,
            10 => PacketType::PathProbe,
            11 => PacketType::PathProbeAck,
            12 => PacketType::KeyExchange,
            13 => PacketType::KeyExchangeAck,
            14 => PacketType::BatchAck,
            15 => PacketType::CongestionControl,
            16 => PacketType::NatProbe,
            17 => PacketType::NatProbeAck,
            18 => PacketType::AggregatedData,
            19 => PacketType::PathChallenge,
            20 => PacketType::PathResponse,
            21 => PacketType::MaxData,
            22 => PacketType::MaxStreamData,
            23 => PacketType::MaxStreams,
            24 => PacketType::Stream,
            25 => PacketType::ConnectionClose,
            26 => PacketType::Retry,
            27 => PacketType::HandshakeDone,
            28 => PacketType::NewToken,
            29 => PacketType::KeyUpdate,
            30 => PacketType::Extension,
            31 => PacketType::MtuProbe,
            32 => PacketType::MtuProbeAck,
            _ => PacketType::Extension,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketHeader {
    pub pkt_type: u8,
    pub flags: u8,
    pub seq: u32,
    pub ack: u32,
    pub conn_id: u64,
    pub timestamp: u64,
}

impl PacketHeader {
    pub const SIZE: usize = 26;
    pub const VERSION: u8 = 2;
    /// Low four bits are packet flags. Version occupies the high nibble on wire.
    pub const FLAG_MASK: u8 = 0x0F;
    #[deprecated(note = "version is no longer stored in PacketHeader::flags; use FLAG_MASK") ]
    pub const FLAG_VERSION_MASK: u8 = 0xF0;

    #[inline]
    pub fn new(pkt_type: PacketType, seq: u32, conn_id: u64) -> Self {
        Self { pkt_type: pkt_type as u8, flags: 0, seq, ack: 0, conn_id, timestamp: now_ms() }
    }
    #[inline]
    pub fn version_from_wire(byte: u8) -> u8 { byte >> 4 }
    #[inline]
    pub fn version(&self) -> u8 { Self::VERSION }
    #[inline]
    pub fn wire_flags(&self) -> u8 { self.flags & Self::FLAG_MASK }
    pub fn ecn(&self) -> u8 { self.flags & 0x03 }
    pub fn set_ecn(&mut self, ecn: u8) { self.flags = (self.flags & !0x03) | (ecn & 0x03); }

    #[inline]
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.pkt_type;
        buf[1] = (Self::VERSION << 4) | (self.flags & Self::FLAG_MASK);
        buf[2..6].copy_from_slice(&self.seq.to_be_bytes());
        buf[6..10].copy_from_slice(&self.ack.to_be_bytes());
        buf[10..18].copy_from_slice(&self.conn_id.to_be_bytes());
        buf[18..26].copy_from_slice(&self.timestamp.to_be_bytes());
        buf
    }

    #[inline]
    pub fn decode(data: &[u8]) -> Option<Self> {
        let h = Self::decode_any(data)?;
        if Self::version_from_wire(data[1]) != Self::VERSION { return None; }
        Some(h)
    }

    pub fn decode_any(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE { return None; }
        Some(Self {
            pkt_type: data[0],
            flags: data[1] & Self::FLAG_MASK,
            seq: u32::from_be_bytes(data[2..6].try_into().ok()?),
            ack: u32::from_be_bytes(data[6..10].try_into().ok()?),
            conn_id: u64::from_be_bytes(data[10..18].try_into().ok()?),
            timestamp: u64::from_be_bytes(data[18..26].try_into().ok()?),
        })
    }
}

// ==================== SACK ====================
#[derive(Clone, Debug)]
pub struct SackBlock {
    pub start: SeqNum,
    pub end: SeqNum,
}
impl Serialize for SackBlock {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = serializer.serialize_struct("SackBlock", 2)?;
        st.serialize_field("start", &self.start.0)?;
        st.serialize_field("end", &self.end.0)?;
        st.end()
    }
}
impl<'de> Deserialize<'de> for SackBlock {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)] struct Wire { start: u32, end: u32 }
        let w = Wire::deserialize(deserializer)?;
        Ok(Self { start: SeqNum::new(w.start), end: SeqNum::new(w.end) })
    }
}

pub fn encode_sack(ack: SeqNum, blocks: &[SackBlock]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 + blocks.len() * 8);
    buf.extend_from_slice(&ack.0.to_be_bytes());
    buf.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
    for b in blocks {
        buf.extend_from_slice(&b.start.0.to_be_bytes());
        buf.extend_from_slice(&b.end.0.to_be_bytes());
    }
    buf
}

pub fn decode_sack(data: &[u8]) -> Option<(SeqNum, Vec<SackBlock>)> {
    if data.len() < 6 {
        return None;
    }
    let ack = SeqNum::new(u32::from_be_bytes(data[0..4].try_into().ok()?));
    let count = u16::from_be_bytes(data[4..6].try_into().ok()?) as usize;
    let mut blocks = Vec::with_capacity(count);
    let mut off = 6;
    if data.len() != 6 + count * 8 {
        return None;
    }
    for _ in 0..count {
        let start = SeqNum::new(u32::from_be_bytes(data[off..off + 4].try_into().ok()?));
        let end = SeqNum::new(u32::from_be_bytes(data[off + 4..off + 8].try_into().ok()?));
        blocks.push(SackBlock { start, end });
        off += 8;
    }
    Some((ack, blocks))
}

// ==================== 连接状态机 ====================
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Closed,
    Listen,
    SynSent,
    KeyExchanging,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
    Reset,
}



/// A stream frame separates the packet number (`PacketHeader::seq`) from the
/// byte offset within a logical stream. This removes the old seq==offset
/// coupling and allows independent retransmission of packets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamFrame {
    pub stream_id: u64,
    pub offset: u64,
    pub fin: bool,
    pub data: Vec<u8>,
}
impl StreamFrame {
    pub const PREFIX: usize = 17;
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::PREFIX + self.data.len());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.push(self.fin as u8);
        out.extend_from_slice(&self.data);
        out
    }
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < Self::PREFIX { return None; }
        Some(Self {
            stream_id: u64::from_be_bytes(data[0..8].try_into().ok()?),
            offset: u64::from_be_bytes(data[8..16].try_into().ok()?),
            fin: data[16] != 0,
            data: data[17..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AckInfo {
    pub ack: SeqNum,
    pub ack_delay_us: u32,
    pub ect0: u64,
    pub ect1: u64,
    pub ce: u64,
}
impl AckInfo {
    pub fn encode(&self, blocks: &[SackBlock]) -> Vec<u8> {
        let mut out = Vec::with_capacity(36 + blocks.len() * 8);
        out.push(0xA1);
        out.push(1);
        out.extend_from_slice(&self.ack.0.to_be_bytes());
        out.extend_from_slice(&self.ack_delay_us.to_be_bytes());
        out.extend_from_slice(&self.ect0.to_be_bytes());
        out.extend_from_slice(&self.ect1.to_be_bytes());
        out.extend_from_slice(&self.ce.to_be_bytes());
        out.extend_from_slice(&(blocks.len() as u16).to_be_bytes());
        for b in blocks {
            out.extend_from_slice(&b.start.0.to_be_bytes());
            out.extend_from_slice(&b.end.0.to_be_bytes());
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct ExtensionFrame {
    pub kind: u16,
    pub value: Vec<u8>,
}
impl ExtensionFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.value.len());
        out.extend_from_slice(&self.kind.to_be_bytes());
        out.extend_from_slice(&(self.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.value);
        out
    }
    pub fn decode(data: &[u8]) -> Option<Self> {
        if data.len() < 4 { return None; }
        let len = u16::from_be_bytes(data[2..4].try_into().ok()?) as usize;
        if data.len() != len + 4 { return None; }
        Some(Self { kind: u16::from_be_bytes(data[0..2].try_into().ok()?), value: data[4..].to_vec() })
    }
}

#[derive(Debug, Clone, Copy)]
pub struct FlowControl {
    pub max_data: u64,
    pub max_streams: u64,
}
impl FlowControl {
    pub fn encode(&self) -> [u8;16] {
        let mut b=[0u8;16];
        b[..8].copy_from_slice(&self.max_data.to_be_bytes());
        b[8..].copy_from_slice(&self.max_streams.to_be_bytes());
        b
    }
    pub fn decode(b:&[u8])->Option<Self>{
        if b.len()!=16{return None}
        Some(Self{max_data:u64::from_be_bytes(b[..8].try_into().ok()?),max_streams:u64::from_be_bytes(b[8..16].try_into().ok()?)})
    }
}

pub fn encode_ack(ack: SeqNum, blocks: &[SackBlock], ack_delay_us: u32, ect0: u64, ect1: u64, ce: u64) -> Vec<u8> {
    AckInfo { ack, ack_delay_us, ect0, ect1, ce }.encode(blocks)
}
pub fn decode_ack(data: &[u8]) -> Option<(AckInfo, Vec<SackBlock>)> {
    const MAGIC: u8 = 0xA1;
    if data.len() >= 36 && data[0] == MAGIC && data[1] == 1 {
        let ack = SeqNum::new(u32::from_be_bytes(data[2..6].try_into().ok()?));
        let delay = u32::from_be_bytes(data[6..10].try_into().ok()?);
        let ect0 = u64::from_be_bytes(data[10..18].try_into().ok()?);
        let ect1 = u64::from_be_bytes(data[18..26].try_into().ok()?);
        let ce = u64::from_be_bytes(data[26..34].try_into().ok()?);
        let count = u16::from_be_bytes(data[34..36].try_into().ok()?) as usize;
        if data.len() != 36 + count * 8 { return None; }
        let mut blocks = Vec::with_capacity(count);
        let mut off = 36;
        for _ in 0..count {
            blocks.push(SackBlock {
                start: SeqNum::new(u32::from_be_bytes(data[off..off+4].try_into().ok()?)),
                end: SeqNum::new(u32::from_be_bytes(data[off+4..off+8].try_into().ok()?)),
            });
            off += 8;
        }
        return Some((AckInfo { ack, ack_delay_us: delay, ect0, ect1, ce }, blocks));
    }
    let (ack, blocks) = decode_sack(data)?;
    Some((AckInfo { ack, ack_delay_us: 0, ect0: 0, ect1: 0, ce: 0 }, blocks))
}
