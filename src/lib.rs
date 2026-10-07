//! # ArkTP Reliable
//!
//! A reliable, multiplexed UDP transport focused on high bandwidth utilization,
//! predictable backpressure and long-lived connection reliability.
//!
//! The crate is organized by responsibility:
//! * `core`: configuration, errors and primitive types
//! * `wire` / `protocol`: versioned packet formats
//! * `security`: cryptography and NAT helpers
//! * `control`: congestion control and FEC
//! * `transport`: endpoint, connection, streams and paths
//! * `performance`: aggregation/cache/pipeline
//! * `observability`: runtime counters
//! * `api`: high-level client/server endpoint API
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(non_snake_case)]

pub mod core;
pub mod security;
pub mod control;
pub mod protocol;
pub mod wire;
pub mod transport;
pub mod performance;
pub mod observability;
pub mod api;

// Compatibility facades for applications built against earlier ArkTP releases.
pub mod crypto { pub use crate::security::*; }
pub mod perf { pub use crate::performance::*; }

pub use core::*;
pub use security::*;
pub use control::*;
pub use protocol::*;
pub use transport::*;
pub use performance::*;
pub use observability::*;
pub use api::*;

pub mod prelude {
    pub use crate::{
        ArkTPSocket, ArkTPListener, ArkTPConnection, ArkTPStream, SendHalf, RecvHalf,
        ArkTPConfig, ArkTPConfigHandle, AuthenticationConfig, CongestionAlgorithm,
        ConnectionState, ArkTPStats, ArkTPError, Result, SeqNum, EncryptionKey,
        CryptoContext, KeyExchangeManager, KeyExchangeMethod, KeyExchangeMessage,
        MultiPathManager, NetworkPath, PathQuality, PathSchedulerPlugin, PathScheduler,
        NatTraversal, NatType, StunClient, ConnectionAggregator, ConnectionHealth,
        PostQuantumCrypto, ReedSolomonFec, SmartAdaptiveFec, SmartCache, CacheStats,
        FecPlugin, StreamFrame, ExtensionFrame, FlowControl, ParallelPipeline,
        FecPacket, SackBlock, SessionTicket, ArkTPReliableClient, ArkTPReliableServer,
        ARKTP_RELIABLE_VERSION,
    };
}
