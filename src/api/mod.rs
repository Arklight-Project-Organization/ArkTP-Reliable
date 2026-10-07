//! High-level ArkTP Reliable endpoint API.
use std::sync::Arc;
use crate::{ArkTPConfig, ArkTPConnection, ArkTPListener, ArkTPSocket, Result};

/// A reusable server endpoint. The underlying UDP socket and demultiplexer are
/// created exactly once, so accepting connections does not rebuild listener state.
pub struct ArkTPReliableServer {
    socket: ArkTPSocket,
    listener: ArkTPListener,
}

impl ArkTPReliableServer {
    pub async fn bind(addr: &str, config: ArkTPConfig) -> Result<Self> {
        let socket = ArkTPSocket::bind_with_config(addr, config).await?;
        let listener = socket.listen()?;
        Ok(Self { socket, listener })
    }

    pub async fn accept(&self) -> Result<Arc<ArkTPConnection>> {
        self.listener.accept().await
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.socket.local_addr()
    }

    pub fn listener(&self) -> ArkTPListener { self.listener.clone() }
}

/// Client endpoint factory. Each outgoing connection gets an independent UDP
/// socket, while the protocol remains fully async and Tokio-native.
#[derive(Clone)]
pub struct ArkTPReliableClient {
    config: ArkTPConfig,
}

impl ArkTPReliableClient {
    pub fn new(config: ArkTPConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub async fn connect(&self, addr: &str) -> Result<ArkTPSocket> {
        let mut socket = ArkTPSocket::bind_with_config("0.0.0.0:0", self.config.clone()).await?;
        socket.connect(addr).await?;
        Ok(socket)
    }

    pub fn config(&self) -> &ArkTPConfig { &self.config }
}

/// Versioned product identity exposed to applications and telemetry.
pub const ARKTP_RELIABLE_VERSION: &str = env!("CARGO_PKG_VERSION");
