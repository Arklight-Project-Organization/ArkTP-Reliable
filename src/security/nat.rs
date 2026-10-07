use std::{
    convert::TryInto,
    net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    time::{interval, timeout},
};
use log::debug;

// 加密相关
use chacha20poly1305::aead::KeyInit;
use sha2::Digest;

// 后量子密码学

// 性能优化
use parking_lot::{RwLock as PLRwLock, Mutex as PLMutex};

use crate::*;

// ==================== NAT穿透 ====================
pub struct NatTraversal {
    public_addr: Arc<PLRwLock<Option<SocketAddr>>>,
    nat_type: Arc<PLRwLock<NatType>>,
    stun_client: StunClient,
    last_probe: Arc<PLMutex<Instant>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NatType {
    Open,
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    Unknown,
}

pub struct StunClient {
    socket: Arc<UdpSocket>,
}

impl StunClient {
    async fn new() -> Result<Self> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        Ok(Self { socket })
    }
    
    async fn query(&self, server: &str) -> Result<SocketAddr> {
        let server_addr: SocketAddr = server.parse()
            .map_err(|e| ArkTPError::NatTraversalFailed(format!("Invalid STUN server: {}", e)))?;
        
        let mut request = vec![0u8; 20];
        request[0] = 0x00;
        request[1] = 0x01;
        request[2..4].copy_from_slice(&0u16.to_be_bytes());
        request[4..8].copy_from_slice(&0x2112A442u32.to_be_bytes());
        request[8..20].copy_from_slice(&rand::random::<[u8; 12]>());
        
        self.socket.send_to(&request, server_addr).await?;
        
        let mut buf = vec![0u8; 2048];
        let (n, _) = timeout(
            Duration::from_secs(3),
            self.socket.recv_from(&mut buf)
        ).await.map_err(|_| ArkTPError::NatTraversalFailed("STUN timeout".to_string()))??;
        
        if n < 20 || buf[0] != 0x01 || buf[1] != 0x01 {
            return Err(ArkTPError::NatTraversalFailed("Invalid STUN response".to_string()));
        }
        
        let mut offset = 20;
        while offset + 4 <= n {
            let attr_type = u16::from_be_bytes(buf[offset..offset+2].try_into().unwrap());
            let attr_len = u16::from_be_bytes(buf[offset+2..offset+4].try_into().unwrap()) as usize;
            
            if offset + 4 + attr_len > n { break; }
            if attr_type == 0x0001 {
                if attr_len >= 8 && offset + 12 <= n {
                    let family = buf[offset+5];
                    let port = u16::from_be_bytes(buf[offset+6..offset+8].try_into().unwrap());
                    
                    if family == 0x01 {
                        let ip = Ipv4Addr::new(buf[offset+8], buf[offset+9], buf[offset+10], buf[offset+11]);
                        return Ok(SocketAddr::new(IpAddr::V4(ip), port));
                    } else if family == 0x02 {
                        let mut ip_bytes = [0u8; 16];
                        ip_bytes.copy_from_slice(&buf[offset+8..offset+24]);
                        let ip = Ipv6Addr::from(ip_bytes);
                        return Ok(SocketAddr::new(IpAddr::V6(ip), port));
                    }
                }
            } else if attr_type == 0x0020 {
                if attr_len >= 8 && offset + 12 <= n {
                    let family = buf[offset+5];
                    let port_xor = u16::from_be_bytes(buf[offset+6..offset+8].try_into().unwrap());
                    let port = port_xor ^ 0x2112;
                    
                    if family == 0x01 {
                        let ip_xor = u32::from_be_bytes(buf[offset+8..offset+12].try_into().unwrap());
                        let ip = Ipv4Addr::from(ip_xor ^ 0x2112A442);
                        return Ok(SocketAddr::new(IpAddr::V4(ip), port));
                    } else if family == 0x02 && attr_len >= 20 && offset + 24 <= n {
                        let mut raw = [0u8; 16];
                        raw.copy_from_slice(&buf[offset+8..offset+24]);
                        let cookie = 0x2112A442u32.to_be_bytes();
                        for i in 0..4 { raw[i] ^= cookie[i]; }
                        let tx_start = &request[8..20];
                        for i in 0..12 { raw[4+i] ^= tx_start[i]; }
                        return Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(raw)), port));
                    }
                }
            }
            
            offset += 4 + attr_len;
        }
        
        Err(ArkTPError::NatTraversalFailed("No mapped address found".to_string()))
    }
}

impl NatTraversal {
    pub async fn new() -> Result<Self> {
        let stun_client = StunClient::new().await?;
        Ok(Self {
            public_addr: Arc::new(PLRwLock::new(None)),
            nat_type: Arc::new(PLRwLock::new(NatType::Unknown)),
            stun_client,
            last_probe: Arc::new(PLMutex::new(Instant::now())),
        })
    }
    
    pub async fn discover_public_addr(&self) -> Result<SocketAddr> {
        for server in STUN_SERVERS {
            match self.stun_client.query(server).await {
                Ok(addr) => {
                    *self.public_addr.write() = Some(addr);
                    *self.last_probe.lock() = Instant::now();
                    debug!("Discovered public address: {} via {}", addr, server);
                    return Ok(addr);
                }
                Err(e) => {
                    debug!("Failed to query STUN server {}: {}", server, e);
                }
            }
        }
        
        Err(ArkTPError::NatTraversalFailed("All STUN servers failed".to_string()))
    }
    
    pub async fn detect_nat_type(&self) -> Result<NatType> {
        if let Some(addr) = *self.public_addr.read() {
            let local_addr = self.stun_client.socket.local_addr()?;
            
            if local_addr == addr {
                *self.nat_type.write() = NatType::Open;
            } else {
                *self.nat_type.write() = NatType::FullCone;
            }
            
            Ok(self.nat_type.read().clone())
        } else {
            Ok(NatType::Unknown)
        }
    }
    
    pub fn get_public_addr(&self) -> Option<SocketAddr> {
        *self.public_addr.read()
    }
    
    pub fn get_nat_type(&self) -> NatType {
        self.nat_type.read().clone()
    }
    
    pub fn start_probe_loop(self: Arc<Self>) {
        let weak = Arc::downgrade(&self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(NAT_PROBE_INTERVAL_MS));
            loop {
                interval.tick().await;
                let Some(nat) = weak.upgrade() else { break; };
                if let Ok(addr) = nat.discover_public_addr().await {
                    debug!("NAT probe successful: {}", addr);
                }
            }
        });
    }
    
    pub fn start_refresh_loop(self: Arc<Self>) {
        let weak = Arc::downgrade(&self);
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_millis(NAT_REFRESH_INTERVAL_MS));
            loop {
                interval.tick().await;
                let Some(nat) = weak.upgrade() else { break; };
                if let Ok(addr) = nat.discover_public_addr().await {
                    debug!("NAT mapping refreshed: {}", addr);
                }
            }
        });
    }
}

