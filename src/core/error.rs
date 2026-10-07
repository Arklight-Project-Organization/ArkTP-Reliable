use thiserror::Error;

// 加密相关

// 后量子密码学

// 性能优化


// ==================== 错误定义 ====================
#[derive(Error, Debug)]
pub enum ArkTPError {
    #[error("IO错误: {0}")]
    Io(#[from] std::io::Error),
    #[error("连接超时")]
    Timeout,
    #[error("连接已关闭")]
    ConnectionClosed,
    #[error("发送队列已满")]
    SendQueueFull,
    #[error("数据包太大 (最大 {max} 字节)")]
    PacketTooLarge { max: usize },
    #[error("协议错误: {0}")]
    Protocol(String),
    #[error("连接被重置")]
    ConnectionReset,
    #[error("握手失败")]
    HandshakeFailed,
    #[error("序列号无效")]
    InvalidSequence,
    #[error("FEC恢复失败: {0}")]
    FecRecoveryFailed(String),
    #[error("配置无效: {0}")]
    InvalidConfig(String),
    #[error("路径不可用: {0}")]
    PathUnavailable(String),
    #[error("没有可用路径")]
    NoAvailablePath,
    #[error("加密错误: {0}")]
    EncryptionError(String),
    #[error("解密错误: {0}")]
    DecryptionError(String),
    #[error("认证失败")]
    AuthenticationFailed,
    #[error("密钥交换失败: {0}")]
    KeyExchangeFailed(String),
    #[error("密钥协商超时")]
    KeyAgreementTimeout,
    #[error("不支持的密钥交换方法")]
    UnsupportedKeyExchange,
    #[error("密钥验证失败")]
    KeyVerificationFailed,
    #[error("NAT穿透失败: {0}")]
    NatTraversalFailed(String),
    #[error("连接聚合失败: {0}")]
    ConnectionAggregationFailed(String),
    #[error("后量子密钥交换失败: {0}")]
    PostQuantumKeyExchangeFailed(String),
    #[error("内存分配失败")]
    AllocationFailed,
    #[error("系统资源不足")]
    ResourceExhausted,
    #[error("监听器已关闭")]
    ListenerClosed,
    #[error("连接数达到上限")]
    PendingConnectionsFull,
    #[error("版本不匹配")]
    VersionMismatch,
    #[error("重放攻击被拒绝")]
    ReplayDetected,
    #[error("路径验证失败")]
    PathValidationFailed,
    #[error("流已关闭")]
    StreamClosed,
    #[error("流量控制窗口耗尽")]
    FlowControlBlocked,
    #[error("认证令牌无效")]
    InvalidToken,
    #[error("会话恢复失败")]
    SessionResumptionFailed,
    #[error("不支持的扩展")]
    UnsupportedExtension,
    #[error("PMTU 探测失败")]
    PmtuDiscoveryFailed,
}

pub type Result<T> = std::result::Result<T, ArkTPError>;

