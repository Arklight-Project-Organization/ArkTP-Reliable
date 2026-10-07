use std::{
    convert::TryInto,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use rand::RngCore;
use serde::{Serialize, Deserialize};

// 加密相关
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce, Key,
};
use argon2::Argon2;
use zeroize::{Zeroize, ZeroizeOnDrop};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519SecretKey};

// 后量子密码学

// 性能优化
use parking_lot::{RwLock as PLRwLock, Mutex as PLMutex};
use rayon::prelude::*;

use crate::*;

// ==================== 加密模块 ====================
#[derive(Clone, Zeroize, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct EncryptionKey {
    key: [u8; KEY_SIZE],
}

impl EncryptionKey {
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut key);
        Self { key }
    }
    
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(ArkTPError::EncryptionError("Invalid key size".to_string()));
        }
        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }
    
    pub fn from_password(password: &str, salt: &[u8]) -> Result<Self> {
        let mut output = [0u8; KEY_SIZE];
        let argon2 = Argon2::default();
        argon2.hash_password_into(password.as_bytes(), salt, &mut output)
            .map_err(|e| ArkTPError::EncryptionError(e.to_string()))?;
        Ok(Self { key: output })
    }
    
    pub fn derive_session_key(&self, session_id: u64, nonce: &[u8]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(&self.key), &session_id.to_be_bytes());
        let mut session_key = [0u8; KEY_SIZE];
        hkdf.expand(nonce, &mut session_key)
            .map_err(|e| ArkTPError::EncryptionError(e.to_string()))?;
        Ok(Self { key: session_key })
    }
    
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }
}

#[derive(Clone)]
pub struct CryptoContext {
    cipher: Arc<ChaCha20Poly1305>,
    send_nonce: Arc<AtomicU64>,
    recv_nonce: Arc<AtomicU64>,
    /// Sliding replay window: highest accepted nonce and a 128-bit bitmap.
    recv_window: Arc<PLMutex<(u64, u128)>>,
}

impl CryptoContext {
    pub fn new(key: &EncryptionKey) -> Self {
        let cipher_key = Key::from(key.key);
        let cipher = Arc::new(ChaCha20Poly1305::new(&cipher_key));
        Self {
            cipher,
            send_nonce: Arc::new(AtomicU64::new(0)),
            recv_nonce: Arc::new(AtomicU64::new(0)),
            recv_window: Arc::new(PLMutex::new((0, 0))),
        }
    }
    
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        let nonce_value = self.send_nonce.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
            value.checked_add(1)
        }).map_err(|_| ArkTPError::EncryptionError("Nonce counter exhausted".to_string()))?;
        let nonce = self.create_nonce(nonce_value);
        
        let payload = Payload {
            msg: plaintext,
            aad,
        };
        
        let ciphertext = self.cipher.encrypt(&nonce, payload)
            .map_err(|e| ArkTPError::EncryptionError(e.to_string()))?;
        
        let mut result = Vec::with_capacity(8 + ciphertext.len());
        result.extend_from_slice(&nonce_value.to_be_bytes());
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    #[inline]
    pub fn decrypt(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
        if data.len() < 8 + TAG_SIZE {
            return Err(ArkTPError::DecryptionError("Data too short".to_string()));
        }
        let nonce_value = u64::from_be_bytes(data[0..8].try_into().map_err(|_| ArkTPError::DecryptionError("invalid nonce".into()))?);
        let mut window = self.recv_window.lock();
        let (highest, bitmap) = &mut *window;
        let distance = if *bitmap == 0 { None } else if nonce_value > *highest { None } else { Some(*highest - nonce_value) };
        if distance.map(|d| d >= 128 || ((*bitmap >> d) & 1) != 0).unwrap_or(false) {
            return Err(ArkTPError::ReplayDetected);
        }
        let nonce = self.create_nonce(nonce_value);
        let payload = Payload { msg: &data[8..], aad };
        let plaintext = self.cipher.decrypt(&nonce, payload)
            .map_err(|e| ArkTPError::DecryptionError(e.to_string()))?;
        if *bitmap == 0 {
            *highest = nonce_value; *bitmap = 1;
        } else if nonce_value > *highest {
            let shift = nonce_value - *highest;
            *bitmap = if shift >= 128 { 1 } else { (*bitmap << shift) | 1 };
            *highest = nonce_value;
        } else {
            *bitmap |= 1u128 << (*highest - nonce_value);
        }
        self.recv_nonce.fetch_max(nonce_value, Ordering::Release);
        Ok(plaintext)
    }

    pub fn needs_key_update(&self) -> bool { self.send_nonce.load(Ordering::Acquire) >= (1u64 << 32) }

    pub fn rotate(&mut self, key: &EncryptionKey) {
        // A key phase starts a fresh nonce/replay namespace. The caller keeps
        // the previous CryptoContext when it needs to accept in-flight packets.
        *self = CryptoContext::new(key);
    }

    #[inline]
    fn create_nonce(&self, counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes[0..4].copy_from_slice(&0u32.to_be_bytes());
        nonce_bytes[4..12].copy_from_slice(&counter.to_be_bytes());
        Nonce::from(nonce_bytes)
    }
}

// ==================== 密钥交换方法 ====================
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyExchangeMethod {
    X25519,
    X25519WithArgon2,
    PreSharedKey,
    AutoGenerated,
    PostQuantumKyber,
    HybridX25519Kyber,
}

impl KeyExchangeMethod {
    fn to_byte(self) -> u8 {
        match self {
            KeyExchangeMethod::X25519 => 0,
            KeyExchangeMethod::X25519WithArgon2 => 1,
            KeyExchangeMethod::PreSharedKey => 2,
            KeyExchangeMethod::AutoGenerated => 3,
            KeyExchangeMethod::PostQuantumKyber => 4,
            KeyExchangeMethod::HybridX25519Kyber => 5,
        }
    }
    
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(KeyExchangeMethod::X25519),
            1 => Some(KeyExchangeMethod::X25519WithArgon2),
            2 => Some(KeyExchangeMethod::PreSharedKey),
            3 => Some(KeyExchangeMethod::AutoGenerated),
            4 => Some(KeyExchangeMethod::PostQuantumKyber),
            5 => Some(KeyExchangeMethod::HybridX25519Kyber),
            _ => None,
        }
    }
}

// ==================== 密钥交换消息 ====================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeMessage {
    method: KeyExchangeMethod,
    public_key: Vec<u8>,
    kyber_public_key: Vec<u8>,
    kyber_ciphertext: Vec<u8>,
    dilithium_signature: Vec<u8>,
    dilithium_public_key: Vec<u8>,
    salt: Vec<u8>,
    session_id: u64,
    timestamp: u64,
    verification_data: Vec<u8>,
    supported_methods: Vec<KeyExchangeMethod>,
    pub retry_token: Vec<u8>,
}

impl KeyExchangeMessage {
    fn new(
        method: KeyExchangeMethod,
        public_key: Vec<u8>,
        salt: Vec<u8>,
        session_id: u64,
        verification_data: Vec<u8>,
    ) -> Self {
        Self {
            method,
            public_key,
            kyber_public_key: Vec::new(),
            kyber_ciphertext: Vec::new(),
            dilithium_signature: Vec::new(),
            dilithium_public_key: Vec::new(),
            salt,
            session_id,
            timestamp: now_ms(),
            verification_data,
            supported_methods: vec![
                KeyExchangeMethod::HybridX25519Kyber,
                KeyExchangeMethod::PostQuantumKyber,
                KeyExchangeMethod::X25519,
                KeyExchangeMethod::X25519WithArgon2,
                KeyExchangeMethod::AutoGenerated,
                KeyExchangeMethod::PreSharedKey,
            ],
            retry_token: Vec::new(),
        }
    }
    
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(512);
        
        buf.push(self.method.to_byte());
        buf.extend_from_slice(&self.session_id.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        
        buf.extend_from_slice(&(self.public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.public_key);
        
        buf.extend_from_slice(&(self.kyber_public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.kyber_public_key);
        
        buf.extend_from_slice(&(self.kyber_ciphertext.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.kyber_ciphertext);
        
        buf.extend_from_slice(&(self.dilithium_signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.dilithium_signature);
        
        buf.extend_from_slice(&(self.dilithium_public_key.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.dilithium_public_key);
        
        buf.extend_from_slice(&(self.salt.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.salt);
        
        buf.extend_from_slice(&(self.verification_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.verification_data);
        
        buf.extend_from_slice(&(self.supported_methods.len() as u16).to_be_bytes());
        for method in &self.supported_methods {
            buf.push(method.to_byte());
        }
        buf.extend_from_slice(&(self.retry_token.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.retry_token);
        
        buf
    }
    
    pub fn decode(data: &[u8]) -> Option<Self> {
        // method(1) + session_id(8) + timestamp(8)
        if data.len() < 17 {
            return None;
        }

        let method = KeyExchangeMethod::from_byte(data[0])?;
        let session_id = u64::from_be_bytes(data[1..9].try_into().ok()?);
        let timestamp = u64::from_be_bytes(data[9..17].try_into().ok()?);

        let mut offset = 17;

        fn take_field<'a>(data: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
            let len_end = offset.checked_add(2)?;
            let len_bytes = data.get(*offset..len_end)?;
            let len = u16::from_be_bytes(len_bytes.try_into().ok()?) as usize;
            *offset = len_end;
            let end = offset.checked_add(len)?;
            let field = data.get(*offset..end)?;
            *offset = end;
            Some(field)
        }

        let public_key = take_field(data, &mut offset)?.to_vec();
        let kyber_public_key = take_field(data, &mut offset)?.to_vec();
        let kyber_ciphertext = take_field(data, &mut offset)?.to_vec();
        let dilithium_signature = take_field(data, &mut offset)?.to_vec();
        let dilithium_public_key = take_field(data, &mut offset)?.to_vec();
        let salt = take_field(data, &mut offset)?.to_vec();
        let verification_data = take_field(data, &mut offset)?.to_vec();

        let methods_bytes = take_field(data, &mut offset)?;
        let mut supported_methods = Vec::with_capacity(methods_bytes.len());
        for byte in methods_bytes {
            if let Some(method) = KeyExchangeMethod::from_byte(*byte) {
                supported_methods.push(method);
            }
        }
        let retry_token = take_field(data, &mut offset)?.to_vec();
        if offset != data.len() { return None; }

        Some(Self {
            method,
            public_key,
            kyber_public_key,
            kyber_ciphertext,
            dilithium_signature,
            dilithium_public_key,
            salt,
            session_id,
            timestamp,
            verification_data,
            supported_methods,
            retry_token,
        })
    }
}

// ==================== 后量子密码学 ====================
pub struct PostQuantumCrypto {
    kyber_keypair: pqc_kyber::Keypair,
    dilithium_keypair: pqc_dilithium::Keypair,
}

impl PostQuantumCrypto {
    pub fn new() -> Result<Self> {
        let mut rng = rand::thread_rng();
        let kyber_keypair = pqc_kyber::keypair(&mut rng);
        let dilithium_keypair = pqc_dilithium::Keypair::generate();

        Ok(Self {
            kyber_keypair,
            dilithium_keypair,
        })
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let mut rng = rand::thread_rng();
        let (ciphertext, shared_secret) = pqc_kyber::encapsulate(&self.kyber_keypair.public, &mut rng)
            .map_err(|e| ArkTPError::PostQuantumKeyExchangeFailed(format!("Kyber encapsulation failed: {}", e)))?;

        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    pub fn encapsulate_to(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        if public_key.len() != KYBER_PUBLIC_KEY_SIZE {
            return Err(ArkTPError::PostQuantumKeyExchangeFailed("Invalid Kyber public key size".into()));
        }
        let mut pk = [0u8; KYBER_PUBLIC_KEY_SIZE];
        pk.copy_from_slice(public_key);
        let mut rng = rand::thread_rng();
        let (ciphertext, shared_secret) = pqc_kyber::encapsulate(&pk, &mut rng)
            .map_err(|e| ArkTPError::PostQuantumKeyExchangeFailed(format!("Kyber encapsulation failed: {}", e)))?;
        Ok((ciphertext.to_vec(), shared_secret.to_vec()))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let shared_secret = pqc_kyber::decapsulate(ciphertext, &self.kyber_keypair.secret)
            .map_err(|e| ArkTPError::PostQuantumKeyExchangeFailed(format!("Kyber decapsulation failed: {}", e)))?;

        Ok(shared_secret.to_vec())
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let signature = self.dilithium_keypair.sign(message);
        Ok(signature.to_vec())
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<bool> {
        match pqc_dilithium::verify(signature, message, &self.dilithium_keypair.public) {
            Ok(()) => Ok(true),
            Err(pqc_dilithium::SignError::Verify) => Ok(false),
            Err(pqc_dilithium::SignError::Input) => Err(ArkTPError::PostQuantumKeyExchangeFailed(
                "Dilithium verification failed: invalid input length".to_string(),
            )),
        }
    }

    pub fn verify_with_public(message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        match pqc_dilithium::verify(signature, message, public_key) {
            Ok(()) => Ok(true),
            Err(pqc_dilithium::SignError::Verify) => Ok(false),
            Err(pqc_dilithium::SignError::Input) => Err(ArkTPError::PostQuantumKeyExchangeFailed("Dilithium verification input invalid".into())),
        }
    }

    pub fn get_kyber_public_key(&self) -> &[u8] {
        &self.kyber_keypair.public
    }

    pub fn get_dilithium_public_key(&self) -> &[u8] {
        &self.dilithium_keypair.public
    }
}

// ==================== 密钥交换管理器 ====================
pub struct KeyExchangeManager {
    private_key: X25519SecretKey,
    public_key: X25519PublicKey,
    pq_crypto: PostQuantumCrypto,
    session_key: Arc<PLRwLock<Option<EncryptionKey>>>,
    key_exchange_state: Arc<PLRwLock<KeyExchangeState>>,
    negotiated_method: Arc<PLRwLock<Option<KeyExchangeMethod>>>,
    preferred_method: Arc<PLRwLock<KeyExchangeMethod>>,
    pub key_verification: Arc<PLRwLock<Vec<u8>>>,
    last_timestamp: Arc<AtomicU64>,
    auth_key: Option<EncryptionKey>,
    trusted_fingerprint: Arc<PLRwLock<Option<Vec<u8>>>>,
    tofu: Arc<std::sync::atomic::AtomicBool>,
    last_response: Arc<PLRwLock<Option<KeyExchangeMessage>>>,
    peer_fingerprint: Arc<PLRwLock<Option<Vec<u8>>>>,
    retry_token: Arc<PLRwLock<Vec<u8>>>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum KeyExchangeState {
    Idle,
    Initiating,
    Responding,
    Verifying,
    Completed,
    Failed(String),
}

impl KeyExchangeManager {
    pub fn new() -> Result<Self> {
        let private_key = X25519SecretKey::random_from_rng(rand::thread_rng());
        let public_key = X25519PublicKey::from(&private_key);
        let pq_crypto = PostQuantumCrypto::new()?;
        
        Ok(Self {
            private_key,
            public_key,
            pq_crypto,
            session_key: Arc::new(PLRwLock::new(None)),
            key_exchange_state: Arc::new(PLRwLock::new(KeyExchangeState::Idle)),
            negotiated_method: Arc::new(PLRwLock::new(None)),
            preferred_method: Arc::new(PLRwLock::new(KeyExchangeMethod::HybridX25519Kyber)),
            key_verification: Arc::new(PLRwLock::new(Vec::new())),
            last_timestamp: Arc::new(AtomicU64::new(0)),
            auth_key: None,
            trusted_fingerprint: Arc::new(PLRwLock::new(None)),
            tofu: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            last_response: Arc::new(PLRwLock::new(None)),
            peer_fingerprint: Arc::new(PLRwLock::new(None)),
            retry_token: Arc::new(PLRwLock::new(Vec::new())),
        })
    }
    
    pub fn from_pre_shared_key(key: &EncryptionKey) -> Result<Self> {
        let mut manager = Self::new()?;
        manager.auth_key = Some(key.clone());
        *manager.session_key.write() = Some(key.clone());
        *manager.key_exchange_state.write() = KeyExchangeState::Completed;
        *manager.negotiated_method.write() = Some(KeyExchangeMethod::PreSharedKey);
        Ok(manager)
    }
    
    pub fn initiate_key_exchange(&self, session_id: u64) -> KeyExchangeMessage {
        *self.key_exchange_state.write() = KeyExchangeState::Initiating;
        
        let mut verification = vec![0u8; KEY_VERIFICATION_SIZE];
        rand::thread_rng().fill_bytes(&mut verification);
        let salt = self.generate_salt();
        
        let preferred = *self.preferred_method.read();
        let mut message = KeyExchangeMessage::new(
            preferred,
            self.public_key.as_bytes().to_vec(),
            salt,
            session_id,
            verification,
        );
        
        message.kyber_public_key = self.pq_crypto.get_kyber_public_key().to_vec();
        if let Some(key) = &self.auth_key {
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC-SHA256 accepts a 32-byte key");
            mac.update(&session_id.to_be_bytes());
            mac.update(&message.timestamp.to_be_bytes());
            mac.update(&[message.method.to_byte()]);
            mac.update(&message.public_key);
            mac.update(&message.kyber_public_key);
            for m in &message.supported_methods { mac.update(&[m.to_byte()]); }
            let tag = mac.finalize().into_bytes();
            message.verification_data = tag.to_vec();
        }
        *self.key_verification.write() = message.verification_data.clone();
        
        message
    }
    
    pub fn set_retry_token(&self, token: Vec<u8>) { *self.retry_token.write() = token; }
    pub fn retry_token(&self) -> Vec<u8> { self.retry_token.read().clone() }

    pub fn respond_to_key_exchange(
        &self,
        message: &KeyExchangeMessage,
        session_id: u64,
    ) -> Result<KeyExchangeMessage> {
        let now = now_ms();
        if message.timestamp.abs_diff(now) > 30_000 { return Err(ArkTPError::ReplayDetected); }
        let previous = self.last_timestamp.load(Ordering::Acquire);
        if message.timestamp < previous { return Err(ArkTPError::ReplayDetected); }
        if message.timestamp == previous {
            if let Some(response) = self.last_response.read().clone() { return Ok(response); }
            return Err(ArkTPError::ReplayDetected);
        }
        self.last_timestamp.store(message.timestamp, Ordering::Release);
        if let Some(key) = &self.auth_key {
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| ArkTPError::AuthenticationFailed)?;
            mac.update(&session_id.to_be_bytes());
            mac.update(&message.timestamp.to_be_bytes());
            mac.update(&[message.method.to_byte()]);
            mac.update(&message.public_key);
            mac.update(&message.kyber_public_key);
            for m in &message.supported_methods { mac.update(&[m.to_byte()]); }
            mac.verify_slice(&message.verification_data).map_err(|_| ArkTPError::AuthenticationFailed)?;
        }
        *self.key_exchange_state.write() = KeyExchangeState::Responding;
        
        let method = self.select_best_method(&message.supported_methods, &message.method)?;
        *self.negotiated_method.write() = Some(method);
        
        let mut response_ciphertext = Vec::new();
        let shared_secret = match method {
            KeyExchangeMethod::HybridX25519Kyber => {
                let x25519_secret = self.compute_shared_secret(&message.public_key)?;
                let (ciphertext, kyber_secret) = self.pq_crypto.encapsulate_to(&message.kyber_public_key)?;
                
                let mut combined = Vec::with_capacity(x25519_secret.len() + kyber_secret.len());
                combined.extend_from_slice(&x25519_secret);
                combined.extend_from_slice(&kyber_secret);
                
                let mut response = KeyExchangeMessage::new(
                    method,
                    self.public_key.as_bytes().to_vec(),
                    self.generate_salt(),
                    session_id,
                    vec![0u8; KEY_VERIFICATION_SIZE],
                );
                response.kyber_ciphertext = ciphertext;
                response.dilithium_signature = self.pq_crypto.sign(&combined)?;
                
                combined
            }
            KeyExchangeMethod::PostQuantumKyber => {
                let (ciphertext, kyber_secret) = self.pq_crypto.encapsulate_to(&message.kyber_public_key)?;
                
                let mut response = KeyExchangeMessage::new(
                    method,
                    Vec::new(),
                    self.generate_salt(),
                    session_id,
                    vec![0u8; KEY_VERIFICATION_SIZE],
                );
                response.kyber_ciphertext = ciphertext;
                response.dilithium_signature = self.pq_crypto.sign(&kyber_secret)?;
                
                kyber_secret
            }
            KeyExchangeMethod::PreSharedKey => {
                self.auth_key.as_ref().ok_or(ArkTPError::AuthenticationFailed)?.as_bytes().to_vec()
            }
            _ => {
                self.compute_shared_secret(&message.public_key)?
            }
        };
        
        let session_key = self.derive_session_key(&shared_secret, session_id, &message.salt)?;
        *self.session_key.write() = Some(session_key);
        
        let response_verification = vec![0u8; KEY_VERIFICATION_SIZE];
        let mut response = KeyExchangeMessage::new(
            method,
            self.public_key.as_bytes().to_vec(),
            message.salt.clone(),
            session_id,
            response_verification,
        );
        
        response.dilithium_public_key = self.pq_crypto.get_dilithium_public_key().to_vec();
        if let Some(key) = &self.auth_key {
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC-SHA256 accepts 32-byte keys");
            mac.update(&session_id.to_be_bytes());
            mac.update(&response.timestamp.to_be_bytes());
            mac.update(&[response.method.to_byte()]);
            mac.update(&response.public_key);
            mac.update(&response.kyber_ciphertext);
            response.verification_data = mac.finalize().into_bytes().to_vec();
        }
        if matches!(method, KeyExchangeMethod::HybridX25519Kyber | KeyExchangeMethod::PostQuantumKyber) {
            response.dilithium_signature = self.pq_crypto.sign(&shared_secret)?;
        }
        if matches!(method, KeyExchangeMethod::HybridX25519Kyber | KeyExchangeMethod::PostQuantumKyber) {
            response.kyber_ciphertext = response_ciphertext;
        }
        
        Ok(response)
    }
    
    pub fn complete_key_exchange(
        &self,
        message: &KeyExchangeMessage,
        session_id: u64,
        _expected_verification: &[u8],
    ) -> Result<()> {
        let now = now_ms();
        if message.timestamp.abs_diff(now) > 30_000 { return Err(ArkTPError::ReplayDetected); }
        let previous = self.last_timestamp.load(Ordering::Acquire);
        if message.timestamp <= previous { return Err(ArkTPError::ReplayDetected); }
        let preferred = *self.preferred_method.read();
        if message.method != preferred && preferred != KeyExchangeMethod::PreSharedKey {
            return Err(ArkTPError::UnsupportedKeyExchange);
        }
        self.last_timestamp.store(message.timestamp, Ordering::Release);
        if let Some(key) = &self.auth_key {
            let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| ArkTPError::AuthenticationFailed)?;
            mac.update(&session_id.to_be_bytes());
            mac.update(&message.timestamp.to_be_bytes());
            mac.update(&[message.method.to_byte()]);
            mac.update(&message.public_key);
            mac.update(&message.kyber_ciphertext);
            mac.verify_slice(&message.verification_data).map_err(|_| ArkTPError::AuthenticationFailed)?;
        }
        if !message.dilithium_public_key.is_empty() {
            let fp = Self::peer_fingerprint(&message.dilithium_public_key);
            *self.peer_fingerprint.write() = Some(fp.clone());
            if let Some(expected) = self.trusted_fingerprint.read().as_ref() {
                if *expected != fp { return Err(ArkTPError::AuthenticationFailed); }
            } else if self.tofu.load(Ordering::Acquire) {
                *self.trusted_fingerprint.write() = Some(fp);
            }
        }
        let shared_secret = match message.method {
            KeyExchangeMethod::HybridX25519Kyber => {
                let x25519_secret = self.compute_shared_secret(&message.public_key)?;
                let kyber_secret = self.pq_crypto.decapsulate(&message.kyber_ciphertext)?;
                
                let mut combined = Vec::with_capacity(x25519_secret.len() + kyber_secret.len());
                combined.extend_from_slice(&x25519_secret);
                combined.extend_from_slice(&kyber_secret);
                
                if !message.dilithium_signature.is_empty() {
                    let verified = if !message.dilithium_public_key.is_empty() {
                        PostQuantumCrypto::verify_with_public(&combined, &message.dilithium_signature, &message.dilithium_public_key)?
                    } else { false };
                    if !verified { return Err(ArkTPError::KeyVerificationFailed); }
                }
                
                combined
            }
            KeyExchangeMethod::PostQuantumKyber => {
                let kyber_secret = self.pq_crypto.decapsulate(&message.kyber_ciphertext)?;
                
                if !message.dilithium_signature.is_empty() {
                    let verified = if !message.dilithium_public_key.is_empty() {
                        PostQuantumCrypto::verify_with_public(&kyber_secret, &message.dilithium_signature, &message.dilithium_public_key)?
                    } else { false };
                    if !verified { return Err(ArkTPError::KeyVerificationFailed); }
                }
                
                kyber_secret
            }
            KeyExchangeMethod::PreSharedKey => {
                self.auth_key.as_ref().ok_or(ArkTPError::AuthenticationFailed)?.as_bytes().to_vec()
            }
            _ => {
                self.compute_shared_secret(&message.public_key)?
            }
        };
        
        let session_key = self.derive_session_key(&shared_secret, session_id, &message.salt)?;
        *self.session_key.write() = Some(session_key);
        *self.key_exchange_state.write() = KeyExchangeState::Completed;
        
        Ok(())
    }
    
    fn compute_shared_secret(&self, peer_public_key: &[u8]) -> Result<Vec<u8>> {
        if peer_public_key.len() != X25519_KEY_SIZE {
            return Err(ArkTPError::KeyExchangeFailed("Invalid public key size".to_string()));
        }
        
        let mut peer_key_bytes = [0u8; X25519_KEY_SIZE];
        peer_key_bytes.copy_from_slice(peer_public_key);
        
        let peer_key = X25519PublicKey::from(peer_key_bytes);
        let shared_secret = self.private_key.diffie_hellman(&peer_key);
        
        Ok(shared_secret.as_bytes().to_vec())
    }
    
    fn derive_session_key(
        &self,
        shared_secret: &[u8],
        session_id: u64,
        salt: &[u8],
    ) -> Result<EncryptionKey> {
        let hkdf = Hkdf::<Sha256>::new(Some(salt), shared_secret);
        let mut session_key = [0u8; KEY_SIZE];
        let info = format!("ArkTP-session-{}", session_id);
        hkdf.expand(info.as_bytes(), &mut session_key)
            .map_err(|e| ArkTPError::KeyExchangeFailed(e.to_string()))?;
        
        EncryptionKey::from_bytes(&session_key)
    }
    
    fn select_best_method(
        &self,
        supported: &[KeyExchangeMethod],
        preferred: &KeyExchangeMethod,
    ) -> Result<KeyExchangeMethod> {
        let priority = [
            KeyExchangeMethod::HybridX25519Kyber,
            KeyExchangeMethod::PostQuantumKyber,
            KeyExchangeMethod::X25519,
            KeyExchangeMethod::X25519WithArgon2,
            KeyExchangeMethod::AutoGenerated,
            KeyExchangeMethod::PreSharedKey,
        ];
        
        if !supported.contains(preferred) {
            return Err(ArkTPError::UnsupportedKeyExchange);
        }
        for method in &priority {
            if supported.contains(method) && method == preferred {
                return Ok(*method);
            }
        }
        
        for method in &priority {
            if supported.contains(method) {
                return Ok(*method);
            }
        }
        
        Err(ArkTPError::UnsupportedKeyExchange)
    }
    
    fn generate_salt(&self) -> Vec<u8> {
        let mut salt = vec![0u8; SALT_SIZE];
        rand::thread_rng().fill_bytes(&mut salt);
        salt
    }
    
    pub fn get_peer_fingerprint(&self) -> Option<Vec<u8>> { self.peer_fingerprint.read().clone() }
    pub fn set_preferred_method(&self, method: KeyExchangeMethod) { *self.preferred_method.write() = method; }
    pub fn set_trusted_fingerprint(&self, fingerprint: Vec<u8>) { *self.trusted_fingerprint.write() = Some(fingerprint); }
    pub fn enable_tofu(&self) { self.tofu.store(true, Ordering::Release); }
    pub fn peer_fingerprint(public_key: &[u8]) -> Vec<u8> { Sha256::digest(public_key).to_vec() }

    pub fn get_session_key(&self) -> Option<EncryptionKey> {
        self.session_key.read().clone()
    }
    
    pub fn get_negotiated_method(&self) -> Option<KeyExchangeMethod> {
        *self.negotiated_method.read()
    }
    
    pub fn get_state(&self) -> KeyExchangeState {
        self.key_exchange_state.read().clone()
    }
    
    pub fn set_session_key(&self, key: EncryptionKey) {
        *self.session_key.write() = Some(key);
        *self.key_exchange_state.write() = KeyExchangeState::Completed;
    }
}

