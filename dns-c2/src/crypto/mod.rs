use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
}

pub type EncryptionKey = [u8; 32];

pub fn generate_key() -> EncryptionKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

pub fn key_from_hex(hex_str: &str) -> Result<EncryptionKey, CryptoError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey(format!("Expected 32 bytes, got {}", bytes.len())));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Encrypt with ChaCha20-Poly1305. Returns: nonce (12) || ciphertext.
pub fn encrypt(key: &EncryptionKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt. Input: nonce (12) || ciphertext.
pub fn decrypt(key: &EncryptionKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::DecryptionFailed("Data too short for nonce".to_string()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher.decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Derive a C2 session key from the master key and session ID
pub fn derive_session_key(master: &EncryptionKey, session_id: &str) -> EncryptionKey {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"dns-c2-session-v1:");
    hasher.update(session_id.as_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}
