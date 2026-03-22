pub mod keys;

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

/// 32-byte encryption key
pub type EncryptionKey = [u8; 32];

/// Generate a new random 32-byte key
pub fn generate_key() -> EncryptionKey {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    key
}

/// Parse a hex-encoded key string
pub fn key_from_hex(hex_str: &str) -> Result<EncryptionKey, CryptoError> {
    let bytes = hex::decode(hex_str.trim()).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    if bytes.len() != 32 {
        return Err(CryptoError::InvalidKey(format!(
            "Expected 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// Encrypt data with ChaCha20-Poly1305
/// Returns: nonce (12 bytes) || ciphertext
pub fn encrypt(key: &EncryptionKey, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt data encrypted with ChaCha20-Poly1305
/// Input: nonce (12 bytes) || ciphertext
pub fn decrypt(key: &EncryptionKey, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.len() < 12 {
        return Err(CryptoError::DecryptionFailed(
            "Data too short for nonce".to_string(),
        ));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// BLAKE3 content hash for deduplication
pub fn content_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_key();
        let plaintext = b"Dn(f)s is chaos and I love it";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_content_hash_deterministic() {
        let data = b"same content";
        assert_eq!(content_hash(data), content_hash(data));
    }

    #[test]
    fn test_content_hash_different() {
        assert_ne!(content_hash(b"aaa"), content_hash(b"bbb"));
    }

    #[test]
    fn test_key_from_hex() {
        let key = generate_key();
        let hex_str = hex::encode(key);
        let recovered = key_from_hex(&hex_str).unwrap();
        assert_eq!(key, recovered);
    }
}
