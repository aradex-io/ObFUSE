use super::EncryptionKey;

/// Derive a per-file key from the master key and file path
/// This ensures each file has a unique encryption context
pub fn derive_file_key(master: &EncryptionKey, path: &str) -> EncryptionKey {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"dnfs-file-key-v1:");
    hasher.update(path.as_bytes());
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Derive a single key for all chunk (data) encryption.
/// This is path-independent so that cross-file dedup works correctly:
/// identical plaintext chunks produce the same content_hash and are
/// encrypted with the same key, allowing any file to decrypt them.
pub fn derive_data_key(master: &EncryptionKey) -> EncryptionKey {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"dnfs-data-key-v1");
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}

/// Derive a key for metadata encryption
pub fn derive_meta_key(master: &EncryptionKey) -> EncryptionKey {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(b"dnfs-meta-key-v1");
    let hash = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash.as_bytes());
    key
}
