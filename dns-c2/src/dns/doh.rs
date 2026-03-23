//! DNS-over-HTTPS backend — implements `DnsBackend` for read operations
//! by sending wire-format DNS queries over HTTPS to public resolvers.
//!
//! Write operations (create/update/delete) are not supported by DoH
//! and return `DnsError::ApiError`. The `TransportChain` routes writes
//! to API-capable channels automatically.

use super::{DnsBackend, DnsError, TxtRecord};
use crate::traffic::doh as doh_util;
use async_trait::async_trait;

/// DoH provider presets
#[derive(Debug, Clone)]
pub struct DoHBackend {
    /// DoH endpoint URL (e.g. "https://cloudflare-dns.com/dns-query")
    endpoint: String,
    /// HTTP client (reused across queries)
    client: reqwest::Client,
    /// Pad queries to this size (0 = no padding)
    pad_to: usize,
}

impl DoHBackend {
    pub fn new(endpoint: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_default();
        Self {
            endpoint: endpoint.to_string(),
            client,
            pad_to: 128,
        }
    }

    /// Cloudflare DoH (1.1.1.1)
    pub fn cloudflare() -> Self {
        Self::new("https://cloudflare-dns.com/dns-query")
    }

    /// Google DoH (8.8.8.8)
    pub fn google() -> Self {
        Self::new("https://dns.google/dns-query")
    }

    /// Quad9 DoH (9.9.9.9)
    pub fn quad9() -> Self {
        Self::new("https://dns.quad9.net:5053/dns-query")
    }

    /// Query TXT records for a name via DoH POST (wire format, RFC 8484)
    async fn query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        let pad = if self.pad_to > 0 { Some(self.pad_to) } else { None };
        let query = doh_util::build_dns_query(name, pad);

        let response = self.client
            .post(&self.endpoint)
            .header("Content-Type", "application/dns-message")
            .header("Accept", "application/dns-message")
            .body(query)
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(format!("DoH POST failed: {e}")))?;

        if !response.status().is_success() {
            return Err(DnsError::ApiError(format!(
                "DoH server returned {}", response.status()
            )));
        }

        let body = response.bytes().await
            .map_err(|e| DnsError::NetworkError(format!("DoH read body: {e}")))?;

        doh_util::parse_dns_response(&body)
            .map_err(|e| DnsError::ApiError(format!("DoH parse: {e}")))
    }
}

#[async_trait]
impl DnsBackend for DoHBackend {
    async fn create_record(&self, _name: &str, _content: &str, _ttl: u32) -> Result<String, DnsError> {
        Err(DnsError::ApiError("DoH is read-only — writes require an API-capable channel".into()))
    }

    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let texts = self.query_txt(name).await?;
        Ok(texts.into_iter().map(|content| TxtRecord {
            name: name.to_string(),
            content,
            id: None,
        }).collect())
    }

    async fn update_record(&self, _id: &str, _content: &str) -> Result<(), DnsError> {
        Err(DnsError::ApiError("DoH is read-only — writes require an API-capable channel".into()))
    }

    async fn delete_record(&self, _id: &str) -> Result<(), DnsError> {
        Err(DnsError::ApiError("DoH is read-only — writes require an API-capable channel".into()))
    }

    async fn list_records(&self, _prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        // DoH can't enumerate records — only query specific names
        Err(DnsError::ApiError("DoH cannot list records — use an API-capable channel".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doh_backend_creation() {
        let backend = DoHBackend::cloudflare();
        assert_eq!(backend.endpoint, "https://cloudflare-dns.com/dns-query");
    }

    #[test]
    fn test_google_backend() {
        let backend = DoHBackend::google();
        assert_eq!(backend.endpoint, "https://dns.google/dns-query");
    }

    #[test]
    fn test_quad9_backend() {
        let backend = DoHBackend::quad9();
        assert!(backend.endpoint.contains("quad9"));
    }

    #[tokio::test]
    async fn test_create_record_fails() {
        let backend = DoHBackend::cloudflare();
        let result = backend.create_record("test", "data", 60).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_list_records_fails() {
        let backend = DoHBackend::cloudflare();
        let result = backend.list_records("_c2.").await;
        assert!(result.is_err());
    }
}
