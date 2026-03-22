pub mod cloudflare;
pub mod local;
pub mod mock;
pub mod retry;

use async_trait::async_trait;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DnsError {
    #[error("Record not found: {0}")]
    NotFound(String),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Rate limited")]
    RateLimited,
    #[error("Record too large: {size} bytes (max {max})")]
    RecordTooLarge { size: usize, max: usize },
    #[error("Network error: {0}")]
    NetworkError(String),
}

/// A DNS TXT record
#[derive(Debug, Clone)]
pub struct TxtRecord {
    /// Full record name (e.g., "c0.abc123.fs.example.com")
    pub name: String,
    /// Record content
    pub content: String,
    /// Cloudflare record ID (for updates/deletes)
    pub id: Option<String>,
}

/// Trait for DNS backend operations — swap Cloudflare for PowerDNS, Route53, etc.
#[async_trait]
pub trait DnsBackend: Send + Sync {
    /// Create a TXT record
    async fn create_record(&self, name: &str, content: &str, ttl: u32) -> Result<String, DnsError>;

    /// Get TXT record(s) by name
    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError>;

    /// Update an existing TXT record
    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError>;

    /// Delete a TXT record by ID
    async fn delete_record(&self, id: &str) -> Result<(), DnsError>;

    /// List all TXT records matching a prefix
    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError>;

    /// Batch create records (for efficiency)
    async fn batch_create(
        &self,
        records: Vec<(&str, &str, u32)>,
    ) -> Result<Vec<String>, DnsError> {
        // Default: sequential. Backends can override with batch APIs.
        let mut ids = Vec::new();
        for (name, content, ttl) in records {
            ids.push(self.create_record(name, content, ttl).await?);
        }
        Ok(ids)
    }
}
