pub mod cloudflare;
pub mod doh;
pub mod local;
pub mod mock;
pub mod multi;
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
    pub name: String,
    pub content: String,
    pub id: Option<String>,
}

/// Trait for DNS backend operations
#[async_trait]
pub trait DnsBackend: Send + Sync {
    async fn create_record(&self, name: &str, content: &str, ttl: u32) -> Result<String, DnsError>;
    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError>;
    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError>;
    async fn delete_record(&self, id: &str) -> Result<(), DnsError>;
    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError>;

    async fn batch_create(
        &self,
        records: Vec<(&str, &str, u32)>,
    ) -> Result<Vec<String>, DnsError> {
        let mut ids = Vec::new();
        for (name, content, ttl) in records {
            ids.push(self.create_record(name, content, ttl).await?);
        }
        Ok(ids)
    }
}
