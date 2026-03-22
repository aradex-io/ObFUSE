use super::{DnsBackend, DnsError, TxtRecord};
use async_trait::async_trait;
use log::{info, warn};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_retries: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub jitter_factor: f64,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_millis(500),
            max_backoff: Duration::from_secs(30),
            jitter_factor: 0.3,
        }
    }
}

pub struct RetryBackend {
    inner: Box<dyn DnsBackend>,
    config: RetryConfig,
}

impl RetryBackend {
    pub fn new(inner: Box<dyn DnsBackend>, config: RetryConfig) -> Self {
        Self { inner, config }
    }

    pub fn with_defaults(inner: Box<dyn DnsBackend>) -> Self {
        Self::new(inner, RetryConfig::default())
    }

    fn backoff_duration(&self, attempt: u32) -> Duration {
        let base = self.config.initial_backoff.as_millis()
            .saturating_mul(2u128.saturating_pow(attempt));
        let capped = base.min(self.config.max_backoff.as_millis());
        let jitter_range = (capped as f64) * self.config.jitter_factor;
        let jitter = (rand::random::<f64>() * 2.0 - 1.0) * jitter_range;
        let final_ms = (capped as f64 + jitter).max(10.0) as u64;
        Duration::from_millis(final_ms)
    }

    fn is_retryable(err: &DnsError) -> bool {
        matches!(err, DnsError::RateLimited | DnsError::NetworkError(_))
    }
}

macro_rules! retry_method {
    ($self:ident, $method:ident, $($arg:expr),*) => {{
        let mut last_err = None;
        for attempt in 0..=$self.config.max_retries {
            match $self.inner.$method($($arg),*).await {
                Ok(result) => {
                    if attempt > 0 { info!("Retry succeeded on attempt {}", attempt + 1); }
                    return Ok(result);
                }
                Err(e) if Self::is_retryable(&e) && attempt < $self.config.max_retries => {
                    let backoff = $self.backoff_duration(attempt);
                    warn!("{} failed (attempt {}/{}): {}. Retrying in {:?}",
                        stringify!($method), attempt + 1, $self.config.max_retries + 1, e, backoff);
                    tokio::time::sleep(backoff).await;
                    last_err = Some(e);
                }
                Err(e) => return Err(e),
            }
        }
        Err(last_err.unwrap_or(DnsError::ApiError("Retry exhausted".to_string())))
    }};
}

#[async_trait]
impl DnsBackend for RetryBackend {
    async fn create_record(&self, name: &str, content: &str, ttl: u32) -> Result<String, DnsError> {
        retry_method!(self, create_record, name, content, ttl)
    }
    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        retry_method!(self, get_records, name)
    }
    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError> {
        retry_method!(self, update_record, id, content)
    }
    async fn delete_record(&self, id: &str) -> Result<(), DnsError> {
        retry_method!(self, delete_record, id)
    }
    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        retry_method!(self, list_records, prefix)
    }
}
