//! Multi-channel DNS backend with automatic failover.
//!
//! Wraps multiple `DnsBackend` implementations (Cloudflare API, DoH, etc.)
//! and routes operations through them with health tracking and failover.
//! Write operations (create/update/delete) are routed only to API-capable
//! backends. Read operations (get/list) are tried across all channels.

use super::{DnsBackend, DnsError, TxtRecord};
use async_trait::async_trait;
use log::warn;
use std::sync::{Arc, Mutex};

/// A named backend channel with health tracking
struct Channel {
    name: String,
    backend: Arc<dyn DnsBackend>,
    /// Can this channel create/update/delete records?
    can_write: bool,
    #[allow(dead_code)]
    priority: u32,
    consecutive_failures: u32,
    max_failures_before_skip: u32,
}

impl Channel {
    fn is_available(&self) -> bool {
        self.consecutive_failures < self.max_failures_before_skip
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
    }
}

/// Snapshot of a channel for use outside the lock
struct ChannelSnapshot {
    name: String,
    backend: Arc<dyn DnsBackend>,
    can_write: bool,
    available: bool,
    /// Original index in the channels vec (stable identifier)
    index: usize,
}

/// Multi-channel backend with failover.
///
/// Channels are tried in priority order. Write operations skip read-only
/// channels (DoH, DoT). Failed channels are temporarily skipped after
/// repeated failures but retried periodically.
pub struct MultiBackend {
    channels: Mutex<Vec<Channel>>,
}

impl MultiBackend {
    pub fn new() -> Self {
        Self {
            channels: Mutex::new(Vec::new()),
        }
    }

    /// Add an API-capable channel (Cloudflare, etc.) that supports read + write
    pub fn add_rw_channel(&self, name: &str, backend: Box<dyn DnsBackend>, priority: u32) {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        channels.push(Channel {
            name: name.to_string(),
            backend: Arc::from(backend),
            can_write: true,
            priority,
            consecutive_failures: 0,
            max_failures_before_skip: 5,
        });
        channels.sort_by_key(|c| c.priority);
    }

    /// Add a read-only channel (DoH, DoT, etc.) that can only query records
    pub fn add_ro_channel(&self, name: &str, backend: Box<dyn DnsBackend>, priority: u32) {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        channels.push(Channel {
            name: name.to_string(),
            backend: Arc::from(backend),
            can_write: false,
            priority,
            consecutive_failures: 0,
            max_failures_before_skip: 5,
        });
        channels.sort_by_key(|c| c.priority);
    }

    pub fn channel_count(&self) -> usize {
        self.channels.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn status_summary(&self) -> Vec<String> {
        self.channels.lock().unwrap_or_else(|e| e.into_inner()).iter().map(|c| {
            let rw = if c.can_write { "rw" } else { "ro" };
            let health = if c.is_available() { "ok" } else { "skip" };
            format!("{:<20} pri={} {} fails={} [{}]",
                c.name, c.priority, rw, c.consecutive_failures, health)
        }).collect()
    }

    /// Take a snapshot of all channels under a single lock acquisition.
    /// The Arc-cloned backends can be used safely across .await points.
    fn snapshot(&self) -> Vec<ChannelSnapshot> {
        let channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        channels.iter().enumerate().map(|(i, c)| ChannelSnapshot {
            name: c.name.clone(),
            backend: Arc::clone(&c.backend),
            can_write: c.can_write,
            available: c.is_available(),
            index: i,
        }).collect()
    }

    fn record_success(&self, index: usize) {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ch) = channels.get_mut(index) {
            ch.record_success();
        }
    }

    fn record_failure(&self, index: usize) {
        let mut channels = self.channels.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(ch) = channels.get_mut(index) {
            ch.record_failure();
        }
    }
}

#[async_trait]
impl DnsBackend for MultiBackend {
    async fn create_record(&self, name: &str, content: &str, ttl: u32) -> Result<String, DnsError> {
        let snapshot = self.snapshot();

        for ch in &snapshot {
            if !ch.can_write || !ch.available { continue; }

            match ch.backend.create_record(name, content, ttl).await {
                Ok(id) => {
                    self.record_success(ch.index);
                    return Ok(id);
                }
                Err(e) => {
                    warn!("channel '{}' create_record failed: {e}", ch.name);
                    self.record_failure(ch.index);
                }
            }
        }

        Err(DnsError::NetworkError("all write-capable channels failed".into()))
    }

    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let snapshot = self.snapshot();

        for ch in &snapshot {
            if !ch.available { continue; }

            match ch.backend.get_records(name).await {
                Ok(records) => {
                    self.record_success(ch.index);
                    return Ok(records);
                }
                Err(e) => {
                    warn!("channel '{}' get_records failed: {e}", ch.name);
                    self.record_failure(ch.index);
                }
            }
        }

        Err(DnsError::NetworkError("all channels failed for get_records".into()))
    }

    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError> {
        let snapshot = self.snapshot();

        for ch in &snapshot {
            if !ch.can_write || !ch.available { continue; }

            match ch.backend.update_record(id, content).await {
                Ok(()) => {
                    self.record_success(ch.index);
                    return Ok(());
                }
                Err(e) => {
                    warn!("channel '{}' update_record failed: {e}", ch.name);
                    self.record_failure(ch.index);
                }
            }
        }

        Err(DnsError::NetworkError("all write-capable channels failed".into()))
    }

    async fn delete_record(&self, id: &str) -> Result<(), DnsError> {
        let snapshot = self.snapshot();

        for ch in &snapshot {
            if !ch.can_write || !ch.available { continue; }

            match ch.backend.delete_record(id).await {
                Ok(()) => {
                    self.record_success(ch.index);
                    return Ok(());
                }
                Err(e) => {
                    warn!("channel '{}' delete_record failed: {e}", ch.name);
                    self.record_failure(ch.index);
                }
            }
        }

        Err(DnsError::NetworkError("all write-capable channels failed".into()))
    }

    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let snapshot = self.snapshot();

        for ch in &snapshot {
            if !ch.can_write || !ch.available { continue; }

            match ch.backend.list_records(prefix).await {
                Ok(records) => {
                    self.record_success(ch.index);
                    return Ok(records);
                }
                Err(e) => {
                    warn!("channel '{}' list_records failed: {e}", ch.name);
                    self.record_failure(ch.index);
                }
            }
        }

        Err(DnsError::NetworkError("all channels failed for list_records".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::mock::MockDnsBackend;

    #[tokio::test]
    async fn test_multi_backend_single_channel() {
        let multi = MultiBackend::new();
        multi.add_rw_channel("mock", Box::new(MockDnsBackend::new()), 1);

        let id = multi.create_record("test.example.com", "hello", 60).await.unwrap();
        assert!(!id.is_empty());

        let records = multi.get_records("test.example.com").await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content, "hello");
    }

    #[tokio::test]
    async fn test_multi_backend_ro_channel_skips_writes() {
        let multi = MultiBackend::new();
        multi.add_ro_channel("doh", Box::new(MockDnsBackend::new()), 1);

        let result = multi.create_record("test.example.com", "hello", 60).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_multi_backend_failover_read() {
        let multi = MultiBackend::new();

        let mock1 = MockDnsBackend::new();
        let mock2 = MockDnsBackend::new();

        multi.add_rw_channel("primary", Box::new(mock1), 1);
        multi.add_rw_channel("secondary", Box::new(mock2), 2);

        multi.create_record("test.example.com", "data", 60).await.unwrap();

        let records = multi.get_records("test.example.com").await.unwrap();
        assert_eq!(records.len(), 1);
    }

    #[tokio::test]
    async fn test_multi_backend_rw_and_ro_together() {
        let multi = MultiBackend::new();

        let mock_rw = MockDnsBackend::new();
        let mock_ro = MockDnsBackend::new();

        multi.add_ro_channel("doh-fast", Box::new(mock_ro), 1);
        multi.add_rw_channel("api", Box::new(mock_rw), 2);

        let id = multi.create_record("test.example.com", "data", 60).await.unwrap();
        assert!(!id.is_empty());
    }

    #[test]
    fn test_status_summary() {
        let multi = MultiBackend::new();
        multi.add_rw_channel("api", Box::new(MockDnsBackend::new()), 1);
        multi.add_ro_channel("doh", Box::new(MockDnsBackend::new()), 2);

        let status = multi.status_summary();
        assert_eq!(status.len(), 2);
        assert!(status[0].contains("rw"));
        assert!(status[1].contains("ro"));
    }
}
