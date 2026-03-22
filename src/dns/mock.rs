use super::{DnsBackend, DnsError, TxtRecord};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// In-memory DNS backend for testing.
/// All records live in a HashMap — no network, no rate limits, instant.
#[derive(Clone)]
pub struct MockDnsBackend {
    /// name → Vec<(id, content)>
    records: Arc<Mutex<HashMap<String, Vec<(String, String)>>>>,
    next_id: Arc<Mutex<u64>>,
    /// Track API call counts for benchmarking
    pub stats: Arc<Mutex<MockStats>>,
}

#[derive(Debug, Default, Clone)]
pub struct MockStats {
    pub creates: u64,
    pub gets: u64,
    pub updates: u64,
    pub deletes: u64,
    pub lists: u64,
    /// Simulate rate limiting after this many calls (0 = never)
    pub rate_limit_after: u64,
    total_calls: u64,
}

impl MockStats {
    fn check_rate_limit(&mut self) -> Result<(), DnsError> {
        self.total_calls += 1;
        if self.rate_limit_after > 0 && self.total_calls > self.rate_limit_after {
            return Err(DnsError::RateLimited);
        }
        Ok(())
    }
}

impl MockDnsBackend {
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
            stats: Arc::new(Mutex::new(MockStats::default())),
        }
    }

    /// Create a mock that starts rate-limiting after N calls
    pub fn with_rate_limit(limit: u64) -> Self {
        let mock = Self::new();
        mock.stats.lock().unwrap().rate_limit_after = limit;
        mock
    }

    fn alloc_id(&self) -> String {
        let mut id = self.next_id.lock().unwrap();
        let current = *id;
        *id += 1;
        format!("mock-{}", current)
    }

    /// Get total number of records stored
    pub fn record_count(&self) -> usize {
        let records = self.records.lock().unwrap();
        records.values().map(|v| v.len()).sum()
    }

    /// Dump all records for debugging
    pub fn dump(&self) -> Vec<(String, String)> {
        let records = self.records.lock().unwrap();
        let mut result = Vec::new();
        for (name, entries) in records.iter() {
            for (id, content) in entries {
                result.push((name.clone(), content.clone()));
            }
        }
        result.sort_by(|a, b| a.0.cmp(&b.0));
        result
    }

    /// Get stats snapshot
    pub fn get_stats(&self) -> MockStats {
        self.stats.lock().unwrap().clone()
    }
}

impl Default for MockDnsBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl DnsBackend for MockDnsBackend {
    async fn create_record(&self, name: &str, content: &str, _ttl: u32) -> Result<String, DnsError> {
        {
            let mut stats = self.stats.lock().unwrap();
            stats.check_rate_limit()?;
            stats.creates += 1;
        }

        let id = self.alloc_id();
        let mut records = self.records.lock().unwrap();
        records
            .entry(name.to_string())
            .or_insert_with(Vec::new)
            .push((id.clone(), content.to_string()));
        Ok(id)
    }

    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        {
            let mut stats = self.stats.lock().unwrap();
            stats.check_rate_limit()?;
            stats.gets += 1;
        }

        let records = self.records.lock().unwrap();
        match records.get(name) {
            Some(entries) => Ok(entries
                .iter()
                .map(|(id, content)| TxtRecord {
                    name: name.to_string(),
                    content: content.clone(),
                    id: Some(id.clone()),
                })
                .collect()),
            None => Ok(vec![]),
        }
    }

    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError> {
        {
            let mut stats = self.stats.lock().unwrap();
            stats.check_rate_limit()?;
            stats.updates += 1;
        }

        let mut records = self.records.lock().unwrap();
        for entries in records.values_mut() {
            for (entry_id, entry_content) in entries.iter_mut() {
                if entry_id == id {
                    *entry_content = content.to_string();
                    return Ok(());
                }
            }
        }
        Err(DnsError::NotFound(format!("Record ID: {}", id)))
    }

    async fn delete_record(&self, id: &str) -> Result<(), DnsError> {
        {
            let mut stats = self.stats.lock().unwrap();
            stats.check_rate_limit()?;
            stats.deletes += 1;
        }

        let mut records = self.records.lock().unwrap();
        for entries in records.values_mut() {
            entries.retain(|(entry_id, _)| entry_id != id);
        }
        // Clean up empty keys
        records.retain(|_, v| !v.is_empty());
        Ok(())
    }

    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        {
            let mut stats = self.stats.lock().unwrap();
            stats.check_rate_limit()?;
            stats.lists += 1;
        }

        let records = self.records.lock().unwrap();
        let mut result = Vec::new();
        for (name, entries) in records.iter() {
            if name.contains(prefix) {
                for (id, content) in entries {
                    result.push(TxtRecord {
                        name: name.clone(),
                        content: content.clone(),
                        id: Some(id.clone()),
                    });
                }
            }
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_crud() {
        let mock = MockDnsBackend::new();

        // Create
        let id = mock.create_record("test.example.com", "hello", 60).await.unwrap();
        assert!(id.starts_with("mock-"));

        // Get
        let records = mock.get_records("test.example.com").await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].content, "hello");

        // Update
        mock.update_record(&id, "updated").await.unwrap();
        let records = mock.get_records("test.example.com").await.unwrap();
        assert_eq!(records[0].content, "updated");

        // Delete
        mock.delete_record(&id).await.unwrap();
        let records = mock.get_records("test.example.com").await.unwrap();
        assert!(records.is_empty());
    }

    #[tokio::test]
    async fn test_mock_list_prefix() {
        let mock = MockDnsBackend::new();
        mock.create_record("_c0.abc.fs.test.com", "chunk0", 60).await.unwrap();
        mock.create_record("_c1.abc.fs.test.com", "chunk1", 60).await.unwrap();
        mock.create_record("_meta.xyz.fs.test.com", "meta", 60).await.unwrap();

        let chunks = mock.list_records("fs.test.com").await.unwrap();
        assert_eq!(chunks.len(), 3);

        let meta_only = mock.list_records("_meta").await.unwrap();
        assert_eq!(meta_only.len(), 1);
    }

    #[tokio::test]
    async fn test_mock_rate_limit() {
        let mock = MockDnsBackend::with_rate_limit(3);
        assert!(mock.create_record("a", "1", 60).await.is_ok());
        assert!(mock.create_record("b", "2", 60).await.is_ok());
        assert!(mock.create_record("c", "3", 60).await.is_ok());
        // 4th call should be rate limited
        assert!(matches!(
            mock.create_record("d", "4", 60).await,
            Err(DnsError::RateLimited)
        ));
    }

    #[tokio::test]
    async fn test_mock_stats() {
        let mock = MockDnsBackend::new();
        mock.create_record("a", "1", 60).await.unwrap();
        mock.create_record("b", "2", 60).await.unwrap();
        mock.get_records("a").await.unwrap();
        mock.list_records("").await.unwrap();

        let stats = mock.get_stats();
        assert_eq!(stats.creates, 2);
        assert_eq!(stats.gets, 1);
        assert_eq!(stats.lists, 1);
    }
}
