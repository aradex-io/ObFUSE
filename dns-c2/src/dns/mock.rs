use super::{DnsBackend, DnsError, TxtRecord};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct MockDnsBackend {
    records: Arc<Mutex<HashMap<String, Vec<(String, String)>>>>,
    next_id: Arc<Mutex<u64>>,
}

impl MockDnsBackend {
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    fn alloc_id(&self) -> String {
        let mut id = self.next_id.lock().unwrap();
        let current = *id;
        *id += 1;
        format!("mock-{}", current)
    }
}

impl Default for MockDnsBackend {
    fn default() -> Self { Self::new() }
}

#[async_trait]
impl DnsBackend for MockDnsBackend {
    async fn create_record(&self, name: &str, content: &str, _ttl: u32) -> Result<String, DnsError> {
        let id = self.alloc_id();
        let mut records = self.records.lock().unwrap();
        records.entry(name.to_string()).or_default()
            .push((id.clone(), content.to_string()));
        Ok(id)
    }

    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let records = self.records.lock().unwrap();
        match records.get(name) {
            Some(entries) => Ok(entries.iter()
                .map(|(id, content)| TxtRecord { name: name.to_string(), content: content.clone(), id: Some(id.clone()) })
                .collect()),
            None => Ok(vec![]),
        }
    }

    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError> {
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
        let mut records = self.records.lock().unwrap();
        for entries in records.values_mut() {
            entries.retain(|(entry_id, _)| entry_id != id);
        }
        records.retain(|_, v| !v.is_empty());
        Ok(())
    }

    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let records = self.records.lock().unwrap();
        let mut result = Vec::new();
        for (name, entries) in records.iter() {
            if name.contains(prefix) {
                for (id, content) in entries {
                    result.push(TxtRecord { name: name.clone(), content: content.clone(), id: Some(id.clone()) });
                }
            }
        }
        Ok(result)
    }
}
