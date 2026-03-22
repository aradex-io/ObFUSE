use super::{DnsBackend, DnsError, TxtRecord};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// DNS backend that persists records to a local JSON file.
/// Useful for demos, development, and offline operation.
///
/// Usage:
///   dnfs mount -m /tmp/dnfs -d local.dnfs --backend local --store-path ./dnfs-records.json
pub struct LocalFileBackend {
    path: PathBuf,
    records: Mutex<LocalStore>,
    next_id: Mutex<u64>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct LocalStore {
    records: HashMap<String, Vec<LocalRecord>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct LocalRecord {
    id: String,
    content: String,
}

impl LocalFileBackend {
    pub fn new(path: PathBuf) -> Self {
        let store = if path.exists() {
            let data = std::fs::read_to_string(&path).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            LocalStore::default()
        };

        // Find max existing ID to avoid collisions
        let max_id = store
            .records
            .values()
            .flat_map(|v| v.iter())
            .filter_map(|r| r.id.strip_prefix("local-").and_then(|n| n.parse::<u64>().ok()))
            .max()
            .unwrap_or(0);

        Self {
            path,
            records: Mutex::new(store),
            next_id: Mutex::new(max_id + 1),
        }
    }

    fn persist(&self) -> Result<(), DnsError> {
        let store = self.records.lock().unwrap();
        let json = serde_json::to_string_pretty(&*store)
            .map_err(|e| DnsError::ApiError(e.to_string()))?;
        std::fs::write(&self.path, json).map_err(|e| DnsError::ApiError(e.to_string()))?;
        Ok(())
    }

    fn alloc_id(&self) -> String {
        let mut id = self.next_id.lock().unwrap();
        let current = *id;
        *id += 1;
        format!("local-{}", current)
    }
}

#[async_trait]
impl DnsBackend for LocalFileBackend {
    async fn create_record(&self, name: &str, content: &str, _ttl: u32) -> Result<String, DnsError> {
        let id = self.alloc_id();
        {
            let mut store = self.records.lock().unwrap();
            store
                .records
                .entry(name.to_string())
                .or_insert_with(Vec::new)
                .push(LocalRecord {
                    id: id.clone(),
                    content: content.to_string(),
                });
        }
        self.persist()?;
        Ok(id)
    }

    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let store = self.records.lock().unwrap();
        match store.records.get(name) {
            Some(entries) => Ok(entries
                .iter()
                .map(|r| TxtRecord {
                    name: name.to_string(),
                    content: r.content.clone(),
                    id: Some(r.id.clone()),
                })
                .collect()),
            None => Ok(vec![]),
        }
    }

    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError> {
        {
            let mut store = self.records.lock().unwrap();
            for entries in store.records.values_mut() {
                for record in entries.iter_mut() {
                    if record.id == id {
                        record.content = content.to_string();
                        drop(store);
                        self.persist()?;
                        return Ok(());
                    }
                }
            }
        }
        Err(DnsError::NotFound(format!("Record ID: {}", id)))
    }

    async fn delete_record(&self, id: &str) -> Result<(), DnsError> {
        {
            let mut store = self.records.lock().unwrap();
            for entries in store.records.values_mut() {
                entries.retain(|r| r.id != id);
            }
            store.records.retain(|_, v| !v.is_empty());
        }
        self.persist()?;
        Ok(())
    }

    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let store = self.records.lock().unwrap();
        let mut result = Vec::new();
        for (name, entries) in store.records.iter() {
            if name.contains(prefix) {
                for r in entries {
                    result.push(TxtRecord {
                        name: name.clone(),
                        content: r.content.clone(),
                        id: Some(r.id.clone()),
                    });
                }
            }
        }
        Ok(result)
    }
}
