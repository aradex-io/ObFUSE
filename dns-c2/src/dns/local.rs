use super::{DnsBackend, DnsError, TxtRecord};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// DNS backend that persists to a local JSON file.
/// Multi-process safe: reloads from disk on every read, writes atomically.
pub struct LocalFileBackend {
    path: PathBuf,
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
        let store = Self::load_store(&path);
        let max_id = store.records.values()
            .flat_map(|v| v.iter())
            .filter_map(|r| r.id.strip_prefix("local-").and_then(|n| n.parse::<u64>().ok()))
            .max()
            .unwrap_or(0);

        Self {
            path,
            next_id: Mutex::new(max_id + 1),
        }
    }

    fn load_store(path: &PathBuf) -> LocalStore {
        if path.exists() {
            let data = std::fs::read_to_string(path).unwrap_or_default();
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            LocalStore::default()
        }
    }

    fn load(&self) -> LocalStore {
        Self::load_store(&self.path)
    }

    fn save(&self, store: &LocalStore) -> Result<(), DnsError> {
        let json = serde_json::to_string_pretty(store)
            .map_err(|e| DnsError::ApiError(e.to_string()))?;
        std::fs::write(&self.path, json).map_err(|e| DnsError::ApiError(e.to_string()))?;
        Ok(())
    }

    fn alloc_id(&self) -> String {
        // Reload max ID from disk to avoid collisions between processes
        let store = self.load();
        let disk_max = store.records.values()
            .flat_map(|v| v.iter())
            .filter_map(|r| r.id.strip_prefix("local-").and_then(|n| n.parse::<u64>().ok()))
            .max()
            .unwrap_or(0);

        let mut id = self.next_id.lock().unwrap();
        // Take the max of our counter and disk state + 1
        *id = (*id).max(disk_max + 1);
        let current = *id;
        *id += 1;
        format!("local-{}", current)
    }

    /// Reload + apply mutation + save (atomic read-modify-write against disk)
    fn mutate<F>(&self, f: F) -> Result<String, DnsError>
    where
        F: FnOnce(&mut LocalStore) -> String,
    {
        let mut store = self.load();
        let result = f(&mut store);
        self.save(&store)?;
        Ok(result)
    }
}

#[async_trait]
impl DnsBackend for LocalFileBackend {
    async fn create_record(&self, name: &str, content: &str, _ttl: u32) -> Result<String, DnsError> {
        let id = self.alloc_id();
        let id_clone = id.clone();
        let name = name.to_string();
        let content = content.to_string();
        self.mutate(|store| {
            store.records.entry(name).or_default()
                .push(LocalRecord { id: id_clone.clone(), content });
            id_clone
        })
    }

    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let store = self.load();
        match store.records.get(name) {
            Some(entries) => Ok(entries.iter()
                .map(|r| TxtRecord { name: name.to_string(), content: r.content.clone(), id: Some(r.id.clone()) })
                .collect()),
            None => Ok(vec![]),
        }
    }

    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError> {
        let mut store = self.load();
        for entries in store.records.values_mut() {
            for record in entries.iter_mut() {
                if record.id == id {
                    record.content = content.to_string();
                    self.save(&store)?;
                    return Ok(());
                }
            }
        }
        Err(DnsError::NotFound(format!("Record ID: {}", id)))
    }

    async fn delete_record(&self, id: &str) -> Result<(), DnsError> {
        let mut store = self.load();
        for entries in store.records.values_mut() {
            entries.retain(|r| r.id != id);
        }
        store.records.retain(|_, v| !v.is_empty());
        self.save(&store)?;
        Ok(())
    }

    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError> {
        let store = self.load();
        let mut result = Vec::new();
        for (name, entries) in store.records.iter() {
            if name.contains(prefix) {
                for r in entries {
                    result.push(TxtRecord { name: name.clone(), content: r.content.clone(), id: Some(r.id.clone()) });
                }
            }
        }
        Ok(result)
    }
}
