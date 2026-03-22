use crate::chunk;
use crate::crypto::{self, keys, EncryptionKey};
use crate::dns::{DnsBackend, DnsError};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),
    #[error("Chunk error: {0}")]
    Chunk(String),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("File too large: {size} bytes (max {max})")]
    FileTooLarge { size: usize, max: usize },
    #[error("Corrupt record at {location}: {detail}")]
    CorruptRecord { location: String, detail: String },
    #[error("Other: {0}")]
    Other(String),
}

const HASH_LABEL_LEN: usize = 32;
const RECORD_TTL: u32 = 60;

/// Storage configuration
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Maximum file size in bytes (default: 64KB)
    pub max_file_size: usize,
    /// Whether to skip corrupt records gracefully (default: true)
    pub recover_corrupt: bool,
    /// Whether to rebuild inode table from DNS on construction (default: false)
    pub rebuild_on_mount: bool,
    /// Metadata cache TTL in seconds (default: 30)
    pub cache_ttl_secs: u64,
    /// Maximum parallel chunk fetches (default: 8)
    pub max_parallel_fetches: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            max_file_size: 64 * 1024,
            recover_corrupt: true,
            rebuild_on_mount: false,
            cache_ttl_secs: 30,
            max_parallel_fetches: 8,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileMeta {
    pub name: String,
    pub size: u64,
    pub mode: u32,
    pub chunk_count: u32,
    pub chunk_hashes: Vec<String>,
    pub created: u64,
    pub modified: u64,
    pub content_hash: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub inode: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DirMeta {
    pub entries: Vec<DirEntry>,
    pub modified: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VolumeMeta {
    pub version: u32,
    pub created: u64,
    pub label: String,
    pub root_hash: String,
}

// ─── TTL-Aware Cache ────────────────────────────────────────────────

struct CacheEntry<T: Clone> {
    value: T,
    inserted: Instant,
}

struct TtlCache<T: Clone> {
    inner: lru::LruCache<String, CacheEntry<T>>,
    ttl: Duration,
    hits: u64,
    misses: u64,
}

impl<T: Clone> TtlCache<T> {
    fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: lru::LruCache::new(std::num::NonZeroUsize::new(capacity).unwrap()),
            ttl,
            hits: 0,
            misses: 0,
        }
    }

    fn get(&mut self, key: &str) -> Option<T> {
        if let Some(entry) = self.inner.get(key) {
            if entry.inserted.elapsed() < self.ttl {
                self.hits += 1;
                return Some(entry.value.clone());
            }
            // Expired — will be evicted on next put or naturally by LRU
            self.inner.pop(key);
        }
        self.misses += 1;
        None
    }

    fn put(&mut self, key: String, value: T) {
        self.inner.put(key, CacheEntry {
            value,
            inserted: Instant::now(),
        });
    }

    fn invalidate(&mut self, key: &str) {
        self.inner.pop(key);
    }

    fn hit_rate(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 { 0.0 } else { self.hits as f64 / total as f64 }
    }

    fn stats(&self) -> (u64, u64) {
        (self.hits, self.misses)
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn truncate_hash(hash: &str) -> &str {
    &hash[..HASH_LABEL_LEN.min(hash.len())]
}

pub fn path_hash(path: &str) -> String {
    let full = crypto::content_hash(path.as_bytes());
    truncate_hash(&full).to_string()
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─── Storage Engine ─────────────────────────────────────────────────

pub struct DnfsStorage {
    backend: Box<dyn DnsBackend>,
    master_key: EncryptionKey,
    domain: String,
    config: StorageConfig,
    inode_map: HashMap<u64, String>,
    path_map: HashMap<String, u64>,
    next_inode: u64,
    known_chunks: HashSet<String>,
    meta_cache: TtlCache<FileMeta>,
    dir_cache: TtlCache<DirMeta>,
    rt: tokio::runtime::Runtime,
}

impl DnfsStorage {
    pub fn new(backend: Box<dyn DnsBackend>, master_key: EncryptionKey, domain: String) -> Self {
        Self::with_config(backend, master_key, domain, StorageConfig::default())
    }

    pub fn with_config(
        backend: Box<dyn DnsBackend>,
        master_key: EncryptionKey,
        domain: String,
        config: StorageConfig,
    ) -> Self {
        let ttl = Duration::from_secs(config.cache_ttl_secs);
        let rebuild = config.rebuild_on_mount;
        let mut s = Self {
            backend,
            master_key,
            domain,
            config,
            inode_map: HashMap::new(),
            path_map: HashMap::new(),
            next_inode: 2,
            known_chunks: HashSet::new(),
            meta_cache: TtlCache::new(512, ttl),
            dir_cache: TtlCache::new(256, ttl),
            rt: tokio::runtime::Runtime::new().expect("Failed to create async runtime"),
        };
        if rebuild {
            if let Err(e) = s.rebuild_state() {
                error!("Failed to rebuild state from DNS: {}. Starting fresh.", e);
            }
        }
        s
    }

    fn meta_key(&self) -> EncryptionKey { keys::derive_meta_key(&self.master_key) }
    fn data_key(&self) -> EncryptionKey { keys::derive_data_key(&self.master_key) }

    fn record_name(&self, prefix: &str, hash: &str) -> String {
        format!("{}.{}.{}", prefix, hash, self.domain)
    }

    fn alloc_inode(&mut self) -> u64 {
        let ino = self.next_inode;
        self.next_inode += 1;
        ino
    }

    // ─── Corrupt Record Recovery ────────────────────────────────────

    fn decode_encrypted_record(&self, content: &str, location: &str) -> Result<Vec<u8>, StorageError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(content)
            .map_err(|e| {
                if self.config.recover_corrupt { warn!("Corrupt base64 at {}: {}", location, e); }
                StorageError::CorruptRecord { location: location.to_string(), detail: format!("base64: {}", e) }
            })?;
        crypto::decrypt(&self.meta_key(), &bytes).map_err(|e| {
            if self.config.recover_corrupt { warn!("Corrupt ciphertext at {}: {}", location, e); }
            StorageError::CorruptRecord { location: location.to_string(), detail: format!("decrypt: {}", e) }
        })
    }

    fn parse_file_meta(&self, data: &[u8], loc: &str) -> Result<FileMeta, StorageError> {
        serde_json::from_slice(data).map_err(|e| StorageError::CorruptRecord {
            location: loc.to_string(), detail: format!("JSON: {}", e),
        })
    }

    fn parse_dir_meta(&self, data: &[u8], loc: &str) -> Result<DirMeta, StorageError> {
        serde_json::from_slice(data).map_err(|e| StorageError::CorruptRecord {
            location: loc.to_string(), detail: format!("JSON: {}", e),
        })
    }

    // ─── Mount State Rebuild ────────────────────────────────────────

    pub fn rebuild_state(&mut self) -> Result<(), StorageError> {
        info!("Rebuilding filesystem state from DNS...");
        let all_records = self.rt.block_on(async { self.backend.list_records(&self.domain).await })?;

        let mut file_count = 0u64;
        let mut chunk_count = 0u64;
        let mut corrupt_count = 0u64;

        for record in &all_records {
            if record.name.contains("_meta.") {
                match self.decode_encrypted_record(&record.content, &record.name) {
                    Ok(dec) => match self.parse_file_meta(&dec, &record.name) {
                        Ok(meta) => {
                            for h in &meta.chunk_hashes { self.known_chunks.insert(h.clone()); }
                            file_count += 1;
                        }
                        Err(_) => corrupt_count += 1,
                    },
                    Err(_) => corrupt_count += 1,
                }
            } else if record.name.contains("_c") {
                chunk_count += 1;
            }
        }

        if let Err(e) = self.rebuild_dir_tree("/") { warn!("Partial dir rebuild: {}", e); }

        info!("Rebuild: {} files, {} chunks, {} corrupt", file_count, chunk_count, corrupt_count);
        Ok(())
    }

    fn rebuild_dir_tree(&mut self, path: &str) -> Result<(), StorageError> {
        let dir = match self.read_dir(path) {
            Ok(d) => d,
            Err(StorageError::CorruptRecord { .. }) if self.config.recover_corrupt => return Ok(()),
            Err(e) => return Err(e),
        };
        for entry in &dir.entries {
            let child = if path == "/" { format!("/{}", entry.name) } else { format!("{}/{}", path, entry.name) };
            self.register_path(&child);
            if entry.is_dir {
                let _ = self.rebuild_dir_tree(&child);
            } else if let Ok(meta) = self.stat_file(&child) {
                for h in &meta.chunk_hashes { self.known_chunks.insert(h.clone()); }
            }
        }
        Ok(())
    }

    // ─── Parallel Chunk Fetch ───────────────────────────────────────

    /// Fetch multiple chunk records concurrently.
    /// Returns results in order matching the input hashes.
    fn fetch_chunks_parallel(
        &self,
        chunk_hashes: &[(usize, String)], // (index, hash)
    ) -> Result<Vec<String>, StorageError> {
        let domain = &self.domain;
        let max_par = self.config.max_parallel_fetches;

        // Build all record names upfront
        let record_names: Vec<(usize, String)> = chunk_hashes
            .iter()
            .map(|(i, h)| (*i, format!("_c.{}.{}", h, domain)))
            .collect();

        // Fetch in parallel batches
        let results = self.rt.block_on(async {
            let mut all_results: Vec<(usize, Result<String, StorageError>)> = Vec::new();

            for batch in record_names.chunks(max_par) {
                let futures: Vec<_> = batch
                    .iter()
                    .map(|(idx, rname)| {
                        let rname = rname.clone();
                        let idx = *idx;
                        async move {
                            let records = self.backend.get_records(&rname).await;
                            (idx, rname, records)
                        }
                    })
                    .collect();

                let batch_results = futures::future::join_all(futures).await;

                for (idx, rname, result) in batch_results {
                    match result {
                        Ok(records) if !records.is_empty() => {
                            all_results.push((idx, Ok(records[0].content.clone())));
                        }
                        Ok(_) => {
                            all_results.push((idx, Err(StorageError::NotFound(
                                format!("Chunk {} at {}", idx, rname),
                            ))));
                        }
                        Err(e) => {
                            all_results.push((idx, Err(StorageError::Dns(e))));
                        }
                    }
                }
            }

            all_results
        });

        // Sort by index and extract
        let mut sorted: Vec<(usize, Result<String, StorageError>)> = results;
        sorted.sort_by_key(|(idx, _)| *idx);

        let mut encoded = Vec::with_capacity(sorted.len());
        for (idx, result) in sorted {
            encoded.push(result?);
        }

        Ok(encoded)
    }

    // ─── Write Coalescing ───────────────────────────────────────────

    /// Write chunks using batch_create when possible to reduce API round-trips.
    fn write_chunks_coalesced(
        &mut self,
        chunks: &[chunk::Chunk],
    ) -> Result<Vec<String>, StorageError> {
        let mut chunk_hashes = Vec::new();
        let mut to_create: Vec<(String, String)> = Vec::new(); // (record_name, encoded)

        for c in chunks {
            let label = truncate_hash(&c.content_hash);
            chunk_hashes.push(label.to_string());

            if self.known_chunks.contains(label) {
                debug!("Dedup hit: chunk {} content={}", c.index, label);
                continue;
            }

            let rname = self.record_name("_c", label);
            to_create.push((rname, c.encoded.clone()));
            self.known_chunks.insert(label.to_string());
        }

        if !to_create.is_empty() {
            debug!("Batch creating {} chunk records", to_create.len());

            // Use batch_create for efficiency
            let batch: Vec<(&str, &str, u32)> = to_create
                .iter()
                .map(|(name, content)| (name.as_str(), content.as_str(), RECORD_TTL))
                .collect();

            self.rt.block_on(async {
                self.backend.batch_create(batch).await
            })?;
        }

        Ok(chunk_hashes)
    }

    // ─── Core File Operations ───────────────────────────────────────

    pub fn write_file(&mut self, path: &str, data: &[u8]) -> Result<FileMeta, StorageError> {
        if data.len() > self.config.max_file_size {
            return Err(StorageError::FileTooLarge { size: data.len(), max: self.config.max_file_size });
        }

        // Use path-independent data key for chunks so cross-file dedup works
        let file_key = self.data_key();
        let content_hash = crypto::content_hash(data);

        let chunks = chunk::chunkify(data, &file_key)
            .map_err(|e| StorageError::Chunk(e.to_string()))?;

        info!("Writing {} ({} bytes, {} chunks)", path, data.len(), chunks.len());

        // Coalesced batch write
        let chunk_hashes = self.write_chunks_coalesced(&chunks)?;

        // Preserve original creation timestamp on overwrite
        let created = self.stat_file(path)
            .map(|m| m.created)
            .unwrap_or_else(|_| now_epoch());

        let meta = FileMeta {
            name: path.rsplit('/').next().unwrap_or(path).to_string(),
            size: data.len() as u64,
            mode: 0o644,
            chunk_count: chunks.len() as u32,
            chunk_hashes,
            created,
            modified: now_epoch(),
            content_hash: truncate_hash(&content_hash).to_string(),
        };

        let meta_json = serde_json::to_string(&meta)?;
        let meta_enc = crypto::encrypt(&self.meta_key(), meta_json.as_bytes())?;
        use base64::Engine;
        let meta_b64 = base64::engine::general_purpose::STANDARD.encode(&meta_enc);

        let phash = path_hash(path);
        let meta_rname = self.record_name("_meta", &phash);
        self.rt.block_on(async {
            if let Ok(existing) = self.backend.get_records(&meta_rname).await {
                for r in existing {
                    if let Some(id) = r.id { let _ = self.backend.delete_record(&id).await; }
                }
            }
            self.backend.create_record(&meta_rname, &meta_b64, RECORD_TTL).await
        })?;

        self.meta_cache.put(phash, meta.clone());

        if !self.path_map.contains_key(path) {
            let ino = self.alloc_inode();
            self.inode_map.insert(ino, path.to_string());
            self.path_map.insert(path.to_string(), ino);
        }

        Ok(meta)
    }

    /// Read file — fetches metadata then all chunks in parallel
    pub fn read_file(&mut self, path: &str) -> Result<Vec<u8>, StorageError> {
        // Use path-independent data key for chunks so cross-file dedup works
        let file_key = self.data_key();
        let file_meta = self.stat_file(path)?;

        info!("Reading {} ({} bytes, {} chunks)", path, file_meta.size, file_meta.chunk_count);

        // Parallel fetch all chunks
        let indexed_hashes: Vec<(usize, String)> = file_meta
            .chunk_hashes
            .iter()
            .enumerate()
            .map(|(i, h)| (i, h.clone()))
            .collect();

        let encoded_chunks = self.fetch_chunks_parallel(&indexed_hashes)?;

        chunk::dechunkify(&encoded_chunks, &file_key)
            .map_err(|e| StorageError::Chunk(e.to_string()))
    }

    pub fn stat_file(&mut self, path: &str) -> Result<FileMeta, StorageError> {
        let phash = path_hash(path);

        // TTL-aware cache check
        if let Some(cached) = self.meta_cache.get(&phash) {
            return Ok(cached);
        }

        let meta_rname = self.record_name("_meta", &phash);
        let records = self.rt.block_on(async { self.backend.get_records(&meta_rname).await })?;

        if records.is_empty() {
            return Err(StorageError::NotFound(path.to_string()));
        }

        let decrypted = self.decode_encrypted_record(&records[0].content, &meta_rname)?;
        let meta = self.parse_file_meta(&decrypted, &meta_rname)?;
        self.meta_cache.put(phash, meta.clone());
        Ok(meta)
    }

    pub fn write_dir(&mut self, path: &str, entries: &[DirEntry]) -> Result<(), StorageError> {
        let dm = DirMeta { entries: entries.to_vec(), modified: now_epoch() };
        let json = serde_json::to_string(&dm)?;
        let enc = crypto::encrypt(&self.meta_key(), json.as_bytes())?;
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&enc);

        let phash = path_hash(path);
        let rname = self.record_name("_dir", &phash);

        self.rt.block_on(async {
            if let Ok(existing) = self.backend.get_records(&rname).await {
                for r in existing {
                    if let Some(id) = r.id { let _ = self.backend.delete_record(&id).await; }
                }
            }
            self.backend.create_record(&rname, &b64, RECORD_TTL).await
        })?;

        // Update dir cache
        self.dir_cache.put(phash, dm);
        Ok(())
    }

    /// Read directory — with TTL cache, no child metadata resolution (lazy)
    pub fn read_dir(&mut self, path: &str) -> Result<DirMeta, StorageError> {
        let phash = path_hash(path);

        // TTL-aware dir cache
        if let Some(cached) = self.dir_cache.get(&phash) {
            return Ok(cached);
        }

        let rname = self.record_name("_dir", &phash);
        let records = self.rt.block_on(async { self.backend.get_records(&rname).await })?;

        if records.is_empty() {
            return Ok(DirMeta { entries: vec![], modified: now_epoch() });
        }

        let decrypted = self.decode_encrypted_record(&records[0].content, &rname)?;
        let dm = self.parse_dir_meta(&decrypted, &rname)?;
        self.dir_cache.put(phash, dm.clone());
        Ok(dm)
    }

    pub fn delete_file(&mut self, path: &str) -> Result<(), StorageError> {
        let phash = path_hash(path);
        self.meta_cache.invalidate(&phash);
        self.dir_cache.invalidate(&phash);

        let meta_rname = self.record_name("_meta", &phash);
        self.rt.block_on(async {
            if let Ok(records) = self.backend.get_records(&meta_rname).await {
                for r in records {
                    if let Some(id) = r.id { let _ = self.backend.delete_record(&id).await; }
                }
            }
        });

        if let Some(ino) = self.path_map.remove(path) { self.inode_map.remove(&ino); }
        Ok(())
    }

    pub fn rename_file(&mut self, old_path: &str, new_path: &str) -> Result<(), StorageError> {
        let data = self.read_file(old_path)?;
        self.write_file(new_path, &data)?;
        self.delete_file(old_path)?;
        Ok(())
    }

    pub fn get_inode(&self, path: &str) -> Option<u64> { self.path_map.get(path).copied() }
    pub fn get_path(&self, inode: u64) -> Option<&str> { self.inode_map.get(&inode).map(|s| s.as_str()) }

    pub fn register_path(&mut self, path: &str) -> u64 {
        if let Some(&ino) = self.path_map.get(path) { return ino; }
        let ino = self.alloc_inode();
        self.inode_map.insert(ino, path.to_string());
        self.path_map.insert(path.to_string(), ino);
        ino
    }

    pub fn config(&self) -> &StorageConfig { &self.config }
    pub fn dedup_chunk_count(&self) -> usize { self.known_chunks.len() }

    /// Get cache hit rate stats: (meta_hits, meta_misses, dir_hits, dir_misses)
    pub fn cache_stats(&self) -> (u64, u64, u64, u64) {
        let (mh, mm) = self.meta_cache.stats();
        let (dh, dm) = self.dir_cache.stats();
        (mh, mm, dh, dm)
    }

    /// Get metadata cache hit rate as a percentage
    pub fn meta_cache_hit_rate(&self) -> f64 { self.meta_cache.hit_rate() }
    pub fn dir_cache_hit_rate(&self) -> f64 { self.dir_cache.hit_rate() }
}

// ─── Volume Operations ──────────────────────────────────────────────

pub async fn init_volume(backend: &dyn DnsBackend, domain: &str) -> Result<(), StorageError> {
    let vol = VolumeMeta { version: 1, created: now_epoch(), label: "dnfs".to_string(), root_hash: path_hash("/") };
    backend.create_record(&format!("_vol.{}", domain), &serde_json::to_string(&vol)?, RECORD_TTL).await?;
    let root = DirMeta { entries: vec![], modified: now_epoch() };
    backend.create_record(&format!("_dir.{}.{}", path_hash("/"), domain), &serde_json::to_string(&root)?, RECORD_TTL).await?;
    info!("Volume initialized: {}", domain);
    Ok(())
}

pub async fn get_volume_stats(backend: &dyn DnsBackend, domain: &str) -> Result<String, StorageError> {
    let records = backend.get_records(&format!("_vol.{}", domain)).await?;
    if records.is_empty() { return Err(StorageError::NotFound("Volume not initialized".to_string())); }
    let vol: VolumeMeta = serde_json::from_str(&records[0].content)?;
    let all = backend.list_records(domain).await?;
    let chunks = all.iter().filter(|r| r.name.contains("_c")).count();
    let files = all.iter().filter(|r| r.name.contains("_meta")).count();
    Ok(format!(
        "Dn(f)s Volume: {}\nVersion: {}\nCreated: {}\nFiles: {}\nChunks: {}\nTotal DNS records: {}",
        domain, vol.version, vol.created, files, chunks, all.len()
    ))
}
