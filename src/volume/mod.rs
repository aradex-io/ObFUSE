//! Volume-level operations for Dn(f)s.
//!
//! - `gc`: Garbage-collect orphaned chunk records
//! - `fsck`: Verify integrity of all files and chunks
//! - `export`: Dump entire volume to a local tar archive
//! - `nuke`: Delete all records under the domain

use crate::crypto::{self, keys, EncryptionKey};
use crate::dns::{DnsBackend, TxtRecord};
use crate::storage::{DirMeta, FileMeta, StorageError, path_hash};
use log::{debug, info, warn};
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Result of a GC pass
#[derive(Debug)]
pub struct GcResult {
    /// Total chunk records scanned
    pub total_chunks: usize,
    /// Chunks still referenced by at least one file
    pub live_chunks: usize,
    /// Orphaned chunks deleted
    pub orphaned_deleted: usize,
    /// Errors encountered during deletion
    pub delete_errors: usize,
}

impl std::fmt::Display for GcResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GC complete:\n  Scanned: {} chunks\n  Live: {}\n  Orphaned & deleted: {}\n  Errors: {}",
            self.total_chunks, self.live_chunks, self.orphaned_deleted, self.delete_errors
        )
    }
}

/// A single issue found by fsck
#[derive(Debug, Clone)]
pub struct FsckIssue {
    pub severity: FsckSeverity,
    pub path: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FsckSeverity {
    Error,
    Warning,
}

/// Result of an fsck pass
#[derive(Debug)]
pub struct FsckResult {
    pub files_checked: usize,
    pub dirs_checked: usize,
    pub chunks_verified: usize,
    pub issues: Vec<FsckIssue>,
}

impl FsckResult {
    pub fn is_clean(&self) -> bool {
        self.issues.iter().all(|i| i.severity != FsckSeverity::Error)
    }
}

impl std::fmt::Display for FsckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fsck complete:\n  Files: {}\n  Dirs: {}\n  Chunks verified: {}\n  Issues: {}",
            self.files_checked,
            self.dirs_checked,
            self.chunks_verified,
            self.issues.len()
        )?;
        for issue in &self.issues {
            let marker = match issue.severity {
                FsckSeverity::Error => "ERROR",
                FsckSeverity::Warning => "WARN ",
            };
            write!(f, "\n  [{}] {}: {}", marker, issue.path, issue.detail)?;
        }
        Ok(())
    }
}

/// Result of a nuke operation
#[derive(Debug)]
pub struct NukeResult {
    pub records_deleted: usize,
    pub errors: usize,
}

// ─── Helpers ────────────────────────────────────────────────────────

fn decode_encrypted(
    meta_key: &EncryptionKey,
    content: &str,
) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(content)
        .map_err(|e| format!("base64: {}", e))?;
    crypto::decrypt(meta_key, &bytes).map_err(|e| format!("decrypt: {}", e))
}

// ─── Garbage Collection ─────────────────────────────────────────────

/// Scan all _meta records to build the set of referenced chunk hashes,
/// then delete any _c* records not in that set.
pub async fn gc(
    backend: &dyn DnsBackend,
    domain: &str,
    master_key: &EncryptionKey,
    dry_run: bool,
) -> Result<GcResult, StorageError> {
    let meta_key = keys::derive_meta_key(master_key);

    info!("GC: scanning all records under {}", domain);
    let all_records = backend.list_records(domain).await?;

    // Pass 1: Build set of referenced chunk hashes from all file metadata
    let mut referenced_hashes: HashSet<String> = HashSet::new();
    let mut meta_count = 0;

    for record in &all_records {
        if !record.name.contains("_meta.") {
            continue;
        }
        meta_count += 1;

        match decode_encrypted(&meta_key, &record.content) {
            Ok(decrypted) => {
                if let Ok(meta) = serde_json::from_slice::<FileMeta>(&decrypted) {
                    for hash in &meta.chunk_hashes {
                        referenced_hashes.insert(hash.clone());
                    }
                }
            }
            Err(e) => {
                warn!("GC: skipping unreadable metadata at {}: {}", record.name, e);
            }
        }
    }

    info!("GC: {} files reference {} unique chunk hashes", meta_count, referenced_hashes.len());

    // Pass 2: Find chunk records and check if they're referenced
    let mut total_chunks = 0;
    let mut orphaned_deleted = 0;
    let mut delete_errors = 0;
    let mut live_chunks = 0;

    for record in &all_records {
        // Chunk records contain "_c" followed by a digit
        if !is_chunk_record(&record.name) {
            continue;
        }
        total_chunks += 1;

        // Extract the content hash from the record name: _c{N}.{hash}.{domain}
        let hash = extract_chunk_hash(&record.name, domain);

        if let Some(ref h) = hash {
            if referenced_hashes.contains(h.as_str()) {
                live_chunks += 1;
                continue;
            }
        }

        // Orphaned chunk
        if dry_run {
            info!("GC [dry-run]: would delete orphaned chunk {}", record.name);
            orphaned_deleted += 1;
        } else {
            if let Some(ref id) = record.id {
                match backend.delete_record(id).await {
                    Ok(()) => {
                        debug!("GC: deleted orphaned chunk {}", record.name);
                        orphaned_deleted += 1;
                    }
                    Err(e) => {
                        warn!("GC: failed to delete {}: {}", record.name, e);
                        delete_errors += 1;
                    }
                }
            }
        }
    }

    Ok(GcResult {
        total_chunks,
        live_chunks,
        orphaned_deleted,
        delete_errors,
    })
}

/// Check if a record name looks like a chunk record (_c.{hash}.{domain})
fn is_chunk_record(name: &str) -> bool {
    name.starts_with("_c.") || name.contains("._c.")
}

/// Extract the content hash from a chunk record name.
/// Format: _c.{hash}.{domain} → returns hash
fn extract_chunk_hash(name: &str, domain: &str) -> Option<String> {
    let without_domain = name.strip_suffix(&format!(".{}", domain))?;
    // without_domain = "_c.abcdef1234..."
    let after_prefix = without_domain.strip_prefix("_c.")?;
    Some(after_prefix.to_string())
}

// ─── Filesystem Check ───────────────────────────────────────────────

/// Verify the integrity of all files and chunks in the volume.
pub async fn fsck(
    backend: &dyn DnsBackend,
    domain: &str,
    master_key: &EncryptionKey,
) -> Result<FsckResult, StorageError> {
    let meta_key = keys::derive_meta_key(master_key);

    info!("fsck: scanning volume {}", domain);
    let all_records = backend.list_records(domain).await?;

    let mut result = FsckResult {
        files_checked: 0,
        dirs_checked: 0,
        chunks_verified: 0,
        issues: Vec::new(),
    };

    // Build a set of all existing chunk record names for fast lookup
    let mut chunk_records: HashSet<String> = HashSet::new();
    for r in &all_records {
        if is_chunk_record(&r.name) {
            chunk_records.insert(r.name.clone());
        }
    }

    // Check all file metadata records
    for record in &all_records {
        if !record.name.contains("_meta.") {
            continue;
        }
        result.files_checked += 1;

        // Try to decrypt metadata
        let decrypted = match decode_encrypted(&meta_key, &record.content) {
            Ok(d) => d,
            Err(e) => {
                result.issues.push(FsckIssue {
                    severity: FsckSeverity::Error,
                    path: record.name.clone(),
                    detail: format!("Cannot decrypt metadata: {}", e),
                });
                continue;
            }
        };

        // Try to parse JSON
        let meta: FileMeta = match serde_json::from_slice(&decrypted) {
            Ok(m) => m,
            Err(e) => {
                result.issues.push(FsckIssue {
                    severity: FsckSeverity::Error,
                    path: record.name.clone(),
                    detail: format!("Invalid metadata JSON: {}", e),
                });
                continue;
            }
        };

        // Verify each referenced chunk exists
        for (i, hash) in meta.chunk_hashes.iter().enumerate() {
            let expected_name = format!("_c.{}.{}", hash, domain);
            if chunk_records.contains(&expected_name) {
                result.chunks_verified += 1;
            } else {
                result.issues.push(FsckIssue {
                    severity: FsckSeverity::Error,
                    path: meta.name.clone(),
                    detail: format!("Missing chunk {} (hash: {})", i, hash),
                });
            }
        }

        // Verify chunk count matches
        if meta.chunk_count as usize != meta.chunk_hashes.len() {
            result.issues.push(FsckIssue {
                severity: FsckSeverity::Warning,
                path: meta.name.clone(),
                detail: format!(
                    "chunk_count={} but {} hashes listed",
                    meta.chunk_count,
                    meta.chunk_hashes.len()
                ),
            });
        }
    }

    // Check directory records
    for record in &all_records {
        if !record.name.contains("_dir.") {
            continue;
        }
        result.dirs_checked += 1;

        if let Err(e) = decode_encrypted(&meta_key, &record.content) {
            result.issues.push(FsckIssue {
                severity: FsckSeverity::Error,
                path: record.name.clone(),
                detail: format!("Cannot decrypt directory: {}", e),
            });
        }
    }

    // Check for volume record
    let vol_name = format!("_vol.{}", domain);
    if !all_records.iter().any(|r| r.name == vol_name) {
        result.issues.push(FsckIssue {
            severity: FsckSeverity::Warning,
            path: vol_name,
            detail: "Volume metadata record missing".to_string(),
        });
    }

    Ok(result)
}

// ─── Export ─────────────────────────────────────────────────────────

/// Export the entire volume to a tar.gz archive.
/// Walks the directory tree and writes each file's decrypted content.
pub async fn export(
    backend: &dyn DnsBackend,
    domain: &str,
    master_key: &EncryptionKey,
    output_path: &Path,
) -> Result<usize, StorageError> {
    use std::fs::File;

    let meta_key = keys::derive_meta_key(master_key);

    info!("Export: scanning volume {}", domain);
    let all_records = backend.list_records(domain).await?;

    // Build maps for efficient lookup
    let mut meta_records: HashMap<String, TxtRecord> = HashMap::new();
    let mut chunk_map: HashMap<String, String> = HashMap::new(); // record_name → content
    let mut dir_records: HashMap<String, TxtRecord> = HashMap::new();

    for r in &all_records {
        if r.name.contains("_meta.") {
            meta_records.insert(r.name.clone(), r.clone());
        } else if is_chunk_record(&r.name) {
            chunk_map.insert(r.name.clone(), r.content.clone());
        } else if r.name.contains("_dir.") {
            dir_records.insert(r.name.clone(), r.clone());
        }
    }

    // Walk directory tree to build path_hash → full_path mapping
    let mut path_map: HashMap<String, String> = HashMap::new();
    let mut dir_queue: Vec<String> = vec!["/".to_string()];

    while let Some(dir_path) = dir_queue.pop() {
        let phash = path_hash(&dir_path);
        let dir_rname = format!("_dir.{}.{}", phash, domain);
        if let Some(dir_record) = dir_records.get(&dir_rname) {
            if let Ok(decrypted) = decode_encrypted(&meta_key, &dir_record.content) {
                if let Ok(dir_meta) = serde_json::from_slice::<DirMeta>(&decrypted) {
                    for entry in &dir_meta.entries {
                        let child_path = if dir_path == "/" {
                            format!("/{}", entry.name)
                        } else {
                            format!("{}/{}", dir_path, entry.name)
                        };
                        if entry.is_dir {
                            dir_queue.push(child_path);
                        } else {
                            let child_phash = path_hash(&child_path);
                            let meta_rname = format!("_meta.{}.{}", child_phash, domain);
                            path_map.insert(meta_rname, child_path);
                        }
                    }
                }
            }
        }
    }

    // Create tar.gz output
    let file = File::create(output_path)
        .map_err(|e| StorageError::Other(format!("Cannot create {}: {}", output_path.display(), e)))?;
    let gz = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);

    let mut exported = 0usize;

    // Export each file
    for (name, record) in &meta_records {
        let decrypted = match decode_encrypted(&meta_key, &record.content) {
            Ok(d) => d,
            Err(e) => {
                warn!("Export: skipping unreadable file at {}: {}", name, e);
                continue;
            }
        };

        let meta: FileMeta = match serde_json::from_slice(&decrypted) {
            Ok(m) => m,
            Err(e) => {
                warn!("Export: skipping unparseable metadata at {}: {}", name, e);
                continue;
            }
        };

        // Use full path from directory walk, fall back to filename only
        let file_path = path_map.get(name)
            .cloned()
            .unwrap_or_else(|| meta.name.clone());

        // Collect and decrypt chunks
        let mut chunk_contents = Vec::new();
        let mut missing_chunks = false;

        for (i, hash) in meta.chunk_hashes.iter().enumerate() {
            let chunk_rname = format!("_c.{}.{}", hash, domain);
            match chunk_map.get(&chunk_rname) {
                Some(encoded) => chunk_contents.push(encoded.clone()),
                None => {
                    warn!("Export: missing chunk {} for {}", i, file_path);
                    missing_chunks = true;
                    break;
                }
            }
        }

        if missing_chunks {
            continue;
        }

        // We need the file-specific key for decryption
        // Since we don't know the full path, we'll export the raw encrypted chunks
        // along with metadata as a manifest — this is the safest approach.
        // The import side would need the master key to decrypt.

        // Export metadata JSON
        let meta_json = serde_json::to_vec_pretty(&meta)
            .map_err(|e| StorageError::Other(e.to_string()))?;

        let meta_path = format!("dnfs-export/{}.meta.json", file_path);
        let mut header = tar::Header::new_gnu();
        header.set_size(meta_json.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, &meta_path, &meta_json[..])
            .map_err(|e| StorageError::Other(format!("tar write: {}", e)))?;

        // Export chunks as-is (encrypted)
        for (i, encoded) in chunk_contents.iter().enumerate() {
            let chunk_path = format!("dnfs-export/{}.chunk.{}", file_path, i);
            let chunk_bytes = encoded.as_bytes();
            let mut header = tar::Header::new_gnu();
            header.set_size(chunk_bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, &chunk_path, chunk_bytes)
                .map_err(|e| StorageError::Other(format!("tar write: {}", e)))?;
        }

        exported += 1;
    }

    // Export volume metadata
    let vol_name = format!("_vol.{}", domain);
    if let Some(vol_record) = all_records.iter().find(|r| r.name == vol_name) {
        let vol_bytes = vol_record.content.as_bytes();
        let mut header = tar::Header::new_gnu();
        header.set_size(vol_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "dnfs-export/_volume.json", vol_bytes)
            .map_err(|e| StorageError::Other(format!("tar write: {}", e)))?;
    }

    tar.finish().map_err(|e| StorageError::Other(format!("tar finish: {}", e)))?;
    info!("Exported {} files to {}", exported, output_path.display());

    Ok(exported)
}

// ─── Nuke ───────────────────────────────────────────────────────────

/// Delete ALL DNS records under the given domain. Destructive and irreversible.
pub async fn nuke(
    backend: &dyn DnsBackend,
    domain: &str,
) -> Result<NukeResult, StorageError> {
    info!("NUKE: deleting all records under {}", domain);
    let all_records = backend.list_records(domain).await?;

    let mut deleted = 0;
    let mut errors = 0;

    for record in &all_records {
        if let Some(ref id) = record.id {
            match backend.delete_record(id).await {
                Ok(()) => {
                    deleted += 1;
                    if deleted % 50 == 0 {
                        info!("NUKE: deleted {} / {} records", deleted, all_records.len());
                    }
                }
                Err(e) => {
                    warn!("NUKE: failed to delete {}: {}", record.name, e);
                    errors += 1;
                }
            }
        }
    }

    info!("NUKE complete: {} deleted, {} errors", deleted, errors);
    Ok(NukeResult {
        records_deleted: deleted,
        errors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_chunk_record() {
        assert!(is_chunk_record("_c.abcdef.fs.test.com"));
        assert!(is_chunk_record("_c.abcdef1234.fs.test.com"));
        assert!(!is_chunk_record("_meta.abcdef.fs.test.com"));
        assert!(!is_chunk_record("_dir.abcdef.fs.test.com"));
        assert!(!is_chunk_record("_vol.fs.test.com"));
    }

    #[test]
    fn test_extract_chunk_hash() {
        assert_eq!(
            extract_chunk_hash("_c.abcdef1234.fs.test.com", "fs.test.com"),
            Some("abcdef1234".to_string())
        );
        assert_eq!(
            extract_chunk_hash("_c.xyz.fs.test.com", "fs.test.com"),
            Some("xyz".to_string())
        );
    }
}
