/// Integration tests for Dn(f)s
///
/// These tests exercise the full pipeline:
///   write_file → chunkify → encrypt → DNS create_record
///   DNS get_records → decrypt → dechunkify → read_file
///
/// All tests use MockDnsBackend — zero network dependencies.

use dnfs::crypto;
use dnfs::dns::mock::MockDnsBackend;
use dnfs::storage::{DirEntry, DnfsStorage};

fn make_storage() -> (DnfsStorage, MockDnsBackend) {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();
    let storage = DnfsStorage::new(
        Box::new(mock.clone()),
        key,
        "fs.test.dnfs".to_string(),
    );
    (storage, mock)
}

// ─── File Roundtrip Tests ───────────────────────────────────────────

#[test]
fn test_write_read_roundtrip_small() {
    let (mut store, mock) = make_storage();
    let data = b"hello from DNS";

    let meta = store.write_file("/hello.txt", data).unwrap();
    assert_eq!(meta.size, data.len() as u64);
    assert_eq!(meta.name, "hello.txt");
    assert!(meta.chunk_count >= 1);

    let recovered = store.read_file("/hello.txt").unwrap();
    assert_eq!(recovered, data.to_vec());

    // Verify DNS records were actually created
    let record_count = mock.record_count();
    assert!(record_count >= 2, "Expected at least meta + 1 chunk, got {}", record_count);
}

#[test]
fn test_write_read_roundtrip_medium() {
    let (mut store, _) = make_storage();
    // ~5KB of structured data
    let data: Vec<u8> = (0..5000).map(|i| (i % 256) as u8).collect();

    store.write_file("/medium.bin", &data).unwrap();
    let recovered = store.read_file("/medium.bin").unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn test_write_read_roundtrip_multi_chunk() {
    let (mut store, _) = make_storage();
    // Force multiple chunks (each chunk ≈ 1400 bytes pre-encryption)
    let data = vec![0xAB; 10000];

    let meta = store.write_file("/big.bin", &data).unwrap();
    assert!(meta.chunk_count > 1, "Expected multiple chunks, got {}", meta.chunk_count);

    let recovered = store.read_file("/big.bin").unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn test_empty_file() {
    let (mut store, _) = make_storage();

    store.write_file("/empty.txt", b"").unwrap();
    let recovered = store.read_file("/empty.txt").unwrap();
    assert!(recovered.is_empty());
}

// ─── Deduplication Tests ────────────────────────────────────────────

#[test]
fn test_dedup_identical_files() {
    let (mut store, mock) = make_storage();
    let data = b"this content is shared between two files";

    // Write first file
    store.write_file("/file_a.txt", data).unwrap();
    let records_after_a = mock.record_count();

    // Write second file with SAME content
    store.write_file("/file_b.txt", data).unwrap();
    let records_after_b = mock.record_count();

    // The chunk records should be deduped — only new metadata record added
    // file_a: 1 meta + N chunks
    // file_b: 1 meta + 0 new chunks (dedup hit)
    let new_records = records_after_b - records_after_a;
    assert_eq!(new_records, 1, "Expected only 1 new record (metadata), got {}", new_records);

    // Both files should still read correctly
    let recovered_a = store.read_file("/file_a.txt").unwrap();
    let recovered_b = store.read_file("/file_b.txt").unwrap();
    assert_eq!(recovered_a, data.to_vec());
    assert_eq!(recovered_b, data.to_vec());
}

#[test]
fn test_dedup_partial_overlap() {
    let (mut store, mock) = make_storage();
    let block_size = 1400; // CHUNK_SPLIT_SIZE
    let shared = vec![0xAA; block_size];
    let unique_a = vec![0xBB; block_size];
    let unique_b = vec![0xCC; block_size];

    let mut file_a = shared.clone();
    file_a.extend_from_slice(&unique_a);

    let mut file_b = shared.clone();
    file_b.extend_from_slice(&unique_b);

    store.write_file("/overlap_a.bin", &file_a).unwrap();
    let count_a = mock.record_count();

    store.write_file("/overlap_b.bin", &file_b).unwrap();
    let count_b = mock.record_count();

    // file_b should reuse the shared chunk, only create 1 new chunk + 1 meta
    let new_records = count_b - count_a;
    assert_eq!(
        new_records, 2,
        "Expected 2 new records (1 meta + 1 unique chunk), got {}",
        new_records
    );

    // Both files read correctly
    assert_eq!(store.read_file("/overlap_a.bin").unwrap(), file_a);
    assert_eq!(store.read_file("/overlap_b.bin").unwrap(), file_b);
}

// ─── Directory Tests ────────────────────────────────────────────────

#[test]
fn test_directory_operations() {
    let (mut store, _) = make_storage();

    // Create directory entries
    let entries = vec![
        DirEntry { name: "readme.md".to_string(), is_dir: false, inode: 2 },
        DirEntry { name: "src".to_string(), is_dir: true, inode: 3 },
    ];

    store.write_dir("/", &entries).unwrap();
    let dir = store.read_dir("/").unwrap();

    assert_eq!(dir.entries.len(), 2);
    assert_eq!(dir.entries[0].name, "readme.md");
    assert!(!dir.entries[0].is_dir);
    assert_eq!(dir.entries[1].name, "src");
    assert!(dir.entries[1].is_dir);
}

#[test]
fn test_nested_directories() {
    let (mut store, _) = make_storage();

    store.write_dir("/src", &[
        DirEntry { name: "main.rs".to_string(), is_dir: false, inode: 10 },
        DirEntry { name: "lib".to_string(), is_dir: true, inode: 11 },
    ]).unwrap();

    store.write_dir("/src/lib", &[
        DirEntry { name: "mod.rs".to_string(), is_dir: false, inode: 20 },
    ]).unwrap();

    let src = store.read_dir("/src").unwrap();
    assert_eq!(src.entries.len(), 2);

    let lib = store.read_dir("/src/lib").unwrap();
    assert_eq!(lib.entries.len(), 1);
    assert_eq!(lib.entries[0].name, "mod.rs");
}

// ─── Delete Tests ───────────────────────────────────────────────────

#[test]
fn test_delete_file() {
    let (mut store, _) = make_storage();

    store.write_file("/doomed.txt", b"goodbye cruel world").unwrap();
    assert!(store.read_file("/doomed.txt").is_ok());

    store.delete_file("/doomed.txt").unwrap();
    assert!(store.read_file("/doomed.txt").is_err());
}

#[test]
fn test_delete_preserves_deduped_chunks() {
    let (mut store, _) = make_storage();
    let data = b"shared content that must survive";

    store.write_file("/keep.txt", data).unwrap();
    store.write_file("/delete_me.txt", data).unwrap();

    store.delete_file("/delete_me.txt").unwrap();

    // The kept file should still be readable (chunks not deleted)
    let recovered = store.read_file("/keep.txt").unwrap();
    assert_eq!(recovered, data.to_vec());
}

// ─── Overwrite Tests ────────────────────────────────────────────────

#[test]
fn test_overwrite_file() {
    let (mut store, _) = make_storage();

    store.write_file("/mutable.txt", b"version 1").unwrap();
    assert_eq!(store.read_file("/mutable.txt").unwrap(), b"version 1");

    store.write_file("/mutable.txt", b"version 2 is longer than v1").unwrap();
    assert_eq!(store.read_file("/mutable.txt").unwrap(), b"version 2 is longer than v1");
}

// ─── Stat Tests ─────────────────────────────────────────────────────

#[test]
fn test_stat_file() {
    let (mut store, _) = make_storage();
    let data = b"stat me";

    store.write_file("/info.txt", data).unwrap();
    let meta = store.stat_file("/info.txt").unwrap();

    assert_eq!(meta.name, "info.txt");
    assert_eq!(meta.size, data.len() as u64);
    assert_eq!(meta.mode, 0o644);
    assert!(meta.created > 0);
    assert!(meta.modified > 0);
    assert!(!meta.content_hash.is_empty());
}

#[test]
fn test_stat_nonexistent() {
    let (mut store, _) = make_storage();
    assert!(store.stat_file("/ghost.txt").is_err());
}

// ─── Inode Management Tests ─────────────────────────────────────────

#[test]
fn test_inode_allocation() {
    let (mut store, _) = make_storage();

    let ino1 = store.register_path("/a.txt");
    let ino2 = store.register_path("/b.txt");
    let ino3 = store.register_path("/a.txt"); // re-register

    assert_ne!(ino1, ino2);
    assert_eq!(ino1, ino3, "Re-registering same path should return same inode");

    assert_eq!(store.get_path(ino1), Some("/a.txt"));
    assert_eq!(store.get_path(ino2), Some("/b.txt"));
    assert_eq!(store.get_inode("/a.txt"), Some(ino1));
}

// ─── API Call Efficiency Tests ──────────────────────────────────────

#[test]
fn test_api_call_count() {
    let (mut store, mock) = make_storage();
    let data = b"small file";

    store.write_file("/efficient.txt", data).unwrap();

    let stats = mock.get_stats();
    // For a single-chunk file: 1 get (check existing meta) + 1 delete (old meta) or just
    // 1 create (chunk) + 1 get (existing meta check) + 1 create (meta)
    // Exact count depends on implementation, but should be reasonable
    println!("Write stats: creates={}, gets={}, deletes={}", stats.creates, stats.gets, stats.deletes);
    assert!(stats.creates <= 3, "Too many create calls: {}", stats.creates);

    store.read_file("/efficient.txt").unwrap();
    let stats = mock.get_stats();
    println!("After read: gets={}", stats.gets);
}

// ─── Binary Data Tests ──────────────────────────────────────────────

#[test]
fn test_binary_data_roundtrip() {
    let (mut store, _) = make_storage();

    // All possible byte values
    let data: Vec<u8> = (0..=255).collect();
    store.write_file("/binary.bin", &data).unwrap();
    let recovered = store.read_file("/binary.bin").unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn test_null_bytes() {
    let (mut store, _) = make_storage();

    let data = vec![0u8; 1000];
    store.write_file("/nulls.bin", &data).unwrap();
    let recovered = store.read_file("/nulls.bin").unwrap();
    assert_eq!(recovered, data);
}
