/// Phase 2 integration tests — Hardening & Robustness
///
/// Tests: file size enforcement, corrupt record recovery, rename operations,
/// mount state rebuild, metadata caching, and overwrite behavior.

use dnfs::crypto;
use dnfs::dns::DnsBackend;
use dnfs::dns::mock::MockDnsBackend;
use dnfs::storage::{DirEntry, DnfsStorage, StorageConfig, StorageError};

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

fn make_storage_with_config(config: StorageConfig) -> (DnfsStorage, MockDnsBackend, [u8; 32]) {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();
    let storage = DnfsStorage::with_config(
        Box::new(mock.clone()),
        key,
        "fs.test.dnfs".to_string(),
        config,
    );
    (storage, mock, key)
}

// ─── File Size Enforcement ──────────────────────────────────────────

#[test]
fn test_file_size_limit_default() {
    let (mut store, _) = make_storage();

    // Default limit is 64KB
    let too_big = vec![0xAA; 65 * 1024];
    let result = store.write_file("/toobig.bin", &too_big);

    assert!(matches!(result, Err(StorageError::FileTooLarge { .. })));
}

#[test]
fn test_file_size_limit_custom() {
    let config = StorageConfig {
        max_file_size: 1024, // 1KB limit
        ..Default::default()
    };
    let (mut store, _, _) = make_storage_with_config(config);

    // Under limit — should work
    let small = vec![0xBB; 512];
    assert!(store.write_file("/small.bin", &small).is_ok());

    // Over limit — should fail
    let big = vec![0xCC; 2048];
    assert!(matches!(
        store.write_file("/big.bin", &big),
        Err(StorageError::FileTooLarge { size: 2048, max: 1024 })
    ));
}

#[test]
fn test_file_at_exact_limit() {
    let config = StorageConfig {
        max_file_size: 1000,
        ..Default::default()
    };
    let (mut store, _, _) = make_storage_with_config(config);

    // Exactly at limit
    let exact = vec![0xDD; 1000];
    assert!(store.write_file("/exact.bin", &exact).is_ok());

    // One byte over
    let over = vec![0xEE; 1001];
    assert!(matches!(
        store.write_file("/over.bin", &over),
        Err(StorageError::FileTooLarge { .. })
    ));
}

// ─── Corrupt Record Recovery ────────────────────────────────────────

#[test]
fn test_corrupt_base64_in_metadata() {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();

    // Manually inject a corrupt metadata record
    let rt = tokio::runtime::Runtime::new().unwrap();
    let phash = dnfs::crypto::content_hash(b"/corrupt.txt");
    let record_name = format!("_meta.{}.fs.test.dnfs", &phash[..32]);
    rt.block_on(async {
        mock.create_record(&record_name, "NOT_VALID_BASE64!!!", 60).await.unwrap();
    });

    let mut store = DnfsStorage::with_config(
        Box::new(mock),
        key,
        "fs.test.dnfs".to_string(),
        StorageConfig { recover_corrupt: true, ..Default::default() },
    );

    let result = store.stat_file("/corrupt.txt");
    assert!(matches!(result, Err(StorageError::CorruptRecord { .. })));
}

#[test]
fn test_corrupt_ciphertext_in_metadata() {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();

    // Valid base64 but invalid ciphertext
    use base64::Engine;
    let fake_encrypted = base64::engine::general_purpose::STANDARD.encode(b"this is not encrypted data");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let phash = dnfs::crypto::content_hash(b"/badcrypt.txt");
    let record_name = format!("_meta.{}.fs.test.dnfs", &phash[..32]);
    rt.block_on(async {
        mock.create_record(&record_name, &fake_encrypted, 60).await.unwrap();
    });

    let mut store = DnfsStorage::with_config(
        Box::new(mock),
        key,
        "fs.test.dnfs".to_string(),
        StorageConfig { recover_corrupt: true, ..Default::default() },
    );

    let result = store.stat_file("/badcrypt.txt");
    assert!(matches!(result, Err(StorageError::CorruptRecord { .. })));
}

// ─── Rename Operations ─────────────────────────────────────────────

#[test]
fn test_rename_file() {
    let (mut store, _) = make_storage();
    let data = b"rename me";

    store.write_file("/old.txt", data).unwrap();
    store.rename_file("/old.txt", "/new.txt").unwrap();

    // Old path should be gone
    assert!(store.read_file("/old.txt").is_err());

    // New path should have the data
    assert_eq!(store.read_file("/new.txt").unwrap(), data.to_vec());
}

#[test]
fn test_rename_preserves_dedup() {
    let (mut store, mock) = make_storage();
    let data = b"dedup content for rename test";

    store.write_file("/original.txt", data).unwrap();
    let count_before = mock.record_count();

    store.rename_file("/original.txt", "/renamed.txt").unwrap();

    // Rename should reuse chunks (dedup), so minimal new records
    // New meta for /renamed.txt + delete old meta = net ~0 new chunk records
    let count_after = mock.record_count();
    // The chunk records should NOT increase
    assert!(
        count_after <= count_before + 1,
        "Rename shouldn't create new chunks: before={}, after={}",
        count_before, count_after
    );
}

// ─── Mount State Rebuild ────────────────────────────────────────────

#[test]
fn test_rebuild_recovers_directory_tree() {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();

    // Phase 1: Write some files with one storage instance
    {
        let mut store = DnfsStorage::new(
            Box::new(mock.clone()),
            key,
            "fs.test.dnfs".to_string(),
        );

        store.write_file("/readme.md", b"# Hello").unwrap();
        store.write_file("/data.bin", b"\x00\x01\x02").unwrap();

        store.write_dir("/", &[
            DirEntry { name: "readme.md".to_string(), is_dir: false, inode: 2 },
            DirEntry { name: "data.bin".to_string(), is_dir: false, inode: 3 },
            DirEntry { name: "src".to_string(), is_dir: true, inode: 4 },
        ]).unwrap();

        store.write_dir("/src", &[
            DirEntry { name: "main.rs".to_string(), is_dir: false, inode: 5 },
        ]).unwrap();
        store.write_file("/src/main.rs", b"fn main() {}").unwrap();
    }

    // Phase 2: Create a NEW storage instance with rebuild_on_mount
    let mut store2 = DnfsStorage::with_config(
        Box::new(mock.clone()),
        key,
        "fs.test.dnfs".to_string(),
        StorageConfig { rebuild_on_mount: true, ..Default::default() },
    );

    // The rebuilt store should be able to read everything
    assert_eq!(store2.read_file("/readme.md").unwrap(), b"# Hello");
    assert_eq!(store2.read_file("/data.bin").unwrap(), b"\x00\x01\x02");
    assert_eq!(store2.read_file("/src/main.rs").unwrap(), b"fn main() {}");

    // Inodes should be populated
    assert!(store2.get_inode("/readme.md").is_some());
    assert!(store2.get_inode("/src/main.rs").is_some());

    // Dedup state should be recovered
    assert!(store2.dedup_chunk_count() > 0);
}

#[test]
fn test_rebuild_survives_corrupt_entries() {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();

    // Write a valid file
    {
        let mut store = DnfsStorage::new(
            Box::new(mock.clone()),
            key,
            "fs.test.dnfs".to_string(),
        );
        store.write_file("/good.txt", b"valid file").unwrap();
        store.write_dir("/", &[
            DirEntry { name: "good.txt".to_string(), is_dir: false, inode: 2 },
        ]).unwrap();
    }

    // Inject a corrupt record
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        mock.create_record("_meta.deadbeef.fs.test.dnfs", "GARBAGE", 60).await.unwrap();
    });

    // Rebuild should succeed despite corrupt record
    let mut store2 = DnfsStorage::with_config(
        Box::new(mock),
        key,
        "fs.test.dnfs".to_string(),
        StorageConfig { rebuild_on_mount: true, recover_corrupt: true, ..Default::default() },
    );

    // Valid file should still be accessible
    assert_eq!(store2.read_file("/good.txt").unwrap(), b"valid file");
}

// ─── Metadata Cache Tests ───────────────────────────────────────────

#[test]
fn test_metadata_cache_hit() {
    let (mut store, mock) = make_storage();

    store.write_file("/cached.txt", b"cache me").unwrap();

    // First stat: DNS lookup
    let _meta1 = store.stat_file("/cached.txt").unwrap();
    let gets_after_first = mock.get_stats().gets;

    // Second stat: should hit cache, no additional DNS gets
    let _meta2 = store.stat_file("/cached.txt").unwrap();
    let gets_after_second = mock.get_stats().gets;

    assert_eq!(
        gets_after_first, gets_after_second,
        "Second stat should hit cache (gets: {} vs {})",
        gets_after_first, gets_after_second
    );
}

#[test]
fn test_metadata_cache_invalidated_on_delete() {
    let (mut store, _) = make_storage();

    store.write_file("/ephemeral.txt", b"soon gone").unwrap();
    assert!(store.stat_file("/ephemeral.txt").is_ok());

    store.delete_file("/ephemeral.txt").unwrap();

    // Cache should be invalidated
    assert!(store.stat_file("/ephemeral.txt").is_err());
}

// ─── Overwrite Behavior ────────────────────────────────────────────

#[test]
fn test_overwrite_updates_metadata() {
    let (mut store, _) = make_storage();

    let meta1 = store.write_file("/evolve.txt", b"v1").unwrap();
    let meta2 = store.write_file("/evolve.txt", b"version two is longer").unwrap();

    assert_ne!(meta1.size, meta2.size);
    assert_ne!(meta1.content_hash, meta2.content_hash);
    assert_eq!(store.read_file("/evolve.txt").unwrap(), b"version two is longer");
}

// ─── StorageConfig Accessors ────────────────────────────────────────

#[test]
fn test_config_accessible() {
    let config = StorageConfig {
        max_file_size: 32768,
        recover_corrupt: false,
        rebuild_on_mount: false,
        ..StorageConfig::default()
    };
    let (store, _, _) = make_storage_with_config(config);

    assert_eq!(store.config().max_file_size, 32768);
    assert!(!store.config().recover_corrupt);
}
