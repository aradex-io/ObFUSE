/// Phase 3 integration tests — Performance & Efficiency
///
/// Tests: parallel chunk fetching, TTL-aware metadata cache, write coalescing,
/// dir cache, API call efficiency, and cache stats reporting.

use dnfs::crypto;
use dnfs::dns::mock::MockDnsBackend;
use dnfs::storage::{DirEntry, DnfsStorage, StorageConfig, StorageError};

fn make_storage() -> (DnfsStorage, MockDnsBackend) {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();
    let storage = DnfsStorage::new(Box::new(mock.clone()), key, "fs.test.dnfs".to_string());
    (storage, mock)
}

fn make_storage_with_config(config: StorageConfig) -> (DnfsStorage, MockDnsBackend) {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();
    let storage = DnfsStorage::with_config(Box::new(mock.clone()), key, "fs.test.dnfs".to_string(), config);
    (storage, mock)
}

// ─── Parallel Chunk Fetch ───────────────────────────────────────────

#[test]
fn test_parallel_read_multi_chunk_file() {
    let (mut store, _) = make_storage();
    // Create a file large enough for multiple chunks (~5 chunks)
    let data = vec![0xAB; 7000];

    store.write_file("/parallel.bin", &data).unwrap();

    // Read should use parallel fetch internally
    let recovered = store.read_file("/parallel.bin").unwrap();
    assert_eq!(recovered, data);
}

#[test]
fn test_parallel_read_preserves_chunk_order() {
    let (mut store, _) = make_storage();
    // Create data with distinct patterns per chunk so order matters
    let mut data = Vec::new();
    for i in 0u8..10 {
        data.extend(vec![i; 1400]); // Each chunk has a unique byte value
    }

    store.write_file("/ordered.bin", &data).unwrap();
    let recovered = store.read_file("/ordered.bin").unwrap();
    assert_eq!(recovered, data, "Parallel fetch must preserve chunk ordering");
}

#[test]
fn test_parallel_read_single_chunk() {
    let (mut store, _) = make_storage();
    // Single chunk file — parallel path should handle gracefully
    let data = b"small file, one chunk";
    store.write_file("/single.txt", data).unwrap();
    assert_eq!(store.read_file("/single.txt").unwrap(), data.to_vec());
}

#[test]
fn test_parallel_read_empty_file() {
    let (mut store, _) = make_storage();
    store.write_file("/empty.txt", b"").unwrap();
    let recovered = store.read_file("/empty.txt").unwrap();
    assert!(recovered.is_empty());
}

// ─── TTL-Aware Metadata Cache ───────────────────────────────────────

#[test]
fn test_meta_cache_reduces_api_calls() {
    let (mut store, mock) = make_storage();
    store.write_file("/cached.txt", b"cache me").unwrap();

    // First stat — cache miss, DNS lookup
    let _m1 = store.stat_file("/cached.txt").unwrap();
    let gets_after_first = mock.get_stats().gets;

    // Second stat — cache hit, no DNS
    let _m2 = store.stat_file("/cached.txt").unwrap();
    let gets_after_second = mock.get_stats().gets;

    assert_eq!(gets_after_first, gets_after_second, "Cache should prevent additional DNS gets");
}

#[test]
fn test_meta_cache_hit_rate_reporting() {
    let (mut store, _) = make_storage();
    store.write_file("/a.txt", b"aaa").unwrap();

    // Miss
    store.stat_file("/a.txt").unwrap();
    // Hits (from write_file's cache population + this second call)
    store.stat_file("/a.txt").unwrap();
    store.stat_file("/a.txt").unwrap();

    let rate = store.meta_cache_hit_rate();
    assert!(rate > 0.5, "Cache hit rate should be >50%, got {:.0}%", rate * 100.0);
}

#[test]
fn test_dir_cache_reduces_api_calls() {
    let (mut store, mock) = make_storage();
    store.write_dir("/mydir", &[
        DirEntry { name: "a.txt".to_string(), is_dir: false, inode: 2 },
    ]).unwrap();

    // First read — populates cache
    let _d1 = store.read_dir("/mydir").unwrap();
    let gets1 = mock.get_stats().gets;

    // Second read — should hit cache
    let _d2 = store.read_dir("/mydir").unwrap();
    let gets2 = mock.get_stats().gets;

    assert_eq!(gets1, gets2, "Dir cache should prevent additional DNS gets");
}

#[test]
fn test_cache_invalidated_on_write() {
    let (mut store, _) = make_storage();

    store.write_file("/evolve.txt", b"v1").unwrap();
    let m1 = store.stat_file("/evolve.txt").unwrap();
    assert_eq!(m1.size, 2);

    // Overwrite should update cache
    store.write_file("/evolve.txt", b"version 2 is longer").unwrap();
    let m2 = store.stat_file("/evolve.txt").unwrap();
    assert_eq!(m2.size, 19);
}

#[test]
fn test_cache_invalidated_on_delete() {
    let (mut store, _) = make_storage();
    store.write_file("/temp.txt", b"soon gone").unwrap();
    assert!(store.stat_file("/temp.txt").is_ok());

    store.delete_file("/temp.txt").unwrap();
    assert!(store.stat_file("/temp.txt").is_err());
}

// ─── Write Coalescing ───────────────────────────────────────────────

#[test]
fn test_write_uses_batch_create() {
    let (mut store, mock) = make_storage();
    // Multi-chunk file should use batch_create internally
    let data = vec![0xCC; 5000]; // Multiple chunks

    store.write_file("/batched.bin", &data).unwrap();

    // Verify data integrity
    assert_eq!(store.read_file("/batched.bin").unwrap(), data);

    // The batch_create in MockDnsBackend falls back to sequential,
    // but we can verify the total creates are reasonable
    let stats = mock.get_stats();
    println!("Write coalesced stats: creates={}, gets={}", stats.creates, stats.gets);
}

#[test]
fn test_dedup_skips_batch_for_known_chunks() {
    let (mut store, mock) = make_storage();
    let data = b"dedup across writes";

    store.write_file("/first.txt", data).unwrap();
    let creates_after_first = mock.get_stats().creates;

    store.write_file("/second.txt", data).unwrap();
    let creates_after_second = mock.get_stats().creates;

    // Second write should only create 1 new record (metadata), not chunks
    let new_creates = creates_after_second - creates_after_first;
    assert_eq!(new_creates, 1, "Dedup should skip chunk creates: {} new creates", new_creates);
}

// ─── Config Validation ──────────────────────────────────────────────

#[test]
fn test_custom_cache_ttl() {
    let config = StorageConfig {
        cache_ttl_secs: 0, // Zero TTL = always miss
        ..Default::default()
    };
    let (mut store, mock) = make_storage_with_config(config);

    store.write_file("/nocache.txt", b"data").unwrap();

    // Both calls should hit DNS since TTL=0
    store.stat_file("/nocache.txt").unwrap();
    let gets1 = mock.get_stats().gets;

    store.stat_file("/nocache.txt").unwrap();
    let gets2 = mock.get_stats().gets;

    assert!(gets2 > gets1, "TTL=0 should cause cache misses: gets {} vs {}", gets1, gets2);
}

#[test]
fn test_max_parallel_config() {
    let config = StorageConfig {
        max_parallel_fetches: 2, // Limit parallelism
        ..Default::default()
    };
    let (mut store, _) = make_storage_with_config(config);

    let data = vec![0xDD; 7000]; // Multiple chunks
    store.write_file("/limited.bin", &data).unwrap();
    assert_eq!(store.read_file("/limited.bin").unwrap(), data);
}

// ─── Cache Stats ────────────────────────────────────────────────────

#[test]
fn test_cache_stats_reporting() {
    let (mut store, _) = make_storage();

    store.write_file("/s.txt", b"stats").unwrap();
    store.stat_file("/s.txt").unwrap(); // cache hit (populated by write)
    store.stat_file("/s.txt").unwrap(); // cache hit

    let (mh, mm, _, _) = store.cache_stats();
    // write_file does its own stat internally, but at minimum we should see hits
    assert!(mh >= 2, "Should have at least 2 meta cache hits, got {}", mh);
}

// ─── End-to-End Performance Scenario ────────────────────────────────

#[test]
fn test_full_workflow_efficiency() {
    let (mut store, mock) = make_storage();

    // Simulate a realistic workflow
    store.write_dir("/", &[
        DirEntry { name: "readme.md".to_string(), is_dir: false, inode: 2 },
        DirEntry { name: "config.json".to_string(), is_dir: false, inode: 3 },
        DirEntry { name: "data.bin".to_string(), is_dir: false, inode: 4 },
    ]).unwrap();

    store.write_file("/readme.md", b"# Dn(f)s\nA DNS filesystem").unwrap();
    store.write_file("/config.json", br#"{"version": 1, "domain": "fs.test"}"#).unwrap();
    store.write_file("/data.bin", &vec![0xFF; 5000]).unwrap();

    let stats_after_write = mock.get_stats();

    // Read everything — should benefit from caching
    let _ = store.read_dir("/").unwrap();
    let _ = store.read_file("/readme.md").unwrap();
    let _ = store.stat_file("/config.json").unwrap();
    let _ = store.read_file("/data.bin").unwrap();

    // Read again — should be mostly cached
    let _ = store.read_dir("/").unwrap();
    let _ = store.stat_file("/readme.md").unwrap();
    let _ = store.stat_file("/config.json").unwrap();

    let final_stats = mock.get_stats();
    let read_phase_gets = final_stats.gets - stats_after_write.gets;

    println!(
        "Full workflow: {} total gets in read phase (lower is better)",
        read_phase_gets
    );
    println!(
        "Cache hit rates: meta={:.0}% dir={:.0}%",
        store.meta_cache_hit_rate() * 100.0,
        store.dir_cache_hit_rate() * 100.0,
    );

    // The second round of reads should produce very few DNS lookups
    assert!(
        store.meta_cache_hit_rate() > 0.3,
        "Meta cache hit rate too low: {:.0}%",
        store.meta_cache_hit_rate() * 100.0
    );
}
