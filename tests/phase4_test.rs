/// Phase 4 integration tests — Chunk GC & Volume Management
///
/// Tests: garbage collection of orphaned chunks, fsck integrity verification,
/// nuke full deletion, and export archive generation.

use dnfs::crypto;
use dnfs::dns::mock::MockDnsBackend;
use dnfs::storage::{DirEntry, DnfsStorage, StorageConfig};
use dnfs::volume;

fn setup() -> (DnfsStorage, MockDnsBackend, [u8; 32]) {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();
    let storage = DnfsStorage::new(Box::new(mock.clone()), key, "fs.test.dnfs".to_string());
    (storage, mock, key)
}

// ─── Garbage Collection ─────────────────────────────────────────────

#[test]
fn test_gc_no_orphans() {
    let (mut store, mock, key) = setup();

    store.write_file("/keep.txt", b"alive").unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        volume::gc(&mock, "fs.test.dnfs", &key, false).await
    }).unwrap();

    assert_eq!(result.orphaned_deleted, 0);
    assert!(result.live_chunks > 0);
    assert_eq!(result.delete_errors, 0);

    // File still readable after GC
    assert_eq!(store.read_file("/keep.txt").unwrap(), b"alive");
}

#[test]
fn test_gc_deletes_orphaned_chunks() {
    let (mut store, mock, key) = setup();

    // Write and then delete a file — leaves orphaned chunks
    store.write_file("/ephemeral.txt", b"soon to be garbage").unwrap();
    let records_before_delete = mock.record_count();

    store.delete_file("/ephemeral.txt").unwrap();
    let records_after_delete = mock.record_count();

    // delete_file only removes metadata, not chunks
    assert!(
        records_after_delete < records_before_delete,
        "Delete should remove metadata: {} -> {}",
        records_before_delete, records_after_delete
    );

    // Run GC — should clean up orphaned chunks
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        volume::gc(&mock, "fs.test.dnfs", &key, false).await
    }).unwrap();

    assert!(result.orphaned_deleted > 0, "GC should find orphaned chunks");
    assert_eq!(result.live_chunks, 0, "No live chunks after file deleted");
    assert_eq!(result.delete_errors, 0);
}

#[test]
fn test_gc_preserves_shared_chunks() {
    let (mut store, mock, key) = setup();
    let shared_data = b"shared across files";

    // Two files with identical content (deduped chunks)
    store.write_file("/a.txt", shared_data).unwrap();
    store.write_file("/b.txt", shared_data).unwrap();

    // Delete one
    store.delete_file("/a.txt").unwrap();

    // GC should NOT delete the shared chunks (still referenced by /b.txt)
    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        volume::gc(&mock, "fs.test.dnfs", &key, false).await
    }).unwrap();

    assert_eq!(result.orphaned_deleted, 0, "Shared chunks must not be deleted");
    assert!(result.live_chunks > 0);

    // /b.txt should still be readable
    assert_eq!(store.read_file("/b.txt").unwrap(), shared_data.to_vec());
}

#[test]
fn test_gc_dry_run() {
    let (mut store, mock, key) = setup();

    store.write_file("/temp.txt", b"will delete").unwrap();
    store.delete_file("/temp.txt").unwrap();

    let records_before_gc = mock.record_count();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        volume::gc(&mock, "fs.test.dnfs", &key, true).await // dry_run = true
    }).unwrap();

    assert!(result.orphaned_deleted > 0, "Dry run should detect orphans");
    assert_eq!(mock.record_count(), records_before_gc, "Dry run must not actually delete");
}

// ─── Filesystem Check ───────────────────────────────────────────────

#[test]
fn test_fsck_clean_volume() {
    let (mut store, mock, key) = setup();

    store.write_file("/healthy.txt", b"all good").unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        volume::fsck(&mock, "fs.test.dnfs", &key).await
    }).unwrap();

    assert!(result.is_clean(), "Clean volume should have no errors: {:?}", result.issues);
    assert!(result.files_checked > 0);
    assert!(result.chunks_verified > 0);
}

#[test]
fn test_fsck_detects_missing_chunk() {
    let (mut store, mock, key) = setup();

    store.write_file("/broken.txt", b"will lose a chunk").unwrap();

    // Manually delete a chunk record to simulate corruption
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let all = mock.list_records("fs.test.dnfs").await.unwrap();
        for r in &all {
            if r.name.contains("_c0.") {
                if let Some(ref id) = r.id {
                    mock.delete_record(id).await.unwrap();
                    break;
                }
            }
        }
    });

    let result = rt.block_on(async {
        volume::fsck(&mock, "fs.test.dnfs", &key).await
    }).unwrap();

    assert!(!result.is_clean(), "Should detect missing chunk");
    let errors: Vec<_> = result.issues.iter()
        .filter(|i| i.severity == volume::FsckSeverity::Error)
        .collect();
    assert!(!errors.is_empty(), "Should have error-severity issues");
    assert!(
        errors.iter().any(|i| i.detail.contains("Missing chunk")),
        "Should specifically report missing chunk: {:?}",
        errors
    );
}

#[test]
fn test_fsck_detects_corrupt_metadata() {
    let mock = MockDnsBackend::new();
    let key = crypto::generate_key();

    // Inject a corrupt metadata record
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        mock.create_record("_meta.baddata.fs.test.dnfs", "NOT_ENCRYPTED", 60).await.unwrap();
    });

    let result = rt.block_on(async {
        volume::fsck(&mock, "fs.test.dnfs", &key).await
    }).unwrap();

    assert!(!result.is_clean());
    assert!(result.issues.iter().any(|i| i.detail.contains("decrypt")));
}

// ─── Nuke ───────────────────────────────────────────────────────────

#[test]
fn test_nuke_deletes_everything() {
    let (mut store, mock, _key) = setup();

    store.write_file("/a.txt", b"aaa").unwrap();
    store.write_file("/b.txt", b"bbb").unwrap();
    store.write_dir("/", &[
        DirEntry { name: "a.txt".to_string(), is_dir: false, inode: 2 },
        DirEntry { name: "b.txt".to_string(), is_dir: false, inode: 3 },
    ]).unwrap();

    let before = mock.record_count();
    assert!(before > 0, "Should have records");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let result = rt.block_on(async {
        volume::nuke(&mock, "fs.test.dnfs").await
    }).unwrap();

    assert_eq!(result.records_deleted, before);
    assert_eq!(result.errors, 0);
    assert_eq!(mock.record_count(), 0, "All records should be deleted");
}

// ─── Export ─────────────────────────────────────────────────────────

#[test]
fn test_export_creates_archive() {
    let (mut store, mock, key) = setup();

    store.write_file("/doc.txt", b"export me").unwrap();
    store.write_file("/data.bin", &vec![0xAA; 500]).unwrap();

    let tmp_dir = std::env::temp_dir().join(format!("dnfs-test-{}", std::process::id()));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let output = tmp_dir.join("export.tar.gz");

    let rt = tokio::runtime::Runtime::new().unwrap();
    let count = rt.block_on(async {
        volume::export(&mock, "fs.test.dnfs", &key, &output).await
    }).unwrap();

    assert_eq!(count, 2, "Should export 2 files");
    assert!(output.exists(), "Archive should exist");
    assert!(output.metadata().unwrap().len() > 0, "Archive should be non-empty");

    // Verify it's a valid gzip file
    let file = std::fs::File::open(&output).unwrap();
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    let entries: Vec<_> = archive.entries().unwrap().collect();
    assert!(entries.len() >= 4, "Should have meta + chunks for each file: got {}", entries.len());

    // Cleanup
    std::fs::remove_dir_all(&tmp_dir).unwrap();
}

// ─── GC + fsck Combined Workflow ────────────────────────────────────

#[test]
fn test_gc_then_fsck_clean() {
    let (mut store, mock, key) = setup();

    store.write_file("/kept.txt", b"keeper").unwrap();
    store.write_file("/deleted.txt", b"going away").unwrap();
    store.delete_file("/deleted.txt").unwrap();

    let rt = tokio::runtime::Runtime::new().unwrap();

    // GC
    let gc_result = rt.block_on(async {
        volume::gc(&mock, "fs.test.dnfs", &key, false).await
    }).unwrap();
    assert!(gc_result.orphaned_deleted > 0);

    // fsck after GC — should be clean
    let fsck_result = rt.block_on(async {
        volume::fsck(&mock, "fs.test.dnfs", &key).await
    }).unwrap();
    assert!(fsck_result.is_clean(), "Volume should be clean after GC: {:?}", fsck_result.issues);

    // Data integrity preserved
    assert_eq!(store.read_file("/kept.txt").unwrap(), b"keeper");
}
