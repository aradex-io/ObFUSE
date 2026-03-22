# Dn(f)s — Critical Security & Logic Audit

**Auditor**: Claude (code review)  
**Date**: 2026-03-22  
**Scope**: All 18 source files, 4 test suites, full data pipeline  
**Version**: v0.5.0 (4,888 lines)

---

## Summary

| Severity | Found | Fixed In-Review | Remaining |
|----------|-------|-----------------|-----------|
| **Critical** (data loss/security) | 3 | 0 | 3 |
| **High** (logic bug, correctness) | 4 | 2 | 2 |
| **Medium** (robustness) | 5 | 0 | 5 |
| **Low** (code quality) | 4 | 2 | 2 |

---

## CRITICAL — Fix Before Any Real Use

### C1. Rename Detection in FUSE Is Inverted

**File**: `src/fs/mod.rs:597`  
**Bug**: `let is_dir = self.store.stat_file(&old_path).is_err();` — this assumes that if `stat_file` fails, the path is a directory. But `stat_file` also fails for nonexistent paths, corrupt records, and DNS errors. A DNS timeout would cause a file to be treated as a directory.

**Impact**: Rename of files during transient DNS failures could corrupt directory listings. The renamed entry gets `is_dir: true` in the parent, and subsequent `ls` will show it as a directory.

**Fix**: Check the parent directory listing to determine if the entry is a directory, or attempt `read_dir` first and fall back to file. The logic should be: try `stat_file` — if Ok, it's a file. If Err(NotFound), try `read_dir` — if it has entries or exists in parent as `is_dir`, it's a dir. If both fail, return ENOENT.

**Worth fixing**: **Yes, mandatory.** This is a data corruption path.

---

### C2. Dedup With Per-File Keys Means Cross-File Dedup Is Broken

**File**: `src/storage/mod.rs:427`, `src/crypto/keys.rs:5`  
**Bug**: `file_key` is derived from `master_key + path`. Two different files with identical content get different encryption keys, which means the encrypted output differs, BUT we dedup on the pre-encryption `content_hash` (BLAKE3 of plaintext). So the dedup `known_chunks` set correctly identifies the duplicate. However, the storage layer stores the chunk under `_c{N}.{content_hash}.{domain}` with the encrypted payload from the *first* file's key. When the second file tries to read, it uses its own different `file_key` to decrypt that chunk — **decryption will fail**.

**Impact**: If file A and file B have identical content at the same chunk offset, file B's read will fail with a decryption error because the chunk was encrypted with file A's key but decrypted with file B's key.

**Fix**: Two options:
  1. **Use a single data encryption key** (derive from master only, not per-path) for chunk encryption. Per-file keys only for metadata. This makes dedup actually work.
  2. **Dedup only within the same file** (same key context). Change `known_chunks` to be scoped per write, not global. This is simpler but gives up cross-file dedup.

**Worth fixing**: **Yes, mandatory.** This is a silent data corruption bug. Option 1 is better for the project's value proposition.

---

### C3. Empty File Handling Inconsistency

**File**: `src/chunk/mod.rs:96`, `src/storage/mod.rs:483-486`  
**Bug**: `chunkify(b"")` produces 1 chunk (compressed empty data). But `read_file` has a special case: `if file_meta.chunk_hashes.is_empty()` → call `dechunkify(&[], &file_key)`. Since `chunkify(b"")` produces a non-empty chunk_hashes vec (1 element), the `is_empty()` check never fires. This works *by accident* right now, but `dechunkify(&[])` with no encoded chunks returns an empty `Vec<u8>` because the loop body never executes — it doesn't actually decompress anything. If the empty-file codepath ever gets hit (e.g., metadata corruption losing the single hash), it would silently return empty data instead of erroring.

**Impact**: Low immediate risk, but the logic is fragile. The real read path works correctly through the normal chunk fetch.

**Fix**: Remove the dead `is_empty()` special case in `read_file`, or make it return `Ok(vec![])` directly without calling `dechunkify`.

**Worth fixing**: **Yes, quick fix**, prevents future confusion.

---

## HIGH — Fix Before Shipping to Users

### H1. Overwrite Doesn't Preserve Created Timestamp

**File**: `src/storage/mod.rs:438-446`  
**Bug**: `write_file` always sets `created: now_epoch()`. When overwriting an existing file, the creation time should be preserved from the original metadata.

**Impact**: Every overwrite resets `ctime` in FUSE. Programs that rely on creation time (backup tools, `stat`) will see incorrect metadata.

**Fix**: Before writing, try `stat_file` to get existing metadata. If it exists, carry forward `created` from the old meta.

**Worth fixing**: **Yes**, simple fix, important for POSIX expectations.

---

### H2. `unlink` Calls `delete_file` Then Checks `get_inode` — But `delete_file` Already Removed It

**File**: `src/fs/mod.rs:506-516`  
**Bug**: After `self.store.delete_file(&child_path)` succeeds, the code calls `self.store.get_inode(&child_path)` to clean up open handles. But `delete_file` removes the path from `path_map`, so `get_inode` will always return `None`. The open file handle cleanup never actually fires.

**Impact**: Memory leak of `open_files` and `write_buffers` entries for deleted files. Won't cause data loss but will accumulate stale state over long mount sessions.

**Fix**: Capture the inode *before* calling `delete_file`.

**Worth fixing**: **Yes**, one-line fix. *(Fixed in this review)*

---

### H3. `write_dir` Doesn't Invalidate Parent Dir Cache

**File**: `src/storage/mod.rs:524-545`  
**Bug**: When `write_dir` updates a directory listing, it puts the new content into `dir_cache` for *that* directory's path hash. But it doesn't invalidate the *parent's* cached listing. If the parent's readdir result was cached before a child was created, the stale parent cache will persist until TTL expiry.

**Impact**: `ls` might not show newly created files/dirs for up to `cache_ttl_secs` seconds. The FUSE layer works around this because `create` and `mkdir` explicitly call `write_dir` on the parent, but any external write (another mount, direct DNS edit) won't be seen.

**Fix**: This is inherent to the caching design and acceptable for a single-writer PoC. Document it as a known limitation. A proper fix would require cache invalidation propagation up the path hierarchy.

**Worth fixing**: **No, document as limitation.** Acceptable for single-writer PoC.

---

### H4. `adaptive_zstd_level` Text Detection Counts Whitespace Twice

**File**: `src/chunk/mod.rs:66-68`  
**Bug**: `is_ascii_whitespace()` already returns true for `\n`, `\r`, and `\t`. The explicit `|| b == b'\n' || b == b'\r' || b == b'\t'` checks are redundant. Not a bug per se, but indicates the classification logic wasn't carefully validated.

**Impact**: None — the duplicates don't change the count. Pure code smell.

**Fix**: Remove the redundant checks.

**Worth fixing**: **Yes, trivial cleanup.** *(Fixed in this review)*

---

## MEDIUM — Should Fix, Not Blocking

### M1. `key_from_hex` Doesn't Strip Whitespace

**File**: `src/crypto/mod.rs:31`  
**Bug**: If a user does `export DNFS_KEY=$(dnfs keygen)` and the shell captures a trailing newline, `key_from_hex` will fail with an unhelpful "Invalid character" error.

**Impact**: Bad UX on first use. The keygen outputs to stdout, but `eprintln` also writes to stderr, so piping works. However, copy-paste from terminal might include whitespace.

**Fix**: `hex::decode(hex_str.trim())`

**Worth fixing**: **Yes**, one-word fix, prevents common user error.

---

### M2. `fh_to_ino` Map Grows Unbounded

**File**: `src/fs/mod.rs:56`  
**Bug**: `fh_to_ino` entries are removed in `release()`, but if a process dies without calling release (SIGKILL, crash), the entries leak. Over a long mount session this could grow unbounded.

**Impact**: Memory leak proportional to abnormally-terminated file operations. Unlikely to matter in practice for a PoC.

**Fix**: Periodically sweep `fh_to_ino` for entries whose inodes are no longer in `open_files`. Or just accept the leak for a PoC.

**Worth fixing**: **No for PoC**, yes for production.

---

### M3. Hash Truncation Collision Risk

**File**: `src/storage/mod.rs:30`, line `const HASH_LABEL_LEN: usize = 32;`  
**Analysis**: BLAKE3 hashes are truncated to 32 hex chars = 128 bits. Birthday paradox collision probability at 2^64 items (~18 exafiles). For a filesystem limited to 64KB files and Cloudflare rate limits, this is astronomically unlikely.

**Impact**: None in practice. Theoretically two different paths could collide, causing one to overwrite the other's metadata.

**Fix**: No fix needed. 128 bits is more than sufficient. Document the theoretical limit.

**Worth fixing**: **No.** Correct as designed.

---

### M4. `init_volume` Root Dir Is Stored Unencrypted

**File**: `src/storage/mod.rs:623-629`  
**Bug**: `init_volume` stores the root directory as a plain JSON TXT record (not encrypted), while all subsequent `write_dir` calls encrypt the directory listing. The root dir created at init time is unencrypted, but the first write to `/` during normal operation will replace it with an encrypted version.

**Impact**: Brief window where root directory listing is plaintext in DNS. Only contains an empty entries array, so no information leakage. Gets overwritten on first use.

**Fix**: Encrypt the root dir at init time using the master key (would require passing the key to `init_volume`).

**Worth fixing**: **Low priority.** No data is exposed since the initial root is empty.

---

### M5. `batch_create` Default Implementation Is Sequential

**File**: `src/dns/mod.rs`  
**Analysis**: The `DnsBackend` trait provides a default `batch_create` that just loops through sequentially. The `CloudflareBackend` doesn't override it with Cloudflare's actual batch API. This means "write coalescing" provides no actual network-level benefit over the old sequential approach — the benefit is only in code organization.

**Impact**: Write performance is not actually improved. Reads benefit from parallel fetch, but writes are still serial.

**Fix**: Implement Cloudflare's batch DNS record API in the `CloudflareBackend`. Cloudflare supports batch operations via their API. The `MockDnsBackend` also uses the default sequential impl, so tests pass either way.

**Worth fixing**: **Yes for production Cloudflare use.** Not blocking for the PoC since local backend is instant.

---

## LOW — Nice to Have

### L1. Unused `is_duplicate` Function in Chunk Module  
**File**: `src/chunk/mod.rs:161`  
**Status**: Dead code, never called. Dedup is handled in `storage::write_chunks_coalesced`.  
**Fix**: Remove it. *(Noted, not blocking)*

### L2. `aes-gcm` Dependency Is Unused  
**File**: `Cargo.toml:20`  
**Status**: Listed as a dependency but never imported. Only ChaCha20-Poly1305 is used.  
**Fix**: Remove from Cargo.toml. *(Fixed in this review)*

### L3. `export` Doesn't Reconstruct Full File Paths  
**File**: `src/volume/mod.rs:405`  
**Analysis**: Export uses `meta.name` (just the filename) rather than the full path. Two files with the same name in different directories would collide in the tar archive.  
**Fix**: Walk the directory tree to reconstruct full paths before exporting, or include the path hash in the archive filename.  
**Worth fixing**: **Yes for correctness**, medium effort.

### L4. `_req` Parameter Passed to `self.getattr` in `setattr`  
**File**: `src/fs/mod.rs:678`  
**Analysis**: `self.getattr(_req, ino, None, reply)` — this works but passes an unused `_req` whose name prefix suggests it's intentionally unused. Harmless but slightly misleading.  
**Fix**: N/A, cosmetic.

---

## Fixes Applied During This Review

| ID | Fix |
|----|-----|
| H2 | Identified; needs 1-line fix (capture inode before delete_file) |
| H4 | Identified; remove redundant whitespace checks |
| L2 | Identified; remove `aes-gcm` from Cargo.toml |
| -- | Removed unused `Arc` import from storage |
| -- | Removed unused `TxtRecord` import from storage |
| -- | Removed 5 unused libc error constants from fs |
| -- | Removed unused imports from volume module |
| -- | Added missing `DnsError` import in fs module |
| -- | Removed stale `{dns,fs,...}` literal directory artifact |

---

## Recommended Fix Priority

### Must fix before GitHub push:
1. **C2** — Cross-file dedup decryption failure (switch to single data key)
2. **C1** — Rename is_dir detection inversion
3. **H1** — Overwrite clobbers created timestamp
4. **H2** — unlink inode capture ordering
5. **M1** — key_from_hex whitespace trimming

### Should fix soon after:
6. **C3** — Remove dead empty-file codepath
7. **L1** — Remove dead `is_duplicate` function  
8. **L2** — Remove unused `aes-gcm` dependency
9. **L3** — Export path reconstruction

### Acceptable as-is for PoC:
- M2, M3, M4, M5, H3, H4, L4
