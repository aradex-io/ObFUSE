# Dn(f)s

> A DNS-backed encrypted filesystem. Because every protocol is a filesystem if you're brave enough.

**Dn(f)s** stores files as encrypted, compressed, content-addressed DNS TXT records. Mount it with FUSE, read and write files with standard tools, and watch your data propagate across the global DNS infrastructure.

This is a proof-of-concept. It is *gloriously* impractical. It works.

```
$ echo "hello from DNS" > /tmp/dnfs/hello.txt
$ cat /tmp/dnfs/hello.txt
hello from DNS
$ dig TXT _meta.7f2a9c3b.fs.example.com +short
"U2FsdGVkX1+..." ← your encrypted file metadata, living in DNS
```

## How It Works

```
┌──────────────┐     ┌──────────────┐     ┌───────────────────────────┐
│   userspace   │────▶│  FUSE layer  │────▶│     Storage Engine         │
│  ls, cat, cp  │     │  (fuser)     │     │  ┌─────────────────────┐  │
│  vim, echo    │     │              │     │  │ Chunker (1400B)     │  │
└──────────────┘     └──────────────┘     │  │ Compress (zstd)     │  │
                                           │  │ Encrypt (ChaCha20)  │  │
                                           │  │ Dedup (BLAKE3)      │  │
                                           │  └──────────┬──────────┘  │
                                           │             │             │
                                           │  ┌──────────▼──────────┐  │
                                           │  │   DNS Backend       │  │
                                           │  │  Cloudflare / Local │  │
                                           │  └─────────────────────┘  │
                                           └───────────────────────────┘
```

### Data Pipeline

```
Write: plaintext → split 1400B blocks → BLAKE3 hash (dedup) → zstd compress → ChaCha20 encrypt → base64 → TXT records
Read:  TXT records (parallel) → base64 → decrypt → decompress → reassemble → plaintext
```

### DNS Record Schema

```
_vol.fs.example.com                    Volume metadata (version, created)
_dir.{path_hash}.fs.example.com        Encrypted directory listing
_meta.{path_hash}.fs.example.com       Encrypted file metadata (size, chunk refs, timestamps)
_c{N}.{content_hash}.fs.example.com    Encrypted file data chunk
```

All hashes are truncated BLAKE3 (32 hex chars). All metadata and directory listings are encrypted.

## Features

- **FUSE mount** — `ls`, `cat`, `cp`, `vim`, `echo >`, `rm`, `mv`, `mkdir` all work
- **End-to-end encryption** — ChaCha20-Poly1305 AEAD with per-file derived keys
- **Content-addressed dedup** — identical blocks stored once via BLAKE3 (pre-encryption)
- **Adaptive compression** — zstd level 15 for text, level 1 for binary, auto-detected
- **Parallel I/O** — chunk fetches run concurrently in configurable batch sizes
- **TTL-aware caching** — metadata and directory caches with configurable expiry
- **Pluggable backends** — Cloudflare DNS API or local JSON file (no network needed)
- **Rate limit resilience** — automatic exponential backoff with jitter
- **Volume management** — `gc`, `fsck`, `export`, `nuke` subcommands
- **Corrupt record recovery** — graceful handling of malformed records
- **Mount state rebuild** — full filesystem recovery from DNS on remount

## Quick Start

### Local Mode (no Cloudflare needed)

```bash
cargo build --release

# Generate an encryption key
export DNFS_KEY=$(./target/release/dnfs keygen)

# Initialize a volume
./target/release/dnfs init -d local.dnfs -b local

# Mount the filesystem
mkdir -p /tmp/dnfs
./target/release/dnfs mount -m /tmp/dnfs -d local.dnfs -b local -k $DNFS_KEY --rw

# Use it
echo "hello from DNS" > /tmp/dnfs/hello.txt
cat /tmp/dnfs/hello.txt
ls -la /tmp/dnfs/
mkdir /tmp/dnfs/subdir
cp /tmp/dnfs/hello.txt /tmp/dnfs/subdir/
```

### Cloudflare Mode

```bash
export DNFS_CF_TOKEN="your-cloudflare-api-token"
export DNFS_CF_ZONE="your-zone-id"
export DNFS_KEY=$(./target/release/dnfs keygen)

./target/release/dnfs init -d fs.yourdomain.com
mkdir -p /tmp/dnfs
./target/release/dnfs mount -m /tmp/dnfs -d fs.yourdomain.com -k $DNFS_KEY --rw

# Verify your data is actually in DNS
dig TXT +short @1.1.1.1 _vol.fs.yourdomain.com
```

## All Commands

```
dnfs keygen                Generate a new 256-bit encryption key
dnfs init                  Create a new volume on a domain
dnfs mount                 Mount the filesystem at a directory
dnfs stat                  Show volume statistics (files, chunks, records)
dnfs gc                    Garbage-collect orphaned chunks (with --dry-run)
dnfs fsck                  Verify integrity of all files and chunks
dnfs export                Dump volume to a tar.gz archive
dnfs nuke                  Delete ALL records (interactive confirmation)
```

Every command supports `--backend local` for offline development and `--help` for full usage.

## Volume Management

```bash
# Check integrity
dnfs fsck -d fs.example.com -k $DNFS_KEY

# Preview garbage collection
dnfs gc -d fs.example.com -k $DNFS_KEY --dry-run

# Run garbage collection
dnfs gc -d fs.example.com -k $DNFS_KEY

# Backup
dnfs export -d fs.example.com -k $DNFS_KEY -o backup.tar.gz

# Start over
dnfs nuke -d fs.example.com
```

## Security Model

```
Master Key (256-bit, user-provided)
    │
    ├──▶ BLAKE3-KDF("dnfs-meta-key-v1") ──▶ Metadata encryption key
    │                                         (directory listings, file attrs)
    │
    └──▶ BLAKE3-KDF("dnfs-file-key-v1:" + path) ──▶ Per-file key
                                                      (file content chunks)
```

- **ChaCha20-Poly1305** AEAD with random 96-bit nonces per encryption operation
- **Metadata encrypted** — directory listings and file attributes are opaque TXT blobs
- **Content hashing before encryption** — BLAKE3 hashes plaintext blocks for dedup, then encrypts with random nonces. No plaintext oracle.
- **No key material in DNS** — lose the key, lose the data. No recovery possible.

## Limitations

| Constraint | Why | Workaround |
|---|---|---|
| ~64KB max file size | TXT record and API limits | Configurable via `StorageConfig` |
| Seconds-per-operation latency | Every I/O hits the Cloudflare API | Parallel fetch + caching |
| 1200 req/5min rate limit | Cloudflare API throttling | Exponential backoff with jitter |
| No concurrent writers | Last-write-wins, no distributed locking | Single-writer architecture |
| TTL-based consistency | DNS caching = potential stale reads | 60s TTL + local LRU cache |

## Cloudflare Setup

1. Create a subdomain for Dn(f)s (e.g., `fs.yourdomain.com`)
2. In your Cloudflare dashboard, create an API token with `Zone.DNS` → Edit permission
3. Copy your Zone ID from the domain overview page
4. Export as environment variables:
   ```bash
   export DNFS_CF_TOKEN="your-token"
   export DNFS_CF_ZONE="your-zone-id"
   ```

## Project Structure

```
src/
├── main.rs              CLI entry point (clap) — 8 subcommands
├── lib.rs               Library root
├── crypto/
│   ├── mod.rs           ChaCha20-Poly1305 encrypt/decrypt, BLAKE3 hashing
│   └── keys.rs          KDF — per-file and metadata key derivation
├── chunk/
│   └── mod.rs           Adaptive compress → encrypt → chunk → base64 pipeline
├── dns/
│   ├── mod.rs           DnsBackend trait definition
│   ├── cloudflare.rs    Cloudflare API implementation
│   ├── local.rs         Local JSON file backend
│   ├── mock.rs          In-memory backend for testing
│   └── retry.rs         RetryBackend — exponential backoff wrapper
├── fs/
│   └── mod.rs           FUSE filesystem (lookup, read, write, rename, mkdir, ...)
├── storage/
│   └── mod.rs           Storage engine — maps fs ops to DNS with parallel I/O & caching
└── volume/
    └── mod.rs           Volume operations — gc, fsck, export, nuke

tests/
├── integration_test.rs  Core roundtrip, dedup, directory, binary data tests
├── phase2_test.rs       File size limits, corrupt recovery, rename, rebuild tests
├── phase3_test.rs       Parallel fetch, TTL cache, write coalescing tests
└── phase4_test.rs       GC, fsck, export, nuke tests
```

## Extending

Implement the `DnsBackend` trait to add PowerDNS, Route53, CoreDNS, or any other provider:

```rust
#[async_trait]
impl DnsBackend for YourProvider {
    async fn create_record(&self, name: &str, content: &str, ttl: u32) -> Result<String, DnsError>;
    async fn get_records(&self, name: &str) -> Result<Vec<TxtRecord>, DnsError>;
    async fn update_record(&self, id: &str, content: &str) -> Result<(), DnsError>;
    async fn delete_record(&self, id: &str) -> Result<(), DnsError>;
    async fn list_records(&self, prefix: &str) -> Result<Vec<TxtRecord>, DnsError>;
}
```

## Building

```bash
# Prerequisites
sudo apt install libfuse3-dev fuse3  # Ubuntu/Debian
# or
sudo dnf install fuse3-devel fuse3   # Fedora

# Build
cargo build --release

# Run tests
cargo test

# Lint
cargo clippy --all-targets -- -D warnings
```

## License

CC BY-NC-SA 4.0 — see [LICENSE](LICENSE)

For commercial licensing inquiries, contact the copyright holder.

## Author

Jeremy Laratro (d0sf3t) — [aradex.io](https://aradex.io)

---

*"Any sufficiently advanced abuse of DNS is indistinguishable from a filesystem."*
