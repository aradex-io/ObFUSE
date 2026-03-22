use dnfs::crypto;
use dnfs::dns;
use dnfs::fs;
use dnfs::storage;
use dnfs::volume;

use clap::{Parser, Subcommand, ValueEnum};
use log::info;
use std::path::PathBuf;

const LONG_ABOUT: &str = "\
Dn(f)s — A DNS-backed encrypted filesystem.

Store files as encrypted, compressed, content-addressed DNS TXT records.
Mount with FUSE and use standard Linux tools (ls, cat, cp, vim, etc.)
to interact with data living in the global DNS infrastructure.

Every file is split into chunks, compressed with zstd, encrypted with
ChaCha20-Poly1305, and stored as base64-encoded TXT records. Identical
chunks are deduplicated via BLAKE3 content addressing.

QUICK START (local mode, no Cloudflare needed):
  $ dnfs keygen > /tmp/dnfs.key
  $ dnfs init -d local.dnfs -b local
  $ mkdir /tmp/dnfs
  $ dnfs mount -m /tmp/dnfs -d local.dnfs -b local -k $(cat /tmp/dnfs.key) --rw
  $ echo 'hello from DNS' > /tmp/dnfs/hello.txt
  $ cat /tmp/dnfs/hello.txt

QUICK START (Cloudflare):
  $ export DNFS_CF_TOKEN=your-api-token
  $ export DNFS_CF_ZONE=your-zone-id
  $ export DNFS_KEY=$(dnfs keygen)
  $ dnfs init -d fs.example.com
  $ dnfs mount -m /tmp/dnfs -d fs.example.com --rw

VERIFY DATA IN DNS:
  $ dig TXT _meta.*.fs.example.com +short";

#[derive(Parser)]
#[command(
    name = "dnfs",
    version = "0.5.0",
    about = "Dn(f)s — A DNS-backed encrypted filesystem",
    long_about = LONG_ABOUT,
    after_help = "See https://github.com/d0sf3t/dnfs for full documentation."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum Backend {
    /// Cloudflare DNS API (requires --token and --zone)
    Cloudflare,
    /// Local JSON file — no network, for development and demos
    Local,
}

#[derive(Parser, Clone)]
struct ConnArgs {
    /// Base domain for DNS records
    ///
    /// For Cloudflare: use a subdomain you control (e.g., fs.example.com).
    /// For local mode: any string works as a namespace (e.g., local.dnfs).
    #[arg(short, long)]
    domain: String,

    /// DNS backend to use
    #[arg(short, long, default_value = "cloudflare")]
    backend: Backend,

    /// Cloudflare API token with Zone.DNS edit permission
    #[arg(short, long, env = "DNFS_CF_TOKEN")]
    token: Option<String>,

    /// Cloudflare Zone ID (found in domain overview dashboard)
    #[arg(short, long, env = "DNFS_CF_ZONE")]
    zone: Option<String>,

    /// Path to local JSON store (only used with --backend local)
    #[arg(long, default_value = "./dnfs-records.json")]
    store_path: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount the filesystem at a directory
    ///
    /// Rebuilds the inode table from DNS on mount, then serves
    /// FUSE operations by translating reads/writes into DNS queries.
    ///
    /// Examples:
    ///   dnfs mount -m /tmp/dnfs -d fs.example.com -k $DNFS_KEY --rw
    ///   dnfs mount -m /mnt/dnfs -d local.dnfs -b local -k $KEY --rw
    Mount {
        #[command(flatten)]
        conn: ConnArgs,

        /// Directory to mount the filesystem at (must exist)
        #[arg(short, long)]
        mountpoint: PathBuf,

        /// Encryption key — hex-encoded 32 bytes. Generate with `dnfs keygen`.
        #[arg(short, long, env = "DNFS_KEY")]
        key: Option<String>,

        /// Enable read-write mode (default: read-only)
        #[arg(long, default_value_t = false)]
        rw: bool,
    },

    /// Create a new Dn(f)s volume on a domain
    ///
    /// Writes the volume metadata and root directory records.
    /// Run this once before first mount.
    ///
    /// Example:
    ///   dnfs init -d fs.example.com
    Init {
        #[command(flatten)]
        conn: ConnArgs,
    },

    /// Generate a new 256-bit encryption key
    ///
    /// Outputs a hex-encoded 32-byte key to stdout.
    /// Store this key securely — without it, your data is unrecoverable.
    ///
    /// Example:
    ///   dnfs keygen > ~/.config/dnfs/key
    ///   export DNFS_KEY=$(dnfs keygen)
    Keygen,

    /// Show volume statistics
    ///
    /// Displays file count, chunk count, and total DNS records.
    ///
    /// Example:
    ///   dnfs stat -d fs.example.com
    Stat {
        #[command(flatten)]
        conn: ConnArgs,
    },

    /// Garbage-collect orphaned chunk records
    ///
    /// Scans all file metadata to build the set of referenced chunks,
    /// then deletes any chunk records not referenced by any file.
    /// Safe for deduplication — shared chunks are preserved.
    ///
    /// Examples:
    ///   dnfs gc -d fs.example.com -k $KEY --dry-run
    ///   dnfs gc -d fs.example.com -k $KEY
    Gc {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key (needed to read file metadata)
        #[arg(short, long, env = "DNFS_KEY")]
        key: String,

        /// Preview what would be deleted without actually deleting
        #[arg(long, default_value_t = false)]
        dry_run: bool,
    },

    /// Verify filesystem integrity
    ///
    /// Checks that all metadata records can be decrypted, all referenced
    /// chunks exist, and volume structure is consistent. Reports errors
    /// and warnings. Exits with code 1 if errors are found.
    ///
    /// Example:
    ///   dnfs fsck -d fs.example.com -k $KEY
    Fsck {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key (needed to decrypt and verify records)
        #[arg(short, long, env = "DNFS_KEY")]
        key: String,
    },

    /// Export the entire volume to a tar.gz archive
    ///
    /// Dumps all file metadata and encrypted chunks into a portable
    /// archive. The export contains encrypted data — the master key
    /// is needed to access file contents after reimport.
    ///
    /// Example:
    ///   dnfs export -d fs.example.com -k $KEY -o backup.tar.gz
    Export {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key
        #[arg(short, long, env = "DNFS_KEY")]
        key: String,

        /// Output archive path
        #[arg(short, long, default_value = "./dnfs-export.tar.gz")]
        output: PathBuf,
    },

    /// Fetch and execute a binary from the DNS filesystem in-memory
    ///
    /// Retrieves the file from DNS, decrypts it, and executes it directly
    /// from memory using memfd_create(2) — no file is written to disk.
    ///
    /// Examples:
    ///   dnfs exec -d local.dnfs -b local -k $KEY /tools/recon
    ///   dnfs exec -d fs.example.com -k $KEY /bin/agent -- --target 10.0.0.1
    Exec {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key
        #[arg(short, long, env = "DNFS_KEY")]
        key: String,

        /// Path of the file within the DNS filesystem to execute
        filepath: String,

        /// Arguments to pass to the executed binary (after --)
        #[arg(last = true)]
        args: Vec<String>,
    },

    /// Delete ALL records under the domain — IRREVERSIBLE
    ///
    /// Removes every DNS record associated with this Dn(f)s volume.
    /// Requires interactive confirmation unless --yes is passed.
    /// Consider running `dnfs export` first.
    ///
    /// Example:
    ///   dnfs nuke -d fs.example.com --yes
    Nuke {
        #[command(flatten)]
        conn: ConnArgs,

        /// Skip the confirmation prompt
        #[arg(long, default_value_t = false)]
        yes: bool,
    },
}

fn make_backend(conn: &ConnArgs) -> Box<dyn dns::DnsBackend> {
    match conn.backend {
        Backend::Cloudflare => {
            let token = conn.token.clone()
                .expect("Cloudflare backend requires --token or DNFS_CF_TOKEN env var");
            let zone = conn.zone.clone()
                .expect("Cloudflare backend requires --zone or DNFS_CF_ZONE env var");
            let retry = dns::retry::RetryBackend::with_defaults(
                Box::new(dns::cloudflare::CloudflareBackend::new(token, zone, conn.domain.clone()))
            );
            Box::new(retry)
        }
        Backend::Local => {
            info!("Using local backend: {:?}", conn.store_path);
            Box::new(dns::local::LocalFileBackend::new(conn.store_path.clone()))
        }
    }
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("warn")
    ).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Mount { conn, mountpoint, key, rw } => {
            let encryption_key = match key {
                Some(k) => crypto::key_from_hex(&k).expect("Invalid encryption key"),
                None => {
                    eprintln!("Error: encryption key required. Generate one with `dnfs keygen`.");
                    std::process::exit(1);
                }
            };

            if !mountpoint.exists() {
                eprintln!("Error: mount point {:?} does not exist. Create it first.", mountpoint);
                std::process::exit(1);
            }

            eprintln!("Mounting Dn(f)s at {} ({})", mountpoint.display(),
                if rw { "read-write" } else { "read-only" });

            let backend = make_backend(&conn);
            let config = storage::StorageConfig {
                rebuild_on_mount: true,
                ..Default::default()
            };
            let store = storage::DnfsStorage::with_config(backend, encryption_key, conn.domain, config);
            let filesystem = fs::DnfsFilesystem::new(store, rw);

            let mut options = vec![
                fuser::MountOption::FSName("dnfs".to_string()),
                fuser::MountOption::AutoUnmount,
                if rw { fuser::MountOption::RW } else { fuser::MountOption::RO },
            ];

            // AllowOther requires /etc/fuse.conf to have user_allow_other
            // Try it, but don't fail if unavailable
            options.push(fuser::MountOption::AllowOther);

            match fuser::mount2(filesystem, &mountpoint, &options) {
                Ok(()) => {}
                Err(e) => {
                    eprintln!("Mount failed: {}", e);
                    eprintln!("Hint: if 'Permission denied', check /etc/fuse.conf has user_allow_other");
                    std::process::exit(1);
                }
            }
        }

        Commands::Init { conn } => {
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                storage::init_volume(backend.as_ref(), &conn.domain)
                    .await.expect("Failed to initialize volume");
            });
            eprintln!("✓ Volume initialized on {}", conn.domain);
        }

        Commands::Keygen => {
            let key = crypto::generate_key();
            println!("{}", hex::encode(key));
            eprintln!("Store this key securely. Without it, your data is unrecoverable.");
        }

        Commands::Stat { conn } => {
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                match storage::get_volume_stats(backend.as_ref(), &conn.domain).await {
                    Ok(stats) => println!("{}", stats),
                    Err(e) => { eprintln!("Error: {}", e); std::process::exit(1); }
                }
            });
        }

        Commands::Gc { conn, key, dry_run } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            if dry_run { eprintln!("Running GC in dry-run mode..."); }

            rt.block_on(async {
                match volume::gc(backend.as_ref(), &conn.domain, &master_key, dry_run).await {
                    Ok(result) => println!("{}", result),
                    Err(e) => { eprintln!("GC error: {}", e); std::process::exit(1); }
                }
            });
        }

        Commands::Fsck { conn, key } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                match volume::fsck(backend.as_ref(), &conn.domain, &master_key).await {
                    Ok(result) => {
                        println!("{}", result);
                        if result.is_clean() {
                            eprintln!("\n✓ Volume is clean");
                        } else {
                            eprintln!("\n✗ Issues found");
                            std::process::exit(1);
                        }
                    }
                    Err(e) => { eprintln!("fsck error: {}", e); std::process::exit(1); }
                }
            });
        }

        Commands::Export { conn, key, output } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                match volume::export(backend.as_ref(), &conn.domain, &master_key, &output).await {
                    Ok(count) => eprintln!("✓ Exported {} files to {}", count, output.display()),
                    Err(e) => { eprintln!("Export error: {}", e); std::process::exit(1); }
                }
            });
        }

        Commands::Exec { conn, key, filepath, args } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let config = storage::StorageConfig {
                max_file_size: 10 * 1024 * 1024, // 10MB — binaries exceed the default 64KB
                ..Default::default()
            };
            let mut store = storage::DnfsStorage::with_config(
                backend, master_key, conn.domain, config,
            );

            eprintln!("Fetching {}...", filepath);
            let binary = match store.read_file(&filepath) {
                Ok(data) => data,
                Err(e) => {
                    eprintln!("Failed to read {}: {}", filepath, e);
                    std::process::exit(1);
                }
            };

            eprintln!("Executing in-memory ({} bytes)...", binary.len());
            if let Err(e) = dnfs::exec::memfd_exec(binary, args) {
                eprintln!("Execution failed: {}", e);
                std::process::exit(1);
            }
        }

        Commands::Nuke { conn, yes } => {
            if !yes {
                eprintln!("⚠  WARNING: This will permanently delete ALL records under {}", conn.domain);
                eprintln!("   This action is IRREVERSIBLE. Consider `dnfs export` first.\n");
                eprint!("   Type 'yes' to confirm: ");
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap();
                if input.trim() != "yes" {
                    eprintln!("Aborted.");
                    std::process::exit(0);
                }
            }

            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                match volume::nuke(backend.as_ref(), &conn.domain).await {
                    Ok(result) => {
                        eprintln!("✓ Nuked: {} records deleted, {} errors",
                            result.records_deleted, result.errors);
                    }
                    Err(e) => { eprintln!("Nuke error: {}", e); std::process::exit(1); }
                }
            });
        }
    }
}
