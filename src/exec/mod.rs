use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExecError {
    #[error("memfd_create failed: {0}")]
    MemfdCreate(std::io::Error),
    #[error("failed to write binary to memfd: {0}")]
    MemfdWrite(std::io::Error),
    #[error("execve failed: {0}")]
    Execve(std::io::Error),
    #[error("unsupported platform")]
    UnsupportedPlatform,
    #[error("binary too small to be valid ({0} bytes)")]
    InvalidBinary(usize),
}

#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
mod windows;

/// Execute raw bytes as a binary in-memory without writing to disk.
///
/// On success this function does NOT return — the current process is
/// replaced via `execve(2)`. Returns `Err` only on failure.
///
/// # Platform support
/// - **Linux**: `memfd_create(2)` + `execve("/proc/self/fd/{fd}")`
/// - **Windows**: stub (returns `UnsupportedPlatform`)
pub fn memfd_exec(binary: Vec<u8>, args: Vec<String>) -> Result<(), ExecError> {
    if binary.len() < 64 {
        return Err(ExecError::InvalidBinary(binary.len()));
    }

    #[cfg(target_os = "linux")]
    {
        linux::exec_memfd(binary, args)
    }

    #[cfg(target_os = "windows")]
    {
        windows::exec_in_memory(binary, args)
    }

    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (binary, args);
        Err(ExecError::UnsupportedPlatform)
    }
}
