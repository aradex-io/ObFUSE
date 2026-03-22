#[cfg(target_os = "linux")]
mod linux;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExecError {
    #[error("memfd_create failed: {0}")]
    MemfdCreate(std::io::Error),
    #[error("memfd write failed: {0}")]
    MemfdWrite(std::io::Error),
    #[error("execve failed: {0}")]
    Execve(std::io::Error),
    #[error("binary too small ({0} bytes)")]
    InvalidBinary(usize),
    #[error("unsupported platform")]
    UnsupportedPlatform,
}

/// Execute a binary from memory without writing to disk (Linux only).
pub fn memfd_exec(binary: Vec<u8>, args: Vec<String>) -> Result<(), ExecError> {
    if binary.len() < 64 {
        return Err(ExecError::InvalidBinary(binary.len()));
    }
    #[cfg(target_os = "linux")]
    { linux::memfd_exec_impl(binary, args) }
    #[cfg(not(target_os = "linux"))]
    { let _ = (binary, args); Err(ExecError::UnsupportedPlatform) }
}
