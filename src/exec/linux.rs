use super::ExecError;
use std::ffi::CString;
use std::io::Write;
use std::os::unix::io::FromRawFd;

/// Execute a binary in-memory using memfd_create(2) + execve(2).
///
/// Creates an anonymous in-memory file descriptor, writes the binary to it,
/// then replaces the current process via execve on /proc/self/fd/{fd}.
/// Does NOT return on success.
pub fn exec_memfd(binary: Vec<u8>, args: Vec<String>) -> Result<(), ExecError> {
    // 1. Create anonymous in-memory fd
    let name = CString::new("dnfs").expect("CString::new failed");
    let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(ExecError::MemfdCreate(std::io::Error::last_os_error()));
    }

    // 2. Write binary content to the memfd
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(&binary).map_err(ExecError::MemfdWrite)?;

    // Prevent the File from closing the fd on drop — execve needs it alive
    std::mem::forget(file);

    // 3. Build execve arguments
    let fd_path = format!("/proc/self/fd/{fd}");
    let fd_path_c = CString::new(fd_path).expect("CString::new failed");

    let mut c_args: Vec<CString> = Vec::with_capacity(args.len() + 1);
    c_args.push(CString::new("dnfs-exec").expect("CString::new failed"));
    for a in &args {
        c_args.push(CString::new(a.as_str()).unwrap_or_else(|_| {
            CString::new(a.replace('\0', "")).expect("CString::new failed")
        }));
    }
    let c_arg_ptrs: Vec<*const libc::c_char> = c_args
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // 4. Build envp from current environment
    let env_vars: Vec<CString> = std::env::vars()
        .map(|(k, v)| CString::new(format!("{k}={v}")).expect("CString::new failed"))
        .collect();
    let c_env_ptrs: Vec<*const libc::c_char> = env_vars
        .iter()
        .map(|s| s.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // 5. execve — replaces the current process, does not return on success
    unsafe {
        libc::execve(
            fd_path_c.as_ptr(),
            c_arg_ptrs.as_ptr(),
            c_env_ptrs.as_ptr(),
        );
    }

    // If we reach here, execve failed
    Err(ExecError::Execve(std::io::Error::last_os_error()))
}
