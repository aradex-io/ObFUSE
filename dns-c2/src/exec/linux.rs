use super::ExecError;
use std::ffi::CString;
use std::os::unix::io::FromRawFd;
use std::io::Write;

pub fn memfd_exec_impl(binary: Vec<u8>, args: Vec<String>) -> Result<(), ExecError> {
    let name = CString::new("").unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_memfd_create, name.as_ptr(), 1u32) } as i32;
    if fd < 0 {
        return Err(ExecError::MemfdCreate(std::io::Error::last_os_error()));
    }

    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(&binary).map_err(ExecError::MemfdWrite)?;
    std::mem::forget(file); // Don't close fd

    let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
    let argv: Vec<CString> = std::iter::once(CString::new(".").unwrap())
        .chain(args.into_iter().filter_map(|a| CString::new(a).ok()))
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();

    let environ: Vec<CString> = std::env::vars()
        .filter_map(|(k, v)| CString::new(format!("{}={}", k, v)).ok())
        .collect();
    let env_ptrs: Vec<*const libc::c_char> = environ.iter().map(|e| e.as_ptr()).chain(std::iter::once(std::ptr::null())).collect();

    unsafe { libc::execve(path.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr()); }
    Err(ExecError::Execve(std::io::Error::last_os_error()))
}
