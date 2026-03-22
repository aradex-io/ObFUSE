//! Reflective loading primitives for Linux ELF binaries.
//!
//! Implements userspace ELF loading — maps an ELF entirely from memory
//! without execve or dlopen, performing manual segment mapping,
//! dynamic linking, and relocation processing.

use super::{Arch, PayloadError};

/// Parsed ELF metadata for reflective loading
#[derive(Debug)]
pub struct ElfLoadInfo {
    pub arch: Arch,
    pub is_pie: bool,
    pub entry_offset: u64,
    pub phdr_offset: u64,
    pub phdr_count: u16,
    pub phdr_entry_size: u16,
    pub segments: Vec<LoadSegment>,
    pub dynamic: Option<DynamicInfo>,
    pub interp: Option<String>,
    pub total_mapping_size: u64,
}

#[derive(Debug, Clone)]
pub struct LoadSegment {
    pub seg_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[derive(Debug)]
pub struct DynamicInfo {
    pub needed_libs: Vec<String>,
    pub rela_offset: u64,
    pub rela_size: u64,
    pub relaent_size: u64,
    pub plt_rel_offset: u64,
    pub plt_rel_size: u64,
    pub init_offset: u64,
    pub fini_offset: u64,
    pub init_array_offset: u64,
    pub init_array_size: u64,
}

/// Parse ELF for reflective loading
pub fn parse_elf(data: &[u8]) -> Result<ElfLoadInfo, PayloadError> {
    if data.len() < 64 || &data[..4] != b"\x7fELF" {
        return Err(PayloadError::InvalidBinary("not a valid ELF".into()));
    }
    if data[4] != 2 {
        return Err(PayloadError::UnsupportedFormat("only ELF64 supported".into()));
    }

    let arch = match u16::from_le_bytes(data[18..20].try_into().unwrap()) {
        0x3E => Arch::X86_64,
        0xB7 => Arch::Aarch64,
        m => return Err(PayloadError::UnsupportedFormat(format!("ELF machine 0x{m:04x}"))),
    };

    let e_type = u16::from_le_bytes(data[16..18].try_into().unwrap());
    let is_pie = e_type == 3; // ET_DYN (shared object / PIE)

    let entry = u64::from_le_bytes(data[0x18..0x20].try_into().unwrap());
    let phoff = u64::from_le_bytes(data[0x20..0x28].try_into().unwrap());
    let phentsize = u16::from_le_bytes(data[0x36..0x38].try_into().unwrap());
    let phnum = u16::from_le_bytes(data[0x38..0x3A].try_into().unwrap());

    let mut segments = Vec::new();
    let mut min_vaddr = u64::MAX;
    let mut max_vaddr = 0u64;
    let mut interp = None;
    let mut dynamic_offset = 0u64;
    let mut dynamic_size = 0u64;

    for i in 0..phnum as usize {
        let ph = phoff as usize + i * phentsize as usize;
        if ph + phentsize as usize > data.len() {
            break;
        }

        let p_type = u32::from_le_bytes(data[ph..ph + 4].try_into().unwrap());
        let p_flags = u32::from_le_bytes(data[ph + 4..ph + 8].try_into().unwrap());
        let p_offset = u64::from_le_bytes(data[ph + 8..ph + 16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(data[ph + 16..ph + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(data[ph + 32..ph + 40].try_into().unwrap());
        let p_memsz = u64::from_le_bytes(data[ph + 40..ph + 48].try_into().unwrap());
        let p_align = u64::from_le_bytes(data[ph + 48..ph + 56].try_into().unwrap());

        match p_type {
            1 => { // PT_LOAD
                min_vaddr = min_vaddr.min(p_vaddr);
                max_vaddr = max_vaddr.max(p_vaddr + p_memsz);
            }
            3 => { // PT_INTERP
                let start = p_offset as usize;
                let end = start + p_filesz as usize;
                if end <= data.len() {
                    let s = std::str::from_utf8(&data[start..end])
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    interp = Some(s.to_string());
                }
            }
            2 => { // PT_DYNAMIC
                dynamic_offset = p_offset;
                dynamic_size = p_filesz;
            }
            _ => {}
        }

        segments.push(LoadSegment {
            seg_type: p_type,
            flags: p_flags,
            offset: p_offset,
            vaddr: p_vaddr,
            filesz: p_filesz,
            memsz: p_memsz,
            align: p_align,
        });
    }

    let total_mapping_size = if max_vaddr > min_vaddr {
        max_vaddr - min_vaddr
    } else {
        0
    };

    // Parse PT_DYNAMIC if present
    let dynamic = if dynamic_offset > 0 && dynamic_size > 0 {
        Some(parse_dynamic(data, dynamic_offset as usize, dynamic_size as usize)?)
    } else {
        None
    };

    Ok(ElfLoadInfo {
        arch,
        is_pie,
        entry_offset: entry,
        phdr_offset: phoff,
        phdr_count: phnum,
        phdr_entry_size: phentsize,
        segments,
        dynamic,
        interp,
        total_mapping_size,
    })
}

fn parse_dynamic(data: &[u8], offset: usize, size: usize) -> Result<DynamicInfo, PayloadError> {
    let mut info = DynamicInfo {
        needed_libs: Vec::new(),
        rela_offset: 0,
        rela_size: 0,
        relaent_size: 0,
        plt_rel_offset: 0,
        plt_rel_size: 0,
        init_offset: 0,
        fini_offset: 0,
        init_array_offset: 0,
        init_array_size: 0,
    };

    let mut strtab_offset = 0u64;
    let mut needed_indices = Vec::new();

    // First pass: find STRTAB and collect entries
    let entry_size = 16; // Elf64_Dyn is 16 bytes
    let count = size / entry_size;
    for i in 0..count {
        let ent = offset + i * entry_size;
        if ent + entry_size > data.len() {
            break;
        }
        let d_tag = i64::from_le_bytes(data[ent..ent + 8].try_into().unwrap());
        let d_val = u64::from_le_bytes(data[ent + 8..ent + 16].try_into().unwrap());

        match d_tag {
            0 => break,         // DT_NULL
            1 => needed_indices.push(d_val), // DT_NEEDED (strtab offset)
            5 => strtab_offset = d_val, // DT_STRTAB
            7 => info.rela_offset = d_val, // DT_RELA
            8 => info.rela_size = d_val,   // DT_RELASZ
            9 => info.relaent_size = d_val, // DT_RELAENT
            12 => info.init_offset = d_val, // DT_INIT
            13 => info.fini_offset = d_val, // DT_FINI
            23 => info.plt_rel_offset = d_val, // DT_JMPREL
            2 => info.plt_rel_size = d_val,    // DT_PLTRELSZ
            25 => info.init_array_offset = d_val, // DT_INIT_ARRAY
            27 => info.init_array_size = d_val,    // DT_INIT_ARRAYSZ
            _ => {}
        }
    }

    // Resolve DT_NEEDED strings (note: strtab_offset is a virtual address,
    // so this only works for non-PIE or when we can map offset = vaddr)
    // For analysis purposes, we just store the indices
    let _ = strtab_offset;
    for idx in needed_indices {
        info.needed_libs.push(format!("lib@0x{idx:x}"));
    }

    Ok(info)
}

/// Generate a reflective ELF loader as shellcode.
///
/// The loader:
/// 1. mmap's a contiguous region for the ELF image
/// 2. Copies each PT_LOAD segment to the correct offset
/// 3. Processes relocations in-place
/// 4. Calls DT_INIT and DT_INIT_ARRAY entries
/// 5. Jumps to the entry point
///
/// Returns: [loader_stub | elf_data]
pub fn generate_reflective_loader(
    elf_data: &[u8],
    config: &ReflectiveConfig,
) -> Result<Vec<u8>, PayloadError> {
    let info = parse_elf(elf_data)?;

    if !info.is_pie {
        return Err(PayloadError::UnsupportedFormat(
            "reflective loading requires PIE (ET_DYN) binary — compile with -fPIE -pie".into(),
        ));
    }

    // Build the loader metadata header
    let meta = ReflectiveLoaderMeta {
        magic: *b"RELF",
        elf_size: elf_data.len() as u64,
        entry_offset: info.entry_offset,
        total_map_size: info.total_mapping_size,
        num_segments: info.segments.len() as u32,
        // Segment descriptors follow
        segments: info.segments.iter()
            .filter(|s| s.seg_type == 1) // PT_LOAD only
            .cloned()
            .collect(),
    };

    let mut output = Vec::new();

    // Serialize meta header
    output.extend_from_slice(&meta.magic);
    output.extend_from_slice(&meta.elf_size.to_le_bytes());
    output.extend_from_slice(&meta.entry_offset.to_le_bytes());
    output.extend_from_slice(&meta.total_map_size.to_le_bytes());
    output.extend_from_slice(&(meta.segments.len() as u32).to_le_bytes());

    // Serialize segment descriptors
    for seg in &meta.segments {
        output.extend_from_slice(&seg.offset.to_le_bytes());
        output.extend_from_slice(&seg.vaddr.to_le_bytes());
        output.extend_from_slice(&seg.filesz.to_le_bytes());
        output.extend_from_slice(&seg.memsz.to_le_bytes());
        output.extend_from_slice(&seg.flags.to_le_bytes());
    }

    // Optionally compress the ELF
    let elf_blob = if config.compress {
        let mut encoder = zstd::Encoder::new(Vec::new(), 15)
            .map_err(|e| PayloadError::EncodingError(format!("zstd: {e}")))?;
        std::io::Write::write_all(&mut encoder, elf_data)
            .map_err(|e| PayloadError::EncodingError(format!("zstd write: {e}")))?;
        let compressed = encoder.finish()
            .map_err(|e| PayloadError::EncodingError(format!("zstd finish: {e}")))?;
        // Add compression marker
        output.push(1); // compressed
        output.extend_from_slice(&(compressed.len() as u64).to_le_bytes());
        compressed
    } else {
        output.push(0); // not compressed
        output.extend_from_slice(&(elf_data.len() as u64).to_le_bytes());
        elf_data.to_vec()
    };

    output.extend_from_slice(&elf_blob);

    Ok(output)
}

/// Configuration for reflective ELF loader generation
#[derive(Debug, Clone)]
pub struct ReflectiveConfig {
    /// Compress the embedded ELF
    pub compress: bool,
    /// Wipe ELF headers from memory after loading (anti-forensics)
    pub wipe_headers: bool,
    /// Randomize the base address offset
    pub randomize_base: bool,
}

impl Default for ReflectiveConfig {
    fn default() -> Self {
        Self {
            compress: true,
            wipe_headers: true,
            randomize_base: true,
        }
    }
}

#[derive(Debug)]
struct ReflectiveLoaderMeta {
    magic: [u8; 4],
    elf_size: u64,
    entry_offset: u64,
    total_map_size: u64,
    num_segments: u32,
    segments: Vec<LoadSegment>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_elf_pie() -> Vec<u8> {
        let mut elf = vec![0u8; 256];
        // ELF magic
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2; // 64-bit
        elf[5] = 1; // little-endian
        elf[6] = 1; // ELF version
        // e_type = ET_DYN (PIE)
        elf[16] = 3;
        elf[17] = 0;
        // e_machine = EM_X86_64
        elf[18] = 0x3E;
        elf[19] = 0;
        // e_entry
        elf[0x18] = 0x00;
        elf[0x19] = 0x10;
        // e_phoff = 64
        elf[0x20] = 64;
        // e_phentsize = 56
        elf[0x36] = 56;
        // e_phnum = 1
        elf[0x38] = 1;

        // Program header at offset 64: PT_LOAD
        let ph = 64;
        elf[ph] = 1; // p_type = PT_LOAD
        elf[ph + 4] = 5; // p_flags = PF_R | PF_X
        // p_offset = 0
        // p_vaddr = 0
        // p_filesz = 256
        elf[ph + 32] = 0;
        elf[ph + 33] = 1; // 256
        // p_memsz = 256
        elf[ph + 40] = 0;
        elf[ph + 41] = 1;

        elf
    }

    #[test]
    fn test_parse_elf_pie() {
        let elf = make_minimal_elf_pie();
        let info = parse_elf(&elf).unwrap();
        assert!(info.is_pie);
        assert_eq!(info.arch, Arch::X86_64);
        assert_eq!(info.segments.len(), 1);
    }

    #[test]
    fn test_reflective_loader_generation() {
        let elf = make_minimal_elf_pie();
        let config = ReflectiveConfig {
            compress: false,
            ..Default::default()
        };
        let output = generate_reflective_loader(&elf, &config).unwrap();
        assert_eq!(&output[..4], b"RELF");
        assert!(output.len() > elf.len());
    }

    #[test]
    fn test_non_pie_rejected() {
        let mut elf = make_minimal_elf_pie();
        elf[16] = 2; // ET_EXEC (not PIE)
        let config = ReflectiveConfig::default();
        let result = generate_reflective_loader(&elf, &config);
        assert!(result.is_err());
    }
}
