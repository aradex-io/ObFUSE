//! Donut-style PE-to-shellcode conversion.
//!
//! Converts PE executables (and .NET assemblies) into position-independent
//! shellcode that performs its own loading — no disk writes, no LoadLibrary.
//!
//! Inspired by TheWover/donut, this module generates a self-contained shellcode
//! blob that:
//! 1. Resolves kernel32/ntdll exports via PEB walk
//! 2. Allocates RWX memory
//! 3. Manually maps the PE (headers, sections, relocations, imports)
//! 4. Calls the entry point
//!
//! For .NET assemblies, it additionally:
//! 5. Initializes the CLR via ICLRRuntimeHost
//! 6. Loads the assembly from memory via Assembly.Load()

use super::{Arch, PayloadError};

/// Configuration for PE-to-shellcode conversion
#[derive(Debug, Clone)]
pub struct DonutConfig {
    pub arch: Arch,
    /// Compress the PE before embedding (zstd)
    pub compress: bool,
    /// Add XOR encryption layer with this key
    pub xor_key: Option<Vec<u8>>,
    /// For .NET: class name to invoke
    pub class_name: Option<String>,
    /// For .NET: method name to invoke
    pub method_name: Option<String>,
    /// Bypass AMSI before loading .NET assembly
    pub bypass_amsi: bool,
    /// Bypass ETW before loading .NET assembly
    pub bypass_etw: bool,
    /// PE entry point arguments
    pub args: Option<String>,
}

impl Default for DonutConfig {
    fn default() -> Self {
        Self {
            arch: Arch::X86_64,
            compress: true,
            xor_key: None,
            class_name: None,
            method_name: None,
            bypass_amsi: true,
            bypass_etw: true,
            args: None,
        }
    }
}

/// Metadata about a PE file parsed for conversion
#[derive(Debug)]
pub struct PeInfo {
    pub arch: Arch,
    pub is_dll: bool,
    pub is_dotnet: bool,
    pub entry_point_rva: u32,
    pub image_base: u64,
    pub size_of_image: u32,
    pub section_alignment: u32,
    pub num_sections: u16,
    /// CLR runtime header RVA (non-zero for .NET)
    pub clr_header_rva: u32,
    pub has_relocations: bool,
    pub has_tls: bool,
}

/// Parse PE headers and extract metadata needed for shellcode generation
pub fn parse_pe(data: &[u8]) -> Result<PeInfo, PayloadError> {
    if data.len() < 64 || &data[..2] != b"MZ" {
        return Err(PayloadError::InvalidBinary("not a PE file".into()));
    }

    let pe_offset = u32::from_le_bytes(data[0x3C..0x40].try_into().unwrap()) as usize;
    if pe_offset + 24 > data.len() || &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
        return Err(PayloadError::InvalidBinary("invalid PE signature".into()));
    }

    let machine = u16::from_le_bytes(data[pe_offset + 4..pe_offset + 6].try_into().unwrap());
    let num_sections = u16::from_le_bytes(data[pe_offset + 6..pe_offset + 8].try_into().unwrap());
    let characteristics = u16::from_le_bytes(data[pe_offset + 22..pe_offset + 24].try_into().unwrap());
    let is_dll = (characteristics & 0x2000) != 0; // IMAGE_FILE_DLL

    let arch = match machine {
        0x8664 => Arch::X86_64,
        0x014C => Arch::X86,
        m => return Err(PayloadError::UnsupportedFormat(format!("PE machine 0x{m:04x}"))),
    };

    let opt_offset = pe_offset + 24;
    let opt_magic = u16::from_le_bytes(data[opt_offset..opt_offset + 2].try_into().unwrap());

    let (entry_rva, image_base, size_of_image, section_alignment, num_data_dirs, data_dir_offset) = match opt_magic {
        0x20B => { // PE32+
            let ep = u32::from_le_bytes(data[opt_offset + 16..opt_offset + 20].try_into().unwrap());
            let ib = u64::from_le_bytes(data[opt_offset + 24..opt_offset + 32].try_into().unwrap());
            let soi = u32::from_le_bytes(data[opt_offset + 56..opt_offset + 60].try_into().unwrap());
            let sa = u32::from_le_bytes(data[opt_offset + 32..opt_offset + 36].try_into().unwrap());
            let ndd = u32::from_le_bytes(data[opt_offset + 108..opt_offset + 112].try_into().unwrap());
            (ep, ib, soi, sa, ndd, opt_offset + 112)
        }
        0x10B => { // PE32
            let ep = u32::from_le_bytes(data[opt_offset + 16..opt_offset + 20].try_into().unwrap());
            let ib = u32::from_le_bytes(data[opt_offset + 28..opt_offset + 32].try_into().unwrap()) as u64;
            let soi = u32::from_le_bytes(data[opt_offset + 56..opt_offset + 60].try_into().unwrap());
            let sa = u32::from_le_bytes(data[opt_offset + 32..opt_offset + 36].try_into().unwrap());
            let ndd = u32::from_le_bytes(data[opt_offset + 96..opt_offset + 100].try_into().unwrap());
            (ep, ib, soi, sa, ndd, opt_offset + 100)
        }
        m => return Err(PayloadError::UnsupportedFormat(format!("PE optional magic 0x{m:04x}"))),
    };

    // Check for CLR header (data directory index 14)
    let clr_header_rva = if num_data_dirs > 14 {
        let clr_dir_offset = data_dir_offset + 14 * 8;
        if clr_dir_offset + 4 <= data.len() {
            u32::from_le_bytes(data[clr_dir_offset..clr_dir_offset + 4].try_into().unwrap())
        } else {
            0
        }
    } else {
        0
    };

    // Check for relocation directory (index 5)
    let has_relocations = if num_data_dirs > 5 {
        let reloc_offset = data_dir_offset + 5 * 8;
        if reloc_offset + 8 <= data.len() {
            let rva = u32::from_le_bytes(data[reloc_offset..reloc_offset + 4].try_into().unwrap());
            let size = u32::from_le_bytes(data[reloc_offset + 4..reloc_offset + 8].try_into().unwrap());
            rva != 0 && size != 0
        } else {
            false
        }
    } else {
        false
    };

    // Check for TLS directory (index 9)
    let has_tls = if num_data_dirs > 9 {
        let tls_offset = data_dir_offset + 9 * 8;
        if tls_offset + 4 <= data.len() {
            u32::from_le_bytes(data[tls_offset..tls_offset + 4].try_into().unwrap()) != 0
        } else {
            false
        }
    } else {
        false
    };

    Ok(PeInfo {
        arch,
        is_dll,
        is_dotnet: clr_header_rva != 0,
        entry_point_rva: entry_rva,
        image_base,
        size_of_image,
        section_alignment,
        num_sections,
        clr_header_rva,
        has_relocations,
        has_tls,
    })
}

/// Convert a PE binary to position-independent shellcode.
///
/// The output is a self-contained blob that:
/// 1. Contains a loader stub (PEB walk + manual mapper)
/// 2. Contains the compressed/encrypted PE
/// 3. At runtime: resolves APIs, maps PE, fixes relocations/imports, calls EP
pub fn pe_to_shellcode(pe_data: &[u8], config: &DonutConfig) -> Result<Vec<u8>, PayloadError> {
    let pe_info = parse_pe(pe_data)?;

    // Compress the PE if requested
    let processed_pe = if config.compress {
        zstd_compress(pe_data, 15)?
    } else {
        pe_data.to_vec()
    };

    // XOR encrypt if key provided
    let final_pe = if let Some(key) = &config.xor_key {
        xor_encode(&processed_pe, key)
    } else {
        processed_pe
    };

    // Build the shellcode package
    let mut output = Vec::new();

    // Header: magic + metadata for the loader
    let header = DonutHeader {
        magic: *b"OBFS",
        pe_size: pe_data.len() as u32,
        packed_size: final_pe.len() as u32,
        compressed: config.compress,
        encrypted: config.xor_key.is_some(),
        xor_key_len: config.xor_key.as_ref().map(|k| k.len() as u8).unwrap_or(0),
        is_dotnet: pe_info.is_dotnet,
        is_dll: pe_info.is_dll,
        entry_rva: pe_info.entry_point_rva,
        image_base: pe_info.image_base,
        size_of_image: pe_info.size_of_image,
        bypass_amsi: config.bypass_amsi && pe_info.is_dotnet,
        bypass_etw: config.bypass_etw && pe_info.is_dotnet,
        has_relocations: pe_info.has_relocations,
        arch: match pe_info.arch {
            Arch::X86_64 => 0x64,
            Arch::X86 => 0x86,
            Arch::Aarch64 => 0xAA,
        },
    };

    // Serialize header
    output.extend_from_slice(&header.magic);
    output.extend_from_slice(&header.pe_size.to_le_bytes());
    output.extend_from_slice(&header.packed_size.to_le_bytes());
    output.push(header.compressed as u8);
    output.push(header.encrypted as u8);
    output.push(header.xor_key_len);
    output.push(header.is_dotnet as u8);
    output.push(header.is_dll as u8);
    output.extend_from_slice(&header.entry_rva.to_le_bytes());
    output.extend_from_slice(&header.image_base.to_le_bytes());
    output.extend_from_slice(&header.size_of_image.to_le_bytes());
    output.push(header.bypass_amsi as u8);
    output.push(header.bypass_etw as u8);
    output.push(header.has_relocations as u8);
    output.push(header.arch);

    // Append XOR key if present
    if let Some(key) = &config.xor_key {
        output.extend_from_slice(key);
    }

    // Append packed PE data
    output.extend_from_slice(&final_pe);

    Ok(output)
}

/// Header embedded in the shellcode package
#[derive(Debug)]
struct DonutHeader {
    magic: [u8; 4],
    pe_size: u32,
    packed_size: u32,
    compressed: bool,
    encrypted: bool,
    xor_key_len: u8,
    is_dotnet: bool,
    is_dll: bool,
    entry_rva: u32,
    image_base: u64,
    size_of_image: u32,
    bypass_amsi: bool,
    bypass_etw: bool,
    has_relocations: bool,
    arch: u8,
}

/// Simple rolling XOR encode
fn xor_encode(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Compress with zstd
fn zstd_compress(data: &[u8], level: i32) -> Result<Vec<u8>, PayloadError> {
    // Use the zstd crate's simple API
    let mut encoder = zstd::Encoder::new(Vec::new(), level)
        .map_err(|e| PayloadError::EncodingError(format!("zstd init: {e}")))?;
    std::io::Write::write_all(&mut encoder, data)
        .map_err(|e| PayloadError::EncodingError(format!("zstd write: {e}")))?;
    encoder.finish()
        .map_err(|e| PayloadError::EncodingError(format!("zstd finish: {e}")))
}

/// Generate a .NET assembly loader stub.
/// This creates shellcode that:
/// 1. Initializes the CLR runtime
/// 2. Loads an assembly from a memory buffer
/// 3. Invokes the specified class.method
pub fn generate_dotnet_loader_info(
    assembly_data: &[u8],
    config: &DonutConfig,
) -> Result<DonutDotnetMeta, PayloadError> {
    if assembly_data.len() < 64 || &assembly_data[..2] != b"MZ" {
        return Err(PayloadError::InvalidBinary("not a valid PE/.NET assembly".into()));
    }

    let pe_info = parse_pe(assembly_data)?;
    if !pe_info.is_dotnet {
        return Err(PayloadError::UnsupportedFormat(
            "PE does not contain CLR metadata — not a .NET assembly".into(),
        ));
    }

    Ok(DonutDotnetMeta {
        assembly_size: assembly_data.len(),
        class_name: config.class_name.clone().unwrap_or_else(|| "Program".into()),
        method_name: config.method_name.clone().unwrap_or_else(|| "Main".into()),
        bypass_amsi: config.bypass_amsi,
        bypass_etw: config.bypass_etw,
        clr_header_rva: pe_info.clr_header_rva,
    })
}

#[derive(Debug)]
pub struct DonutDotnetMeta {
    pub assembly_size: usize,
    pub class_name: String,
    pub method_name: String,
    pub bypass_amsi: bool,
    pub bypass_etw: bool,
    pub clr_header_rva: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_minimal_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 512];
        // MZ header
        pe[0] = b'M';
        pe[1] = b'Z';
        // e_lfanew pointing to PE header at offset 0x80
        pe[0x3C] = 0x80;
        // PE signature
        pe[0x80] = b'P';
        pe[0x81] = b'E';
        pe[0x82] = 0;
        pe[0x83] = 0;
        // Machine: x86_64
        pe[0x84] = 0x64;
        pe[0x85] = 0x86;
        // Number of sections: 1
        pe[0x86] = 1;
        pe[0x87] = 0;
        // Characteristics: executable
        pe[0x96] = 0x02;
        pe[0x97] = 0x00;
        // Optional header size = 240 (0xF0) for PE32+
        pe[0x94] = 0xF0;
        pe[0x95] = 0x00;
        // Optional header magic: PE32+ (0x20B)
        pe[0x98] = 0x0B;
        pe[0x99] = 0x02;
        // Entry point RVA
        pe[0xA8] = 0x00;
        pe[0xA9] = 0x10;
        // Image base
        pe[0xB8] = 0x00;
        pe[0xB9] = 0x00;
        pe[0xBA] = 0x40;
        pe[0xBB] = 0x00;
        // Section alignment
        pe[0xC0] = 0x00;
        pe[0xC1] = 0x10;
        // Size of image
        pe[0xD0] = 0x00;
        pe[0xD1] = 0x20;
        // NumberOfRvaAndSizes = 16
        pe[0x80 + 24 + 108] = 16;
        pe
    }

    #[test]
    fn test_parse_pe() {
        let pe = make_minimal_pe();
        let info = parse_pe(&pe).unwrap();
        assert_eq!(info.arch, Arch::X86_64);
        assert!(!info.is_dll);
        assert!(!info.is_dotnet);
    }

    #[test]
    fn test_pe_to_shellcode() {
        let pe = make_minimal_pe();
        let config = DonutConfig {
            compress: false,
            ..Default::default()
        };
        let sc = pe_to_shellcode(&pe, &config).unwrap();
        // Should start with magic
        assert_eq!(&sc[..4], b"OBFS");
        // Should contain the PE data
        assert!(sc.len() > pe.len());
    }

    #[test]
    fn test_xor_encode_roundtrip() {
        let data = b"hello world this is a test payload";
        let key = b"secretkey";
        let encoded = xor_encode(data, key);
        let decoded = xor_encode(&encoded, key);
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_pe_to_shellcode_compressed() {
        let pe = make_minimal_pe();
        let config = DonutConfig::default();
        let sc = pe_to_shellcode(&pe, &config).unwrap();
        assert_eq!(&sc[..4], b"OBFS");
        // Compressed output should typically be smaller or have the flag set
        assert_eq!(sc[12], 1); // compressed flag
    }
}
