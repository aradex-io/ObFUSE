//! Advanced payload generation: shellcode conversion, PIC wrappers,
//! Donut-style PE→shellcode, staged loaders, and reflective injection.

pub mod shellcode;
pub mod pic;
pub mod donut;
pub mod reflective;
pub mod staged;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PayloadError {
    #[error("invalid binary: {0}")]
    InvalidBinary(String),
    #[error("unsupported format: {0}")]
    UnsupportedFormat(String),
    #[error("payload too large: {size} bytes (max {max})")]
    TooLarge { size: usize, max: usize },
    #[error("encoding error: {0}")]
    EncodingError(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// High-level payload format descriptor
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadFormat {
    /// Raw shellcode (position-independent)
    RawShellcode,
    /// ELF binary wrapped in PIC loader
    ElfPic,
    /// PE binary converted to shellcode (Donut-style)
    PeToShellcode,
    /// .NET assembly loader shellcode
    DotnetLoader,
    /// Reflective DLL injection payload
    ReflectiveDll,
    /// Staged DNS loader (fetches real payload at runtime)
    StagedDnsLoader,
}

/// Metadata for a generated payload
#[derive(Debug, Clone)]
pub struct PayloadMeta {
    pub format: PayloadFormat,
    pub arch: Arch,
    pub size: usize,
    pub encrypted: bool,
    pub encoder_passes: u32,
    pub hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Aarch64,
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::X86 => write!(f, "x86"),
            Arch::X86_64 => write!(f, "x86_64"),
            Arch::Aarch64 => write!(f, "aarch64"),
        }
    }
}

impl std::fmt::Display for PayloadFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayloadFormat::RawShellcode => write!(f, "raw-shellcode"),
            PayloadFormat::ElfPic => write!(f, "elf-pic"),
            PayloadFormat::PeToShellcode => write!(f, "pe-to-shellcode"),
            PayloadFormat::DotnetLoader => write!(f, "dotnet-loader"),
            PayloadFormat::ReflectiveDll => write!(f, "reflective-dll"),
            PayloadFormat::StagedDnsLoader => write!(f, "staged-dns-loader"),
        }
    }
}

/// Detect architecture from ELF or PE headers
pub fn detect_arch(data: &[u8]) -> Result<Arch, PayloadError> {
    if data.len() < 64 {
        return Err(PayloadError::InvalidBinary("too small for header detection".into()));
    }

    // ELF
    if &data[..4] == b"\x7fELF" {
        return match data[18] | ((data[19] as u16) << 8) as u8 {
            0x3E => Ok(Arch::X86_64),  // EM_X86_64
            0x03 => Ok(Arch::X86),      // EM_386
            0xB7 => Ok(Arch::Aarch64),  // EM_AARCH64
            m => Err(PayloadError::UnsupportedFormat(format!("ELF machine type 0x{m:02x}"))),
        };
    }

    // PE
    if &data[..2] == b"MZ" {
        let pe_offset = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
        if pe_offset + 6 > data.len() {
            return Err(PayloadError::InvalidBinary("PE offset out of bounds".into()));
        }
        if &data[pe_offset..pe_offset + 4] != b"PE\0\0" {
            return Err(PayloadError::InvalidBinary("invalid PE signature".into()));
        }
        let machine = u16::from_le_bytes([data[pe_offset + 4], data[pe_offset + 5]]);
        return match machine {
            0x8664 => Ok(Arch::X86_64),  // IMAGE_FILE_MACHINE_AMD64
            0x014C => Ok(Arch::X86),      // IMAGE_FILE_MACHINE_I386
            0xAA64 => Ok(Arch::Aarch64),  // IMAGE_FILE_MACHINE_ARM64
            m => Err(PayloadError::UnsupportedFormat(format!("PE machine type 0x{m:04x}"))),
        };
    }

    Err(PayloadError::UnsupportedFormat("neither ELF nor PE".into()))
}
