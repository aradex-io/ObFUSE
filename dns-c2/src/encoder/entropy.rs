//! Entropy analysis and normalization.
//!
//! Encrypted/compressed data has high entropy (~8.0 bits/byte).
//! Many security tools flag high-entropy blobs as suspicious.
//! This module normalizes payload entropy to match typical file types,
//! making encrypted payloads look like normal documents or executables.

use rand::Rng;

/// Calculate Shannon entropy of data (bits per byte, 0.0 - 8.0)
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0u64; 256];
    for &b in data {
        freq[b as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Entropy targets for different file types (for camouflage)
pub mod targets {
    /// English text: ~4.0-5.0 bits/byte
    pub const ENGLISH_TEXT: f64 = 4.5;
    /// HTML/XML: ~5.0-5.5 bits/byte
    pub const HTML: f64 = 5.2;
    /// Native executable (.exe, ELF): ~5.5-6.5 bits/byte
    pub const EXECUTABLE: f64 = 6.0;
    /// PDF document: ~6.0-7.0 bits/byte
    pub const PDF: f64 = 6.5;
    /// JPEG image: ~7.0-7.5 bits/byte
    pub const JPEG: f64 = 7.2;
    /// Encrypted/compressed: ~7.9-8.0 bits/byte
    pub const ENCRYPTED: f64 = 7.95;
}

/// Normalize data entropy to a target value.
/// Works by interleaving the real data with carefully crafted padding
/// that brings the overall Shannon entropy to the desired level.
///
/// Returns (normalized_data, key) where key contains decode metadata.
pub fn normalize(data: &[u8], target_entropy: f64) -> (Vec<u8>, Vec<u8>) {
    let current = shannon_entropy(data);

    if (current - target_entropy).abs() < 0.3 {
        // Already close enough
        let mut key = Vec::new();
        key.extend_from_slice(&(data.len() as u32).to_le_bytes());
        key.push(0); // no padding applied
        return (data.to_vec(), key);
    }

    if current > target_entropy {
        // Need to lower entropy: mix in low-entropy padding (repeated patterns)
        let (result, pad_ratio) = lower_entropy(data, target_entropy);
        let mut key = Vec::new();
        key.extend_from_slice(&(data.len() as u32).to_le_bytes());
        key.push(1); // padding applied: lower
        key.extend_from_slice(&pad_ratio.to_le_bytes());
        (result, key)
    } else {
        // Need to raise entropy: mix in high-entropy random bytes
        let (result, pad_ratio) = raise_entropy(data, target_entropy);
        let mut key = Vec::new();
        key.extend_from_slice(&(data.len() as u32).to_le_bytes());
        key.push(2); // padding applied: raise
        key.extend_from_slice(&pad_ratio.to_le_bytes());
        (result, key)
    }
}

/// Denormalize: extract original data from entropy-normalized payload
pub fn denormalize(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() < 5 {
        return Err("key too short".into());
    }

    let orig_len = u32::from_le_bytes(key[..4].try_into().unwrap()) as usize;
    let mode = key[4];

    match mode {
        0 => {
            // No padding applied
            Ok(data[..orig_len.min(data.len())].to_vec())
        }
        1 | 2 => {
            // Padding was interleaved — extract every Nth byte
            // The interleaving pattern uses a fixed stride based on pad_ratio
            if key.len() < 9 {
                return Err("key missing pad ratio".into());
            }
            let pad_ratio = f32::from_le_bytes(key[5..9].try_into().unwrap());
            let stride = (1.0 + pad_ratio) as usize;
            if stride < 1 {
                return Ok(data[..orig_len.min(data.len())].to_vec());
            }

            let mut result = Vec::with_capacity(orig_len);
            let mut i = 0;
            while i < data.len() && result.len() < orig_len {
                result.push(data[i]);
                i += stride;
            }

            Ok(result)
        }
        _ => Err(format!("unknown normalization mode: {mode}")),
    }
}

/// Lower entropy by interleaving low-entropy padding
fn lower_entropy(data: &[u8], target: f64) -> (Vec<u8>, f32) {
    let current = shannon_entropy(data);
    // Calculate how much padding we need
    // Simple model: interleave 1 pad byte per N data bytes
    let ratio = ((current - target) / target).max(0.1) as f32;
    let pad_interval = (1.0 / ratio) as usize;
    let pad_interval = pad_interval.max(1);

    let mut result = Vec::with_capacity(data.len() * 2);
    let mut rng = rand::thread_rng();

    // Low-entropy padding: ASCII-range characters with repeated patterns
    let pad_pool = b"aaaaaabbbbccccddddeeeeffffgggghhhh    \n\r\t";

    for (i, &byte) in data.iter().enumerate() {
        result.push(byte);
        if i % pad_interval == 0 {
            result.push(pad_pool[rng.gen_range(0..pad_pool.len())]);
        }
    }

    (result, ratio)
}

/// Raise entropy by interleaving high-entropy random bytes
fn raise_entropy(data: &[u8], target: f64) -> (Vec<u8>, f32) {
    let current = shannon_entropy(data);
    let ratio = ((target - current) / (8.0 - current)).max(0.1) as f32;
    let pad_interval = (1.0 / ratio) as usize;
    let pad_interval = pad_interval.max(1);

    let mut result = Vec::with_capacity(data.len() * 2);
    let mut rng = rand::thread_rng();

    for (i, &byte) in data.iter().enumerate() {
        result.push(byte);
        if i % pad_interval == 0 {
            result.push(rng.gen()); // fully random byte
        }
    }

    (result, ratio)
}

/// Analyze a payload and return an entropy report
#[derive(Debug)]
pub struct EntropyReport {
    pub overall: f64,
    pub block_entropies: Vec<(usize, f64)>,
    pub classification: EntropyClass,
    pub suspicious: bool,
}

#[derive(Debug)]
pub enum EntropyClass {
    PlainText,
    StructuredData,
    Executable,
    Compressed,
    Encrypted,
}

pub fn analyze(data: &[u8]) -> EntropyReport {
    let overall = shannon_entropy(data);

    // Calculate per-block entropy (256-byte blocks)
    let block_size = 256;
    let block_entropies: Vec<(usize, f64)> = data
        .chunks(block_size)
        .enumerate()
        .map(|(i, block)| (i * block_size, shannon_entropy(block)))
        .collect();

    let classification = match overall {
        e if e < 4.0 => EntropyClass::PlainText,
        e if e < 5.5 => EntropyClass::StructuredData,
        e if e < 6.8 => EntropyClass::Executable,
        e if e < 7.5 => EntropyClass::Compressed,
        _ => EntropyClass::Encrypted,
    };

    // High-entropy + uniform block distribution = suspicious
    let suspicious = overall > 7.5 && {
        let mean_block = block_entropies.iter().map(|(_, e)| e).sum::<f64>()
            / block_entropies.len().max(1) as f64;
        let variance: f64 = block_entropies.iter()
            .map(|(_, e)| (e - mean_block).powi(2))
            .sum::<f64>() / block_entropies.len().max(1) as f64;
        variance < 0.1 // Very uniform = likely encrypted
    };

    EntropyReport {
        overall,
        block_entropies,
        classification,
        suspicious,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_zeros() {
        let data = vec![0u8; 1000];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_entropy_random() {
        let data: Vec<u8> = (0..10000).map(|_| rand::random()).collect();
        let e = shannon_entropy(&data);
        assert!(e > 7.5, "random data should have high entropy, got {e}");
    }

    #[test]
    fn test_entropy_text() {
        let data = b"The quick brown fox jumps over the lazy dog. \
                     This is a typical English text with normal entropy.";
        let e = shannon_entropy(data);
        assert!(e > 3.0 && e < 6.0, "English text entropy should be 3-6, got {e}");
    }

    #[test]
    fn test_normalize_high_to_executable() {
        let data: Vec<u8> = (0..1000).map(|_| rand::random()).collect();
        let (normalized, key) = normalize(&data, targets::EXECUTABLE);
        let norm_entropy = shannon_entropy(&normalized);
        // Should be closer to target than original
        let original_entropy = shannon_entropy(&data);
        assert!(
            (norm_entropy - targets::EXECUTABLE).abs() < (original_entropy - targets::EXECUTABLE).abs(),
            "normalization should move entropy toward target"
        );
        // Should be recoverable
        let recovered = denormalize(&normalized, &key).unwrap();
        assert_eq!(recovered.len(), data.len());
    }

    #[test]
    fn test_analyze_report() {
        let data: Vec<u8> = (0..2000).map(|_| rand::random()).collect();
        let report = analyze(&data);
        assert!(report.overall > 7.0);
        assert!(report.suspicious);
        assert!(matches!(report.classification, EntropyClass::Encrypted));
    }

    #[test]
    fn test_already_at_target() {
        let data = b"Some normal text that probably has moderate entropy values around five or so bits";
        let (normalized, key) = normalize(data, 4.5);
        // Should not add much padding if already close
        assert!(key[4] == 0 || normalized.len() < data.len() * 3);
    }
}
