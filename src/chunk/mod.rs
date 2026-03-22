use crate::crypto;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChunkError {
    #[error("Compression failed: {0}")]
    CompressionFailed(String),
    #[error("Decompression failed: {0}")]
    DecompressionFailed(String),
}

/// Maximum payload size per TXT record after encoding overhead.
/// DNS TXT records: max 255 bytes per character-string, multiple strings per RRset.
/// Cloudflare allows ~2048 bytes per TXT record value.
/// After base64 encoding (4/3 expansion) and JSON overhead, target ~1400 bytes raw per chunk.
pub const MAX_CHUNK_RAW: usize = 1400;

/// Maximum raw data size before compression/encryption that can fit in MAX_CHUNK_RAW.
/// Accounts for: 12-byte nonce + 16-byte auth tag + base64 expansion (~4/3).
/// Conservative estimate: 1400 * 3/4 - 28 ≈ 1022 bytes per chunk pre-encryption.
/// But since we compress first then encrypt the whole blob, the real limit is
/// the size of the encrypted+compressed output.
pub const CHUNK_SPLIT_SIZE: usize = 1400;

/// A content-addressed chunk ready for DNS storage
#[derive(Debug, Clone)]
pub struct Chunk {
    /// BLAKE3 hash of the PLAINTEXT content — used for dedup (pre-encryption)
    pub content_hash: String,
    /// BLAKE3 hash of the encoded payload — used as DNS label (post-encryption)
    pub storage_hash: String,
    /// The encoded payload to store in the TXT record
    pub encoded: String,
    /// Chunk index in the file
    pub index: u32,
}

/// Split plaintext data into encrypted, compressed, base64-encoded chunks.
///
/// Dedup strategy:
///   1. Split raw plaintext into fixed-size blocks
///   2. Hash each block BEFORE encryption → content_hash (for dedup lookups)
///   3. Compress + encrypt each block
///   4. Hash the encrypted output → storage_hash (for DNS label)
///   5. Base64-encode for TXT record storage
///
/// This means identical plaintext blocks produce the same content_hash even
/// though they produce different ciphertexts (due to random nonces).
/// The storage layer uses content_hash for dedup decisions.
/// Detect if data is likely text (high compressibility) or binary (low compressibility).
/// Returns an appropriate zstd compression level.
///
/// Strategy:
///   - Text/JSON/XML/code: level 15 (aggressive, great ratio for compressible data)
///   - Random/encrypted/binary: level 1 (fast, won't waste CPU on incompressible data)
///   - Mixed/unknown: level 3 (balanced default)
fn adaptive_zstd_level(data: &[u8]) -> i32 {
    if data.is_empty() {
        return 1;
    }

    // Sample first 256 bytes (or less)
    let sample = &data[..data.len().min(256)];

    // Count bytes that are printable ASCII, whitespace, or common text
    let text_chars = sample.iter().filter(|&&b| {
        b.is_ascii_graphic() || b.is_ascii_whitespace()
    }).count();

    let text_ratio = text_chars as f64 / sample.len() as f64;

    // Count unique byte values — high entropy = incompressible
    let mut seen = [false; 256];
    for &b in sample {
        seen[b as usize] = true;
    }
    let unique = seen.iter().filter(|&&v| v).count();
    let entropy_ratio = unique as f64 / sample.len().min(256) as f64;

    if text_ratio > 0.85 {
        // Highly text-like: aggressive compression
        15
    } else if entropy_ratio > 0.9 && text_ratio < 0.3 {
        // High entropy, low text: likely binary/encrypted — minimal compression
        1
    } else {
        // Mixed content
        3
    }
}

pub fn chunkify(
    data: &[u8],
    encryption_key: &crypto::EncryptionKey,
) -> Result<Vec<Chunk>, Box<dyn std::error::Error>> {
    if data.is_empty() {
        let compressed = zstd::encode_all(&[][..], 1)
            .map_err(|e| ChunkError::CompressionFailed(e.to_string()))?;
        let encrypted = crypto::encrypt(encryption_key, &compressed)?;

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        let content_hash = crypto::content_hash(&[]);
        let storage_hash = crypto::content_hash(&encrypted);

        return Ok(vec![Chunk { content_hash, storage_hash, encoded, index: 0 }]);
    }

    // Detect optimal compression level from file content
    let zstd_level = adaptive_zstd_level(data);

    let blocks: Vec<&[u8]> = data.chunks(CHUNK_SPLIT_SIZE).collect();
    let mut chunks = Vec::with_capacity(blocks.len());

    for (i, block) in blocks.iter().enumerate() {
        let content_hash = crypto::content_hash(block);

        let compressed = zstd::encode_all(*block, zstd_level)
            .map_err(|e| ChunkError::CompressionFailed(e.to_string()))?;

        let encrypted = crypto::encrypt(encryption_key, &compressed)?;

        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        let storage_hash = crypto::content_hash(&encrypted);

        chunks.push(Chunk { content_hash, storage_hash, encoded, index: i as u32 });
    }

    Ok(chunks)
}

/// Reassemble chunks back into plaintext.
/// Each chunk is independently: base64 → decrypt → decompress.
pub fn dechunkify(
    encoded_chunks: &[String],
    encryption_key: &crypto::EncryptionKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use base64::Engine;
    let mut result = Vec::new();

    for chunk in encoded_chunks {
        // Step 1: Base64 decode
        let encrypted = base64::engine::general_purpose::STANDARD.decode(chunk)?;

        // Step 2: Decrypt
        let compressed = crypto::decrypt(encryption_key, &encrypted)?;

        // Step 3: Decompress
        let data = zstd::decode_all(compressed.as_slice())
            .map_err(|e| ChunkError::DecompressionFailed(e.to_string()))?;

        result.extend_from_slice(&data);
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_roundtrip() {
        let key = crypto::generate_key();
        let data = b"The filesystem that should not exist but does.";

        let chunks = chunkify(data, &key).unwrap();
        assert!(!chunks.is_empty());

        let encoded: Vec<String> = chunks.iter().map(|c| c.encoded.clone()).collect();
        let recovered = dechunkify(&encoded, &key).unwrap();
        assert_eq!(data.to_vec(), recovered);
    }

    #[test]
    fn test_empty_data() {
        let key = crypto::generate_key();
        let chunks = chunkify(b"", &key).unwrap();
        assert_eq!(chunks.len(), 1);

        let encoded: Vec<String> = chunks.iter().map(|c| c.encoded.clone()).collect();
        let recovered = dechunkify(&encoded, &key).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_large_data_multiple_chunks() {
        let key = crypto::generate_key();
        let data = vec![0x42u8; CHUNK_SPLIT_SIZE * 5]; // Force multiple chunks

        let chunks = chunkify(&data, &key).unwrap();
        assert_eq!(chunks.len(), 5, "Should produce exactly 5 chunks");

        // Verify chunk indices
        for (i, c) in chunks.iter().enumerate() {
            assert_eq!(c.index, i as u32);
        }

        let encoded: Vec<String> = chunks.iter().map(|c| c.encoded.clone()).collect();
        let recovered = dechunkify(&encoded, &key).unwrap();
        assert_eq!(data, recovered);
    }

    #[test]
    fn test_dedup_content_hash_stable() {
        // CRITICAL: The same plaintext block must produce the same content_hash
        // even with different encryption nonces (different ciphertexts)
        let key = crypto::generate_key();
        let data = b"this block will be deduped";

        let chunks1 = chunkify(data, &key).unwrap();
        let chunks2 = chunkify(data, &key).unwrap();

        // content_hash (pre-encryption) MUST match
        assert_eq!(
            chunks1[0].content_hash, chunks2[0].content_hash,
            "Content hashes must be identical for same plaintext"
        );

        // storage_hash (post-encryption) will differ due to random nonces
        assert_ne!(
            chunks1[0].storage_hash, chunks2[0].storage_hash,
            "Storage hashes should differ (random nonces)"
        );

        // But both decrypt to the same data
        let r1 = dechunkify(&[chunks1[0].encoded.clone()], &key).unwrap();
        let r2 = dechunkify(&[chunks2[0].encoded.clone()], &key).unwrap();
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_dedup_across_files() {
        // Two files sharing identical blocks should have matching content_hashes
        let key = crypto::generate_key();
        let shared_block = vec![0xAA; CHUNK_SPLIT_SIZE];
        let unique_block = vec![0xBB; CHUNK_SPLIT_SIZE];

        let mut file_a = shared_block.clone();
        file_a.extend_from_slice(&unique_block);

        let mut file_b = shared_block.clone();
        file_b.extend_from_slice(&vec![0xCC; CHUNK_SPLIT_SIZE]);

        let chunks_a = chunkify(&file_a, &key).unwrap();
        let chunks_b = chunkify(&file_b, &key).unwrap();

        // First chunk of both files is the same plaintext → same content_hash
        assert_eq!(chunks_a[0].content_hash, chunks_b[0].content_hash);

        // Second chunks differ
        assert_ne!(chunks_a[1].content_hash, chunks_b[1].content_hash);
    }

    #[test]
    fn test_encoded_fits_txt_record() {
        // Verify no chunk exceeds Cloudflare's TXT record limit (~2048 bytes)
        let key = crypto::generate_key();
        let data = vec![0xFF; CHUNK_SPLIT_SIZE * 3];

        let chunks = chunkify(&data, &key).unwrap();
        for c in &chunks {
            assert!(
                c.encoded.len() <= 2048,
                "Encoded chunk {} is {} bytes (max 2048)",
                c.index,
                c.encoded.len()
            );
        }
    }

    #[test]
    fn test_various_sizes() {
        let key = crypto::generate_key();
        for size in [1, 10, 100, 255, 1000, 1399, 1400, 1401, 5000, 10000] {
            let data = vec![0x42u8; size];
            let chunks = chunkify(&data, &key).unwrap();
            let encoded: Vec<String> = chunks.iter().map(|c| c.encoded.clone()).collect();
            let recovered = dechunkify(&encoded, &key).unwrap();
            assert_eq!(data, recovered, "Roundtrip failed for size {}", size);
        }
    }

    #[test]
    fn test_adaptive_compression_text() {
        // Pure ASCII text → should select high compression level
        let level = adaptive_zstd_level(b"Hello world, this is a text file with lots of ASCII content.\n");
        assert!(level >= 10, "Text should get high compression level, got {}", level);
    }

    #[test]
    fn test_adaptive_compression_binary() {
        // Random-looking binary data → low level
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let level = adaptive_zstd_level(&data);
        assert!(level <= 3, "Binary should get low compression level, got {}", level);
    }

    #[test]
    fn test_adaptive_compression_empty() {
        assert_eq!(adaptive_zstd_level(b""), 1);
    }

    #[test]
    fn test_text_compresses_smaller_than_binary() {
        let key = crypto::generate_key();

        // Repetitive text → should compress well
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(30);
        let text_chunks = chunkify(text.as_bytes(), &key).unwrap();

        // Random binary → poor compression
        let binary: Vec<u8> = (0..text.len()).map(|i| ((i * 7 + 13) % 256) as u8).collect();
        let bin_chunks = chunkify(&binary, &key).unwrap();

        let text_size: usize = text_chunks.iter().map(|c| c.encoded.len()).sum();
        let bin_size: usize = bin_chunks.iter().map(|c| c.encoded.len()).sum();

        assert!(
            text_size < bin_size,
            "Text ({} bytes encoded) should be smaller than binary ({} bytes)",
            text_size, bin_size
        );
    }
}
