//! Polymorphic encoding primitives: substitution, dead byte insertion,
//! chunk reversal, block transposition, and base85 encoding.

use rand::Rng;

/// Random substitution cipher using a randomized S-box (256-byte permutation).
/// Returns (encoded_data, sbox_bytes) where sbox_bytes is the 256-byte S-box.
pub fn substitution_encode(data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sbox = generate_sbox();
    let encoded: Vec<u8> = data.iter().map(|&b| sbox[b as usize]).collect();
    (encoded, sbox.to_vec())
}

/// Decode using the inverse S-box
pub fn substitution_decode(data: &[u8], sbox: &[u8]) -> Vec<u8> {
    if sbox.len() != 256 {
        return data.to_vec();
    }
    // Build inverse S-box
    let mut inv_sbox = [0u8; 256];
    for (i, &v) in sbox.iter().enumerate() {
        inv_sbox[v as usize] = i as u8;
    }
    data.iter().map(|&b| inv_sbox[b as usize]).collect()
}

/// Generate a random 256-byte S-box (Fisher-Yates shuffle)
fn generate_sbox() -> [u8; 256] {
    let mut sbox: [u8; 256] = std::array::from_fn(|i| i as u8);
    let mut rng = rand::thread_rng();
    for i in (1..256).rev() {
        let j = rng.gen_range(0..=i);
        sbox.swap(i, j);
    }
    sbox
}

/// Insert random dead bytes between real data bytes.
/// Returns (encoded_data, bitmap) where bitmap encodes which bytes are real.
/// `frequency` is the probability of inserting a dead byte after each real byte.
pub fn insert_dead_bytes(data: &[u8], frequency: f64) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut encoded = Vec::with_capacity((data.len() as f64 * (1.0 + frequency)) as usize + 16);
    let mut bitmap = Vec::new(); // packed bits: 1 = real, 0 = dead

    let mut bit_buffer = 0u8;
    let mut bit_count = 0;

    for &byte in data {
        // Mark as real
        bit_buffer |= 1 << bit_count;
        bit_count += 1;
        if bit_count == 8 {
            bitmap.push(bit_buffer);
            bit_buffer = 0;
            bit_count = 0;
        }
        encoded.push(byte);

        // Maybe insert dead byte
        if rng.gen_bool(frequency.clamp(0.0, 0.9)) {
            bit_count += 1; // bit stays 0 (dead)
            if bit_count == 8 {
                bitmap.push(bit_buffer);
                bit_buffer = 0;
                bit_count = 0;
            }
            encoded.push(rng.gen()); // random dead byte
        }
    }

    // Flush remaining bits
    if bit_count > 0 {
        bitmap.push(bit_buffer);
    }

    // Prepend original length for reliable decoding
    let orig_len = data.len() as u32;
    let mut key = orig_len.to_le_bytes().to_vec();
    key.extend_from_slice(&bitmap);

    (encoded, key)
}

/// Remove dead bytes using the bitmap key
pub fn remove_dead_bytes(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.len() < 4 {
        return data.to_vec();
    }

    let orig_len = u32::from_le_bytes(key[..4].try_into().unwrap()) as usize;
    let bitmap = &key[4..];

    let mut result = Vec::with_capacity(orig_len);
    let mut data_idx = 0;

    for (byte_idx, &bits) in bitmap.iter().enumerate() {
        for bit in 0..8 {
            if data_idx >= data.len() {
                break;
            }
            if (bits >> bit) & 1 == 1 {
                result.push(data[data_idx]);
            }
            data_idx += 1;

            if byte_idx * 8 + bit + 1 >= data.len() {
                break;
            }
        }
    }

    result.truncate(orig_len);
    result
}

/// Reverse data in fixed-size chunks (self-inverse)
pub fn chunk_reverse(data: &[u8], chunk_size: usize) -> Vec<u8> {
    if chunk_size == 0 {
        return data.to_vec();
    }
    let mut result = Vec::with_capacity(data.len());
    for chunk in data.chunks(chunk_size) {
        result.extend(chunk.iter().rev());
    }
    result
}

/// Transpose bytes within blocks (interleave)
/// For a block [a,b,c,d,e,f,g,h] with block_size=8, stride=2:
/// → [a,c,e,g,b,d,f,h]
pub fn block_transpose(data: &[u8], block_size: usize) -> Vec<u8> {
    if block_size < 2 {
        return data.to_vec();
    }

    let mut result = Vec::with_capacity(data.len());
    let stride = 2; // fixed stride for simplicity

    for block in data.chunks(block_size) {
        // Even indices first, then odd
        for i in (0..block.len()).step_by(stride) {
            result.push(block[i]);
        }
        for i in (1..block.len()).step_by(stride) {
            result.push(block[i]);
        }
    }

    result
}

/// Inverse block transpose
pub fn block_transpose_inverse(data: &[u8], block_size: usize) -> Vec<u8> {
    if block_size < 2 {
        return data.to_vec();
    }

    let mut result = Vec::with_capacity(data.len());

    for block in data.chunks(block_size) {
        let even_count = (block.len() + 1) / 2;
        let odd_count = block.len() / 2;
        let evens = &block[..even_count];
        let odds = &block[even_count..even_count + odd_count];

        let mut reconstructed = vec![0u8; block.len()];
        for (i, &b) in evens.iter().enumerate() {
            reconstructed[i * 2] = b;
        }
        for (i, &b) in odds.iter().enumerate() {
            reconstructed[i * 2 + 1] = b;
        }
        result.extend_from_slice(&reconstructed);
    }

    result
}

/// Base85 encoding (ASCII85 variant) — more compact than base64
pub fn base85_encode(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    for chunk in data.chunks(4) {
        let mut value = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            value |= (b as u32) << (24 - i * 8);
        }

        let mut encoded = [0u8; 5];
        for i in (0..5).rev() {
            encoded[i] = (value % 85) as u8 + 33; // ASCII printable range
            value /= 85;
        }

        // Only write as many encoded chars as needed for partial chunks
        let chars = match chunk.len() {
            1 => 2,
            2 => 3,
            3 => 4,
            _ => 5,
        };
        result.extend_from_slice(&encoded[..chars]);
    }

    result
}

/// Base85 decoding
pub fn base85_decode(data: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();

    for chunk in data.chunks(5) {
        let mut value = 0u32;
        for &b in chunk {
            value = value * 85 + (b.wrapping_sub(33)) as u32;
        }

        // Pad with 'u' (84) for partial groups
        for _ in chunk.len()..5 {
            value = value * 85 + 84;
        }

        let bytes = value.to_be_bytes();
        let out_bytes = match chunk.len() {
            2 => 1,
            3 => 2,
            4 => 3,
            _ => 4,
        };
        result.extend_from_slice(&bytes[..out_bytes]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_substitution_roundtrip() {
        let data = b"substitution cipher test";
        let (encoded, sbox) = substitution_encode(data);
        assert_ne!(&encoded, data);
        let decoded = substitution_decode(&encoded, &sbox);
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_dead_byte_insertion_roundtrip() {
        let data = b"dead byte insertion test payload";
        let (encoded, key) = insert_dead_bytes(data, 0.3);
        assert!(encoded.len() >= data.len());
        let decoded = remove_dead_bytes(&encoded, &key);
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_chunk_reverse_self_inverse() {
        let data = b"0123456789abcdef";
        let reversed = chunk_reverse(data, 4);
        let restored = chunk_reverse(&reversed, 4);
        assert_eq!(&restored, data);
    }

    #[test]
    fn test_block_transpose_roundtrip() {
        let data = b"abcdefghijklmnop";
        let transposed = block_transpose(data, 8);
        assert_ne!(&transposed, data);
        let restored = block_transpose_inverse(&transposed, 8);
        assert_eq!(&restored, data);
    }

    #[test]
    fn test_base85_roundtrip() {
        let data = b"base85 encoding test data";
        let encoded = base85_encode(data);
        let decoded = base85_decode(&encoded);
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_sbox_is_permutation() {
        let sbox = generate_sbox();
        let mut sorted = sbox.to_vec();
        sorted.sort();
        let expected: Vec<u8> = (0..=255).collect();
        assert_eq!(sorted, expected);
    }
}
