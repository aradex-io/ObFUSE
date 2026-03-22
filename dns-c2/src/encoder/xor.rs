//! XOR-based encoding primitives with key derivation.

use rand::RngCore;

/// Generate a cryptographically random XOR key
pub fn generate_random_key(size: usize) -> Vec<u8> {
    let mut key = vec![0u8; size];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Derive a deterministic XOR key from a seed using BLAKE3
pub fn derive_xor_key(seed: &[u8], length: usize) -> Vec<u8> {
    let mut key = vec![0u8; length];
    let mut hasher = blake3::Hasher::new_keyed(&[0u8; 32]);
    hasher.update(b"obfuse-xor-key-v1:");
    hasher.update(seed);

    // Use BLAKE3's XOF (extendable output) mode to generate arbitrary-length key
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut key);
    key
}

/// Rolling XOR encode/decode (self-inverse with same key)
pub fn xor_rolling(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

/// Additive feedback XOR — each byte depends on the previous encrypted byte.
/// More resistant to known-plaintext attacks than simple rolling XOR.
pub fn xor_feedback_encode(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() || data.is_empty() {
        return data.to_vec();
    }

    let mut output = Vec::with_capacity(data.len());
    let mut feedback = key[0];

    for (i, &b) in data.iter().enumerate() {
        let encoded = b ^ key[i % key.len()] ^ feedback;
        feedback = encoded;
        output.push(encoded);
    }

    output
}

/// Decode additive feedback XOR
pub fn xor_feedback_decode(data: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() || data.is_empty() {
        return data.to_vec();
    }

    let mut output = Vec::with_capacity(data.len());
    let mut feedback = key[0];

    for (i, &b) in data.iter().enumerate() {
        let decoded = b ^ key[i % key.len()] ^ feedback;
        feedback = b; // feedback uses the encrypted byte
        output.push(decoded);
    }

    output
}

/// Multi-layer XOR: apply multiple XOR keys in sequence
pub fn xor_multilayer(data: &[u8], keys: &[Vec<u8>]) -> Vec<u8> {
    let mut current = data.to_vec();
    for key in keys {
        current = xor_rolling(&current, key);
    }
    current
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rolling_xor_roundtrip() {
        let data = b"test data for XOR encoding";
        let key = generate_random_key(16);
        let encoded = xor_rolling(data, &key);
        assert_ne!(&encoded, data);
        let decoded = xor_rolling(&encoded, &key);
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_feedback_xor_roundtrip() {
        let data = b"feedback XOR test payload";
        let key = generate_random_key(8);
        let encoded = xor_feedback_encode(data, &key);
        assert_ne!(&encoded, data);
        let decoded = xor_feedback_decode(&encoded, &key);
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_derived_key_determinism() {
        let seed = b"my secret seed";
        let k1 = derive_xor_key(seed, 32);
        let k2 = derive_xor_key(seed, 32);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_multilayer_xor() {
        let data = b"multilayer test";
        let keys: Vec<Vec<u8>> = (0..3).map(|_| generate_random_key(16)).collect();
        let encoded = xor_multilayer(data, &keys);
        // Decode by applying keys in reverse
        let rev_keys: Vec<Vec<u8>> = keys.into_iter().rev().collect();
        let decoded = xor_multilayer(&encoded, &rev_keys);
        assert_eq!(&decoded, data);
    }
}
