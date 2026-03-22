//! Polymorphic and metamorphic encoding engine.
//!
//! Transforms payloads through multiple encoding passes to evade
//! signature-based detection. Each encoding produces a unique output
//! even for identical inputs, while maintaining functional equivalence.

pub mod xor;
pub mod poly;
pub mod entropy;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncoderError {
    #[error("encoding failed: {0}")]
    EncodingFailed(String),
    #[error("decoding failed: {0}")]
    DecodingFailed(String),
    #[error("invalid encoder chain: {0}")]
    InvalidChain(String),
}

/// An encoding pass in the chain
#[derive(Debug, Clone)]
pub enum EncoderPass {
    /// Rolling XOR with random key
    XorRolling { key_size: usize },
    /// XOR with BLAKE3-derived key
    XorDerived { seed: Vec<u8> },
    /// Byte-level substitution cipher (randomized S-box)
    Substitution,
    /// Insert random dead bytes between real data (with length encoding)
    DeadByteInsertion { frequency: f64 },
    /// Reverse chunks of data
    ChunkReverse { chunk_size: usize },
    /// Transpose bytes in blocks
    BlockTranspose { block_size: usize },
    /// Base-encoding layer (base64/base85/base91)
    BaseEncode { variant: BaseVariant },
    /// Entropy normalization (pad to target entropy)
    EntropyNormalize { target: f64 },
}

#[derive(Debug, Clone, Copy)]
pub enum BaseVariant {
    Base64,
    Base85,
}

/// Encoder chain — applies multiple passes in sequence
#[derive(Debug, Clone)]
pub struct EncoderChain {
    pub passes: Vec<EncoderPass>,
}

impl EncoderChain {
    pub fn new() -> Self {
        Self { passes: Vec::new() }
    }

    pub fn add(mut self, pass: EncoderPass) -> Self {
        self.passes.push(pass);
        self
    }

    /// Encode data through the full chain.
    /// Returns the encoded data + metadata needed for decoding.
    pub fn encode(&self, data: &[u8]) -> Result<EncodedPayload, EncoderError> {
        let mut current = data.to_vec();
        let mut decode_keys = Vec::new();

        for pass in &self.passes {
            let (encoded, key) = apply_pass(pass, &current)?;
            current = encoded;
            decode_keys.push(key);
        }

        Ok(EncodedPayload {
            data: current,
            decode_keys,
            num_passes: self.passes.len() as u32,
        })
    }

    /// Decode data by reversing the chain.
    pub fn decode(&self, payload: &EncodedPayload) -> Result<Vec<u8>, EncoderError> {
        let mut current = payload.data.clone();

        // Apply in reverse order
        for (pass, key) in self.passes.iter().zip(payload.decode_keys.iter()).rev() {
            current = reverse_pass(pass, &current, key)?;
        }

        Ok(current)
    }

    /// Preset: light obfuscation (fast, low overhead)
    pub fn light() -> Self {
        Self::new()
            .add(EncoderPass::XorRolling { key_size: 16 })
    }

    /// Preset: medium obfuscation (balanced)
    pub fn medium() -> Self {
        Self::new()
            .add(EncoderPass::XorRolling { key_size: 32 })
            .add(EncoderPass::DeadByteInsertion { frequency: 0.1 })
            .add(EncoderPass::ChunkReverse { chunk_size: 64 })
    }

    /// Preset: heavy obfuscation (maximum evasion, larger output)
    pub fn heavy() -> Self {
        Self::new()
            .add(EncoderPass::Substitution)
            .add(EncoderPass::XorRolling { key_size: 64 })
            .add(EncoderPass::DeadByteInsertion { frequency: 0.2 })
            .add(EncoderPass::BlockTranspose { block_size: 16 })
            .add(EncoderPass::ChunkReverse { chunk_size: 32 })
            .add(EncoderPass::EntropyNormalize { target: 7.5 })
    }
}

impl Default for EncoderChain {
    fn default() -> Self {
        Self::medium()
    }
}

#[derive(Debug, Clone)]
pub struct EncodedPayload {
    pub data: Vec<u8>,
    pub decode_keys: Vec<Vec<u8>>,
    pub num_passes: u32,
}

fn apply_pass(pass: &EncoderPass, data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EncoderError> {
    match pass {
        EncoderPass::XorRolling { key_size } => {
            let key = xor::generate_random_key(*key_size);
            let encoded = xor::xor_rolling(data, &key);
            Ok((encoded, key))
        }
        EncoderPass::XorDerived { seed } => {
            let key = xor::derive_xor_key(seed, data.len());
            let encoded = xor::xor_rolling(data, &key);
            Ok((encoded, seed.clone()))
        }
        EncoderPass::Substitution => {
            let (encoded, sbox) = poly::substitution_encode(data);
            Ok((encoded, sbox))
        }
        EncoderPass::DeadByteInsertion { frequency } => {
            let (encoded, map) = poly::insert_dead_bytes(data, *frequency);
            Ok((encoded, map))
        }
        EncoderPass::ChunkReverse { chunk_size } => {
            let encoded = poly::chunk_reverse(data, *chunk_size);
            Ok((encoded, chunk_size.to_le_bytes().to_vec()))
        }
        EncoderPass::BlockTranspose { block_size } => {
            let encoded = poly::block_transpose(data, *block_size);
            Ok((encoded, block_size.to_le_bytes().to_vec()))
        }
        EncoderPass::BaseEncode { variant } => {
            let encoded = match variant {
                BaseVariant::Base64 => {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(data).into_bytes()
                }
                BaseVariant::Base85 => {
                    poly::base85_encode(data)
                }
            };
            let key = vec![*variant as u8];
            Ok((encoded, key))
        }
        EncoderPass::EntropyNormalize { target } => {
            let (encoded, key) = entropy::normalize(data, *target);
            Ok((encoded, key))
        }
    }
}

fn reverse_pass(pass: &EncoderPass, data: &[u8], key: &[u8]) -> Result<Vec<u8>, EncoderError> {
    match pass {
        EncoderPass::XorRolling { .. } | EncoderPass::XorDerived { .. } => {
            // XOR is its own inverse
            Ok(xor::xor_rolling(data, key))
        }
        EncoderPass::Substitution => {
            Ok(poly::substitution_decode(data, key))
        }
        EncoderPass::DeadByteInsertion { .. } => {
            Ok(poly::remove_dead_bytes(data, key))
        }
        EncoderPass::ChunkReverse { .. } => {
            let chunk_size = if key.len() >= 8 {
                usize::from_le_bytes(key[..8].try_into().unwrap())
            } else {
                64
            };
            Ok(poly::chunk_reverse(data, chunk_size)) // reverse is self-inverse
        }
        EncoderPass::BlockTranspose { .. } => {
            let block_size = if key.len() >= 8 {
                usize::from_le_bytes(key[..8].try_into().unwrap())
            } else {
                16
            };
            Ok(poly::block_transpose_inverse(data, block_size))
        }
        EncoderPass::BaseEncode { .. } => {
            if key.first() == Some(&0) {
                // Base64
                use base64::Engine;
                let s = std::str::from_utf8(data)
                    .map_err(|e| EncoderError::DecodingFailed(e.to_string()))?;
                base64::engine::general_purpose::STANDARD.decode(s)
                    .map_err(|e| EncoderError::DecodingFailed(e.to_string()))
            } else {
                Ok(poly::base85_decode(data))
            }
        }
        EncoderPass::EntropyNormalize { .. } => {
            entropy::denormalize(data, key)
                .map_err(|e| EncoderError::DecodingFailed(e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_light_chain_roundtrip() {
        let chain = EncoderChain::light();
        let data = b"Hello, this is a test payload for encoding";
        let encoded = chain.encode(data).unwrap();
        assert_ne!(&encoded.data, data);
        let decoded = chain.decode(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_medium_chain_roundtrip() {
        let chain = EncoderChain::medium();
        let data = b"Medium obfuscation test with more passes";
        let encoded = chain.encode(data).unwrap();
        assert_ne!(&encoded.data, data);
        let decoded = chain.decode(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }

    #[test]
    fn test_polymorphic_uniqueness() {
        let chain = EncoderChain::light();
        let data = b"same input data";
        let e1 = chain.encode(data).unwrap();
        let e2 = chain.encode(data).unwrap();
        // Each encoding should produce different output (random key)
        assert_ne!(e1.data, e2.data);
    }

    #[test]
    fn test_custom_chain() {
        let chain = EncoderChain::new()
            .add(EncoderPass::XorRolling { key_size: 8 })
            .add(EncoderPass::ChunkReverse { chunk_size: 4 });
        let data = b"custom chain test";
        let encoded = chain.encode(data).unwrap();
        let decoded = chain.decode(&encoded).unwrap();
        assert_eq!(&decoded, data);
    }
}
