//! HMAC-SHA256 key types for JWT token signing.
//!
//! This module provides types for managing HMAC-SHA256 symmetric keys used in
//! JWT token signing and verification. HMAC-SHA256 is widely supported and
//! simpler to use than asymmetric algorithms like EdDSA.
//!
//! # Design Principles
//!
//! - **No secret leakage**: Secret keys are never exposed unnecessarily
//! - **Deterministic encoding**: Keys always encode to the same format
//! - **Clone-safe**: Keys can be safely cloned for use in multiple services
//! - **Simple and compatible**: Uses standard HMAC-SHA256 widely supported by JWT libraries

use jsonwebtoken::{DecodingKey, EncodingKey};
use rand::RngExt;

/// Default key size for HMAC-SHA256 (256 bits = 32 bytes).
pub const HMAC_KEY_SIZE: usize = 32;

/// An HMAC-SHA256 symmetric key for token signing and verification.
///
/// HMAC uses the same key for both signing and verification (symmetric cryptography).
/// The key is wrapped to prevent accidental exposure.
#[derive(Debug, Clone)]
pub struct HmacKey {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    key_bytes: [u8; HMAC_KEY_SIZE],
}

impl HmacKey {
    /// Create a new HMAC key from raw bytes.
    ///
    /// The key must be exactly 32 bytes (256 bits) for HMAC-SHA256.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not exactly 32 bytes.
    pub fn from_bytes(key: &[u8]) -> Result<Self, String> {
        if key.len() != HMAC_KEY_SIZE {
            return Err(format!(
                "Invalid key length: expected {} bytes, got {}",
                HMAC_KEY_SIZE,
                key.len()
            ));
        }

        // For HMAC-SHA256, we use the same bytes for both encoding and decoding
        let encoding_key = EncodingKey::from_secret(key);
        let decoding_key = DecodingKey::from_secret(key);
        
        let mut key_bytes = [0u8; HMAC_KEY_SIZE];
        key_bytes.copy_from_slice(key);

        Ok(Self {
            encoding_key,
            decoding_key,
            key_bytes,
        })
    }

    /// Generate a new random HMAC key using cryptographically secure RNG.
    ///
    /// Uses the operating system's cryptographically secure random number generator.
    pub fn generate() -> Result<Self, String> {
        let mut key = [0u8; HMAC_KEY_SIZE];
        rand::rng().fill(&mut key);
        
        Self::from_bytes(&key)
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> [u8; HMAC_KEY_SIZE] {
        self.key_bytes
    }

    /// Encode the key to base64 (URL-safe, no padding).
    pub fn to_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(&self.key_bytes)
    }

    /// Create an HMAC key from base64-encoded bytes.
    pub fn from_base64(encoded: &str) -> Result<Self, String> {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        
        let bytes = URL_SAFE_NO_PAD.decode(encoded)
            .map_err(|e| format!("Failed to decode base64: {}", e))?;

        Self::from_bytes(&bytes)
    }

    /// Get a reference to the encoding key (for signing).
    pub fn encoding_key(&self) -> &EncodingKey {
        &self.encoding_key
    }

    /// Get a reference to the decoding key (for verification).
    pub fn decoding_key(&self) -> &DecodingKey {
        &self.decoding_key
    }
}
