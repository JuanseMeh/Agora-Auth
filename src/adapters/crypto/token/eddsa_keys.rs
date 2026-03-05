//! Ed25519 key types for JWT token signing.
//!
//! This module provides types for managing Ed25519 asymmetric keys used in
//! JWT token signing and verification. Ed25519 is an elliptic curve signature
//! scheme that offers better security and performance than HMAC.
//!
//! # Design Principles
//!
//! - **No secret leakage**: Private keys are never exposed unnecessarily
//! - **Deterministic encoding**: Keys always encode to the same format
//! - **Clone-safe**: Keys can be safely cloned for use in multiple services
//! - **Secure by default**: Uses cryptographically secure key generation

use ed25519_dalek::{SigningKey as DalekSigningKey, VerifyingKey};
use jsonwebtoken::{DecodingKey, EncodingKey};
use pkcs8::EncodePrivateKey;
use ring::rand::{SecureRandom, SystemRandom};

/// Default key size for Ed25519 (256 bits = 32 bytes).
pub const ED25519_KEY_SIZE: usize = 32;

/// An Ed25519 asymmetric key pair for token signing and verification.
///
/// Ed25519 uses a private key for signing and a public key for verification
/// (asymmetric cryptography). The keys are stored as raw bytes to allow cloning.
#[derive(Debug, Clone)]
pub struct EddsaKey {
    /// The dalek signing key from which everything is derived.
    signing_key: DalekSigningKey,
}

impl EddsaKey {
    /// Create a new Ed25519 key pair from raw private key bytes.
    ///
    /// The private key must be exactly 32 bytes (256 bits).
    ///
    /// # Errors
    ///
    /// Returns an error if the key is not exactly 32 bytes or if key generation fails.
    pub fn from_private_key_bytes(private_key: &[u8]) -> Result<Self, String> {
        if private_key.len() != ED25519_KEY_SIZE {
            return Err(format!(
                "Invalid private key length: expected {} bytes, got {}",
                ED25519_KEY_SIZE,
                private_key.len()
            ));
        }

        // Create dalek signing key from the raw bytes
        let signing_key = DalekSigningKey::from_bytes(
            private_key.try_into().map_err(|_| "Invalid key length")?
        );

        Ok(Self { signing_key })
    }

    /// Generate a new random Ed25519 key pair using cryptographically secure RNG.
    ///
    /// Uses the ring library's cryptographically secure random number generator.
    pub fn generate() -> Result<Self, String> {
        let rng = SystemRandom::new();
        
        // Generate a random seed
        let mut seed = [0u8; ED25519_KEY_SIZE];
        rng.fill(&mut seed)
            .map_err(|e| format!("Failed to generate random key: {:?}", e))?;

        // Use dalek to create the key pair
        let signing_key = DalekSigningKey::from_bytes(&seed);
        Ok(Self { signing_key })
    }

    /// Get the raw private key bytes (32 bytes).
    pub fn as_bytes(&self) -> [u8; ED25519_KEY_SIZE] {
        self.signing_key.to_bytes()
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; ED25519_KEY_SIZE] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Encode the private key to base64 (standard, with padding).
    pub fn to_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.as_bytes())
    }

    /// Encode the public key to base64.
    pub fn public_key_to_base64(&self) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(self.public_key_bytes())
    }

    /// Create an Ed25519 key from base64-encoded private key.
    pub fn from_base64(encoded: &str) -> Result<Self, String> {
        use base64::Engine as _;
        
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|e| format!("Failed to decode base64: {}", e))?;

        Self::from_private_key_bytes(&bytes)
    }

    /// Create from base64-encoded private and public keys.
    /// Supports both raw 32-byte Ed25519 keys and PEM-formatted PKCS#8 keys.
    pub fn from_base64_pair(private_key_b64: &str, public_key_b64: &str) -> Result<Self, String> {
        use base64::Engine as _;
        
        let private_bytes_vec = base64::engine::general_purpose::STANDARD
            .decode(private_key_b64)
            .map_err(|e| format!("Failed to decode private key base64: {}", e))?;
            
        let public_bytes_vec = base64::engine::general_purpose::STANDARD
            .decode(public_key_b64)
            .map_err(|e| format!("Failed to decode public key base64: {}", e))?;

        // Try to parse as raw 32-byte key first
        if private_bytes_vec.len() == ED25519_KEY_SIZE && public_bytes_vec.len() == ED25519_KEY_SIZE {
            return Self::from_raw_key_pair(&private_bytes_vec, &public_bytes_vec);
        }

        // If not 32 bytes each, try PEM format
        let private_bytes = Self::extract_ed25519_from_pem(&private_bytes_vec, "private")?;
        let public_bytes = Self::extract_ed25519_from_pem(&public_bytes_vec, "public")?;

        Self::from_raw_key_pair(&private_bytes, &public_bytes)
    }

    /// Extract raw Ed25519 key bytes from PEM-formatted data.
    fn extract_ed25519_from_pem(pem_data: &[u8], key_type: &str) -> Result<[u8; ED25519_KEY_SIZE], String> {
        // Check if it's PEM format (starts with -----BEGIN)
        if pem_data.starts_with(b"-----BEGIN") {
            // Parse PEM format manually
            let pem_str = String::from_utf8(pem_data.to_vec())
                .map_err(|e| format!("Invalid PEM format: {}", e))?;
            
            // Find the base64 content between BEGIN and END markers
            let lines: Vec<&str> = pem_str.lines().collect();
            let mut b64_content = String::new();
            let mut in_content = false;
            
            for line in lines {
                if line.contains("BEGIN") && line.contains("KEY") {
                    in_content = true;
                    continue;
                }
                if line.contains("END") && line.contains("KEY") {
                    break;
                }
                if in_content {
                    b64_content.push_str(line.trim());
                }
            }
            
            if b64_content.is_empty() {
                return Err(format!("No PEM content found for {} key", key_type));
            }
            
            // Decode base64
            use base64::Engine as _;
            let der_bytes = base64::engine::general_purpose::STANDARD
                .decode(&b64_content)
                .map_err(|e| format!("Failed to decode PEM base64: {}", e))?;
            
            Self::extract_key_from_der(&der_bytes, key_type)
        } else {
            // Could be raw 32-byte key OR base64-encoded DER (like from .env)
            // Try to parse as raw 32-byte key first
            if pem_data.len() == ED25519_KEY_SIZE {
                let mut key_bytes = [0u8; ED25519_KEY_SIZE];
                key_bytes.copy_from_slice(pem_data);
                Ok(key_bytes)
            } else if pem_data.len() == 48 || pem_data.len() == 44 {
                // Likely base64-encoded DER (48 bytes for private key, 44 for public)
                // Try to extract the key bytes
                Self::extract_key_from_der(pem_data, key_type)
            } else {
                Err(format!("Invalid {} key length: expected {} bytes or PEM/DER format, got {}", 
                    key_type, ED25519_KEY_SIZE, pem_data.len()))
            }
        }
    }

    /// Extract Ed25519 key from DER-encoded key data.
    fn extract_key_from_der(der_bytes: &[u8], key_type: &str) -> Result<[u8; ED25519_KEY_SIZE], String> {
        // For Ed25519 private key (PKCS#8): 48 bytes = 16 header + 32 key
        // For Ed25519 public key (SPKI): 44 bytes = 12 header + 32 key
        if key_type == "private" {
            // PKCS#8 private key - last 32 bytes are the Ed25519 key
            if der_bytes.len() < 16 + ED25519_KEY_SIZE {
                return Err(format!("Invalid {} key DER length: {} bytes", key_type, der_bytes.len()));
            }
            let mut key_bytes = [0u8; ED25519_KEY_SIZE];
            key_bytes.copy_from_slice(&der_bytes[der_bytes.len() - ED25519_KEY_SIZE..]);
            Ok(key_bytes)
        } else {
            // SPKI public key - last 32 bytes are the Ed25519 key
            if der_bytes.len() < 12 + ED25519_KEY_SIZE {
                return Err(format!("Invalid {} key DER length: {} bytes", key_type, der_bytes.len()));
            }
            let mut key_bytes = [0u8; ED25519_KEY_SIZE];
            key_bytes.copy_from_slice(&der_bytes[der_bytes.len() - ED25519_KEY_SIZE..]);
            Ok(key_bytes)
        }
    }

    /// Create Ed25519 key from raw byte pair (internal helper).
    fn from_raw_key_pair(private_bytes: &[u8], public_bytes: &[u8]) -> Result<Self, String> {
        if private_bytes.len() != ED25519_KEY_SIZE {
            return Err(format!("Invalid private key length: expected {} bytes", ED25519_KEY_SIZE));
        }
        
        if public_bytes.len() != ED25519_KEY_SIZE {
            return Err(format!("Invalid public key length: expected {} bytes", ED25519_KEY_SIZE));
        }

        let private_bytes: [u8; ED25519_KEY_SIZE] = private_bytes
            .try_into()
            .map_err(|_| "Invalid private key length")?;

        let public_bytes: [u8; ED25519_KEY_SIZE] = public_bytes
            .try_into()
            .map_err(|_| "Invalid public key length")?;

        // Verify the key pair is valid by creating a dalek key
        let signing_key = DalekSigningKey::from_bytes(&private_bytes);
        
        let verifying_key = signing_key.verifying_key();
        
        // Verify the public key matches
        if verifying_key.as_bytes() != public_bytes.as_slice() {
            return Err("Public key does not match private key".to_string());
        }

        Ok(Self { signing_key })
    }

    /// Get the encoding key for jsonwebtoken (for signing).
    ///
    /// This derives the PKCS#8 encoding on each call, which is cheap
    /// and ensures we always have a fresh, correct key.
    pub fn encoding_key(&self) -> Result<EncodingKey, String> {
        // Use pkcs8 crate to generate proper RFC 8410 compliant PKCS#8 DER encoding
        let pkcs8_der = self.signing_key
            .to_pkcs8_der()
            .map_err(|e| format!("Failed to create PKCS#8 encoding: {}", e))?;
        
        Ok(EncodingKey::from_ed_der(pkcs8_der.as_bytes()))
    }

    /// Get the decoding key for jsonwebtoken (for verification).
    ///
    /// This uses raw 32-byte Ed25519 public key, NOT SPKI.
    /// jsonwebtoken internally interprets the raw Ed25519 key correctly.
    pub fn decoding_key(&self) -> DecodingKey {
        let verifying_key: VerifyingKey = self.signing_key.verifying_key();
        // Use raw 32-byte public key - NOT manual SPKI!
        DecodingKey::from_ed_der(verifying_key.as_bytes())
    }
}

