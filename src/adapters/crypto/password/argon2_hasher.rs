//! Argon2 password hasher implementation.
//!
//! This module provides a concrete implementation of the `PasswordHasher` port
//! using the Argon2id algorithm via the argon2 crate.
//!
//! # Design Principles
//!
//! - **Pure cryptographic**: No policy logic, no version tracking
//! - **Configurable**: All parameters injected via constructor
//! - **PHC format**: Uses standard PHC string format for storage
//! - **No secret leakage**: Passwords are never logged or exposed in errors
//!
//! # Example
//!
//! ```rust
//! use auth::adapters::crypto::password::Argon2PasswordHasher;
//! use auth::core::usecases::ports::PasswordHasher;
//!
//! // Create hasher with custom parameters
//! let hasher = Argon2PasswordHasher::new(
//!     65536,  // 64 MB memory cost
//!     3,      // 3 iterations
//!     4,      // 4 parallelism
//!     16,     // 16 byte salt
//! ).expect("Valid parameters");
//!
//! let credential = hasher.hash("user_password");
//! ```

use crate::adapters::crypto::error::PasswordError;
use crate::core::credentials::StoredCredential;
use crate::core::usecases::ports::PasswordHasher;
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher as Argon2Hasher, PasswordVerifier, SaltString,
    },
    Algorithm, Argon2, Params, Version,
};

/// Argon2id password hasher implementation.
///
/// This hasher uses the Argon2id algorithm with configurable parameters.
/// All parameters are injected via constructor - no hardcoded defaults.
#[derive(Debug, Clone)]
pub struct Argon2PasswordHasher {
    argon2: Argon2<'static>,
    salt_length: usize,
}

impl Argon2PasswordHasher {
    /// Create a new Argon2 password hasher with the specified parameters.
    ///
    /// # Arguments
    ///
    /// * `memory_cost` - Memory cost in KB (m_cost parameter)
    /// * `time_cost` - Number of iterations (t_cost parameter)
    /// * `parallelism` - Degree of parallelism (p_cost parameter)
    /// * `salt_length` - Salt length in bytes
    ///
    /// # Errors
    ///
    /// Returns `PasswordError` if the parameters are invalid.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auth::adapters::crypto::password::Argon2PasswordHasher;
    ///
    /// let hasher = Argon2PasswordHasher::new(65536, 3, 4, 16)
    ///     .expect("Valid parameters");
    /// ```
    pub fn new(
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        salt_length: usize,
    ) -> Result<Self, PasswordError> {
        // Validate salt length
        if salt_length < 8 {
            return Err(PasswordError::hashing(
                "salt length must be at least 8 bytes",
            ));
        }

        // Create Argon2 parameters
        let params = Params::new(memory_cost, time_cost, parallelism, None)
            .map_err(|e| PasswordError::hashing(format!("invalid argon2 parameters: {}", e)))?;

        // Create Argon2 instance with Argon2id variant
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        Ok(Self {
            argon2,
            salt_length,
        })
    }

    /// Get the configured salt length.
    pub fn salt_length(&self) -> usize {
        self.salt_length
    }

    /// Hash a password and return the PHC string.
    ///
    /// This is the internal implementation that returns the actual hash string.
    /// The public `hash` method wraps this in a StoredCredential.
    fn hash_to_string(&self, raw: &str) -> Result<String, PasswordError> {
        // Generate a random salt using OsRng
        let salt = SaltString::generate(&mut OsRng);

        // Hash the password
        let password_hash = self
            .argon2
            .hash_password(raw.as_bytes(), &salt)
            .map_err(|e| PasswordError::hashing(format!("argon2 hashing failed: {}", e)))?;

        Ok(password_hash.to_string())
    }

}

impl PasswordHasher for Argon2PasswordHasher {
    fn hash(&self, raw: &str) -> StoredCredential {
        // Hash the password and wrap in StoredCredential
        let hash_str = self
            .hash_to_string(raw)
            .expect("argon2 hashing should not fail with valid parameters");

        StoredCredential::from_hash(hash_str)
    }

    fn verify(&self, raw: &str, stored: &StoredCredential) -> bool {
        // Get the stored hash string from the credential
        let hash_str = stored.as_hash_str();
        
        // Parse the stored PHC hash
        let parsed_hash = match PasswordHash::new(hash_str) {
            Ok(hash) => hash,
            Err(_) => return false,
        };

        // Verify the password
        match self.argon2.verify_password(raw.as_bytes(), &parsed_hash) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}
