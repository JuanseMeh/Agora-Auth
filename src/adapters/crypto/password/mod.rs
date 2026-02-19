//! Password hashing module for the crypto adapter.
//!
//! This module provides password hashing and verification implementations
//! using the Argon2id algorithm. It implements the `PasswordHasher` port
//! from the core domain.
//!
//! # Components
//!
//! - [`Argon2PasswordHasher`]: Argon2id password hashing and verification
//!
//! # Example
//!
//! ```rust
//! use auth::adapters::crypto::password::Argon2PasswordHasher;
//! use auth::core::usecases::ports::PasswordHasher;
//!
//! // Create hasher with OWASP recommended parameters
//! let hasher = Argon2PasswordHasher::new(
//!     65536,  // 64 MB memory cost
//!     3,      // 3 iterations
//!     4,      // 4 parallelism
//!     16,     // 16 byte salt
//! ).expect("Valid parameters");
//!
//! let credential = hasher.hash("user_password");
//! assert!(hasher.verify("user_password", &credential));
//! ```

pub mod argon2_hasher;

pub use argon2_hasher::Argon2PasswordHasher;

#[cfg(test)]
mod tests;
