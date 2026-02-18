// Crypto adapter error types.

/*
This module defines errors specific to the crypto adapter layer.

These errors represent failures in cryptographic operations,
independent of business logic. They are NOT domain errors.

Design Principles:
 - **Isolation**: Crypto errors never leak cryptographic details upward
 - **Mapping**: All library errors are caught and mapped to CryptoError
 - **No panic**: All crypto operations return Results
 - **Deterministic**: Same input always produces same error type

Errors are organized by concern:
 - `PasswordError`: Password hashing and verification errors
 - `JwtError`: JWT token encoding and decoding errors
 - `CryptoError`: Top-level enum that wraps all of the above
*/

pub mod crypto_error;
pub mod jwt_error;
pub mod password_error;

pub use crypto_error::CryptoError;
pub use jwt_error::JwtError;
pub use password_error::PasswordError;
