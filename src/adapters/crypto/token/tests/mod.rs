//! Tests for token module (HMAC-SHA256 and EdDSA).
//!
//! These tests verify:
//! - Key generation and encoding/decoding
//! - Token issuance and validation
//! - Expiration handling
//! - Signature verification
//! - Error conversions

pub mod eddsa_token_tests;
pub mod hmac_keys_tests;
pub mod hmac_token_tests;
pub mod jwks_provider_tests;
pub mod google_validator_configuration_tests;
pub mod google_rsa256_validator_tests;
