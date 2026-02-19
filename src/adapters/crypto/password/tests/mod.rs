//! Tests for the password hashing module.
//!
//! These tests verify:
//! - Argon2 hasher creation with various parameters
//! - Password hashing produces valid credentials
//! - Password verification succeeds for correct passwords
//! - Password verification fails for incorrect passwords
//! - Corrupted hashes are rejected
//! - Same password produces different hashes (due to random salt)

pub mod argon2_hasher_tests;
