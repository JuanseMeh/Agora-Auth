/// ID conversion utilities for cross-service interoperability.
///
/// This module handles ID conversions between different formats used across microservices:
/// - User Service uses BIGSERIAL (64-bit integers)
/// - Auth Service uses UUID (128-bit)
/// - Workspace Service uses INTEGER (32-bit)
///
/// The conversion strategy ensures that IDs from external services can be safely
/// converted to the Auth Service's UUID format without loss of information.

use sha2::{Digest, Sha256};

/// Convert any ID format to UUID string representation.
///
/// This function implements a deterministic conversion strategy suitable for
/// production use where cross-service IDs need to be unified.
///
/// # Strategy
///
/// - If the input is already a valid UUID format (standard UUID string), return as-is
/// - Otherwise, create a deterministic UUID by hashing the ID using SHA256
///   - This ensures the same ID always produces the same UUID
///   - No state or mapping table required
///   - Works offline without database lookups
///
/// # Examples
///
/// ```ignore
/// // UUID passthrough
/// let uuid_str = to_uuid("550e8400-e29b-41d4-a716-446655440000");
/// assert_eq!(uuid_str, "550e8400-e29b-41d4-a716-446655440000");
///
/// // BIGSERIAL conversion to deterministic UUID
/// let uuid_from_bigint = to_uuid("12345");
/// // Returns a valid UUID derived from hashing "12345"
/// ```
pub fn to_uuid(id: &str) -> String {
    // If already a UUID, return as-is
    if is_uuid_format(id) {
        return id.to_string();
    }

    // Convert non-UUID IDs (BIGSERIAL, INTEGER, etc.) to deterministic UUID
    // using SHA256 hash. This creates a v5-like UUID from the ID.
    // Format: first 16 bytes of SHA256(id) formatted as UUID
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    let hash = hasher.finalize();

    // Take first 16 bytes and format as UUID
    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    let bytes = &hash[..16];
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// Check if a string is in valid UUID format.
///
/// # Format
///
/// Standard UUID string: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
/// - 8 hex digits, dash, 4 hex digits, dash, 4 hex digits, dash,
///   4 hex digits, dash, 12 hex digits
/// - Total length: 36 characters
/// - All hex digits (0-9, a-f, A-F)
pub fn is_uuid_format(id: &str) -> bool {
    // UUID string format: 8-4-4-4-12 hex digits with dashes
    if id.len() != 36 {
        return false;
    }

    let parts: Vec<&str> = id.split('-').collect();
    if parts.len() != 5 {
        return false;
    }

    // Check lengths: 8, 4, 4, 4, 12
    let expected_lengths = [8, 4, 4, 4, 12];
    if parts.iter().zip(expected_lengths.iter()).any(|(p, &len)| p.len() != len) {
        return false;
    }

    // Check all characters are valid hex
    parts.iter().all(|part| part.chars().all(|c| c.is_ascii_hexdigit()))
}


