//! Tests for HMAC-SHA256 key types.

use crate::adapters::crypto::token::{HmacKey, HMAC_KEY_SIZE};

#[test]
fn test_key_generation() {
    let key1 = HmacKey::generate().expect("Should generate key");
    let key2 = HmacKey::generate().expect("Should generate key");
    
    // Two generated keys should be different
    assert_ne!(key1.as_bytes(), key2.as_bytes());
}

#[test]
fn test_key_from_bytes() {
    let bytes = [0u8; HMAC_KEY_SIZE];
    let key = HmacKey::from_bytes(&bytes).expect("Should create key");
    
    assert_eq!(key.as_bytes(), bytes);
}

#[test]
fn test_invalid_key_length() {
    let short_bytes = [0u8; 16];
    let result = HmacKey::from_bytes(&short_bytes);
    assert!(result.is_err());
    
    let long_bytes = [0u8; 64];
    let result = HmacKey::from_bytes(&long_bytes);
    assert!(result.is_err());
}

#[test]
fn test_base64_roundtrip() {
    let key = HmacKey::generate().expect("Should generate key");
    let encoded = key.to_base64();
    let decoded = HmacKey::from_base64(&encoded).expect("Should decode");
    
    assert_eq!(key.as_bytes(), decoded.as_bytes());
}

#[test]
fn test_multiple_generations_produce_different_keys() {
    let keys: Vec<_> = (0..10)
        .map(|_| HmacKey::generate().expect("Should generate"))
        .collect();
    
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i].as_bytes(), keys[j].as_bytes());
        }
    }
}

#[test]
fn test_invalid_base64_fails() {
    let result = HmacKey::from_base64("not-valid-base64!!!");
    assert!(result.is_err());
}

#[test]
fn test_base64_with_invalid_length_fails() {
    // Valid base64 but wrong length when decoded
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let short_bytes = [0u8; 16];
    let short_b64 = URL_SAFE_NO_PAD.encode(&short_bytes);
    
    let result = HmacKey::from_base64(&short_b64);
    assert!(result.is_err());
}
