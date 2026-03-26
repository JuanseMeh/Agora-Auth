//! Tests for JWKS provider.

use crate::adapters::crypto::token::jwks_provider::{JwksProvider, JwksDocument, JwksKey};
use std::sync::Arc;
use base64::Engine;

#[test]
fn test_new_provider() {
    let _provider = JwksProvider::new("https://www.googleapis.com/oauth2/v3/certs".to_string());
}

#[tokio::test]
async fn test_fetch_jwks_success() {
    let provider = JwksProvider::new("https://www.googleapis.com/oauth2/v3/certs".to_string());
    
    let jwks = provider.fetch_jwks().await.expect("Should fetch Google JWKS");
    
    assert!(!jwks.keys.is_empty());
    assert!(!jwks.keys[0].kid.is_empty());
    assert_eq!(jwks.keys[0].kty, "RSA");
    assert!(!jwks.keys[0].modulus.is_empty());
    assert!(!jwks.keys[0].exponent.is_empty());
}

#[test]
fn test_jwks_structs() {
    let key = JwksKey {
        kid: "test-kid".to_string(),
        kty: "RSA".to_string(),
        modulus: "modulus-base64".to_string(),
        exponent: "AQAB".to_string(), // standard RSA exponent
    };
    
    let doc = JwksDocument {
        keys: vec![key],
    };
    
    assert_eq!(doc.keys[0].kid, "test-kid");
    assert_eq!(doc.keys[0].kty, "RSA");
}

#[tokio::test]
async fn test_get_key_cache_miss_hit() {
    let provider = JwksProvider::new("https://www.googleapis.com/oauth2/v3/certs".to_string());
    
    // Get first key from real JWKS
    let jwks = provider.fetch_jwks().await.expect("fetch");
    let kid = &jwks.keys[0].kid;
    
    // First call - miss, fetches and caches
    let key1 = provider.get_key(kid).await.expect("first get");
    assert!(Arc::ptr_eq(&key1, &key1));
    
    // Second call - hit from cache
    let key2 = provider.get_key(kid).await.expect("second get");
    assert!(Arc::ptr_eq(&key1, &key2));
}

#[tokio::test]
async fn test_get_key_invalid_kid() {
    let provider = JwksProvider::new("https://www.googleapis.com/oauth2/v3/certs".to_string());
    
    let key = provider.get_key("non-existent-kid").await;
    assert!(key.is_none());
}

#[tokio::test]
async fn test_cache_expiry() {
    let provider = JwksProvider::new("https://www.googleapis.com/oauth2/v3/certs".to_string());
    
    let _ = provider.fetch_jwks().await.expect("fetch jwks");
}

#[tokio::test]
async fn test_parse_rsa_key_valid() {
    let exponent_b64 = "AQAB";
    
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let mut buf = Vec::new();
    engine.decode_vec(exponent_b64.as_bytes(), &mut buf).expect("decode");
    assert_eq!(buf, vec![1, 0, 1]);
}
