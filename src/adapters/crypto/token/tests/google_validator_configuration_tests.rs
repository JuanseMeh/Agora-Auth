//! Tests for Google RS256 validator configuration.

use crate::adapters::crypto::token::google_validator_config::GoogleValidatorConfig;
use serde_json::from_str;

#[test]
fn test_new_config() {
    let config = GoogleValidatorConfig::new(
        "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        "https://accounts.google.com".to_string(),
        "my-app-client-id".to_string(),
    );
    
    assert_eq!(config.jwks_url, "https://www.googleapis.com/oauth2/v3/certs");
    assert_eq!(config.issuer, "https://accounts.google.com");
    assert_eq!(config.audience, "my-app-client-id");
}

#[test]
fn test_deserialize_config() {
    let json = r#"{
        "jwks_url": "https://www.googleapis.com/oauth2/v3/certs",
        "issuer": "https://accounts.google.com",
        "audience": "my-app-client-id"
    }"#;

    let config: GoogleValidatorConfig = from_str(json).expect("Should deserialize config");
    
    assert_eq!(config.jwks_url, "https://www.googleapis.com/oauth2/v3/certs");
    assert_eq!(config.issuer, "https://accounts.google.com");
    assert_eq!(config.audience, "my-app-client-id");
}

#[test]
fn test_debug_impl() {
    let config = GoogleValidatorConfig::new(
        "https://example.com/jwks.json".to_string(),
        "https://example.com".to_string(),
        "test-client".to_string(),
    );
    
    let debug = format!("{:?}", config);
    assert!(debug.contains("jwks_url"));
    assert!(debug.contains("https://example.com/jwks.json"));
}
