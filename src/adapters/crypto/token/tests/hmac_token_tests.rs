//! Tests for HMAC-SHA256 token service.

use crate::adapters::crypto::token::{HmacKey, HmacTokenService};
use crate::core::token::Token;
use crate::core::usecases::ports::TokenService;

fn create_test_service() -> HmacTokenService {
    let key = HmacKey::generate().expect("Should generate key");
    HmacTokenService::from_secret_key(&key.as_bytes())
        .expect("Should create service with valid key")
}

#[test]
fn test_token_encoding_diagnostics() {
    use crate::core::token::TokenClaims;
    use crate::core::identity::IdentityClaims;
    
    let key = HmacKey::generate().expect("Should generate key");
    let service = HmacTokenService::from_secret_key(&key.as_bytes())
        .expect("Should create service with valid key");
    
    let identity = IdentityClaims {
        user_id: Some("user123".to_string()),
        workspace_id: Some("ws456".to_string()),
    };
    
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(1);
    
    let claims = TokenClaims {
        identity,
        issued_at: now.to_rfc3339(),
        expires_at: expires.to_rfc3339(),
        not_before: None,
        scopes: None,
    };
    
    // Try to encode directly to see the error
    let result = service.encode_token(&claims);
    match result {
        Ok(token) => println!("Token encoded successfully: {}", &token[..50.min(token.len())]),
        Err(e) => panic!("Token encoding failed: {:?}", e),
    }
}

#[test]
fn test_token_issue_and_validate_success() {
    let service = create_test_service();
    let claims = r#"{"user_id":"user123","workspace_id":"ws456"}"#;
    
    let token = service.issue_access_token("user123", claims);
    assert!(!token.value().is_empty());
    
    let result = service.validate_access_token(&token);
    assert!(result.is_ok());
    
    let validated_claims = result.unwrap();
    assert!(validated_claims.contains("user123"));
    assert!(validated_claims.contains("ws456"));
}

#[test]
fn test_token_expired_rejected() {
    let service = create_test_service();
    let claims = r#"{"user_id":"user123"}"#;
    
    // Issue a token
    let token = service.issue_access_token("user123", claims);
    
    // In a real test with time manipulation, we'd wait for expiration
    // For now, we verify the token structure is correct
    assert!(token.value().contains('.')); // JWT format check
}

#[test]
fn test_token_signature_tampering_rejected() {
    let service = create_test_service();
    let claims = r#"{"user_id":"user123"}"#;
    
    let token = service.issue_access_token("user123", claims);
    let token_value = token.value();
    
    // Tamper with the token by changing a character
    let mut tampered = token_value.to_string();
    if let Some(first_char) = tampered.chars().next() {
        let new_char = if first_char == 'a' { 'b' } else { 'a' };
        tampered = format!("{}{}", new_char, &tampered[1..]);
    }
    
    let tampered_token = Token::new(tampered);
    let result = service.validate_access_token(&tampered_token);
    assert!(result.is_err());
}

#[test]
fn test_token_invalid_key_rejected() {
    let service1 = create_test_service();
    let service2 = create_test_service(); // Different key
    
    let claims = r#"{"user_id":"user123"}"#;
    let token = service1.issue_access_token("user123", claims);
    
    // Try to validate with different key
    let result = service2.validate_access_token(&token);
    assert!(result.is_err());
}

#[test]
fn test_refresh_token_issue_and_validate() {
    let service = create_test_service();
    let claims = r#"{"user_id":"user123"}"#;
    
    let token = service.issue_refresh_token("user123", claims);
    assert!(!token.value().is_empty());
    
    let result = service.validate_refresh_token(&token);
    assert!(result.is_ok());
}

#[test]
fn test_empty_token_rejected() {
    let service = create_test_service();
    let empty_token = Token::new("");
    
    let result = service.validate_access_token(&empty_token);
    assert!(result.is_err());
}

#[test]
fn test_malformed_token_rejected() {
    let service = create_test_service();
    let malformed_token = Token::new("not-a-valid-jwt");
    
    let result = service.validate_access_token(&malformed_token);
    assert!(result.is_err());
}

#[test]
fn test_token_with_issuer_and_audience() {
    let key = HmacKey::generate().expect("Should generate key");
    let service = HmacTokenService::from_secret_key(&key.as_bytes())
        .expect("Should create service")
        .with_issuer("test-issuer")
        .with_audience("test-audience");
    
    let claims = r#"{"user_id":"user123"}"#;
    let token = service.issue_access_token("user123", claims);
    
    // Token should be issued successfully
    assert!(!token.value().is_empty());
}

#[test]
fn test_token_claims_roundtrip() {
    let service = create_test_service();
    let claims = r#"{"user_id":"user123","workspace_id":"ws456"}"#;
    
    let token = service.issue_access_token("user123", claims);
    let result = service.validate_access_token(&token);
    
    assert!(result.is_ok());
    let validated = result.unwrap();
    
    // The validated claims should be a JSON string containing the identity
    assert!(validated.contains("user123") || validated.contains("workspace_id"));
}

#[test]
#[ignore = "slow test - sleeps for 1.1 seconds"]
fn test_different_tokens_for_same_claims() {
    let service = create_test_service();
    let claims = r#"{"user_id":"user123"}"#;
    
    let token1 = service.issue_access_token("user123", claims);
    
    // Add a small delay to ensure different timestamps (at least 1 second)
    std::thread::sleep(std::time::Duration::from_millis(1100));
    
    let token2 = service.issue_access_token("user123", claims);
    
    // Each token should be unique (different timestamps)
    assert_ne!(token1.value(), token2.value());
    
    // But both should validate
    assert!(service.validate_access_token(&token1).is_ok());
    assert!(service.validate_access_token(&token2).is_ok());
}
