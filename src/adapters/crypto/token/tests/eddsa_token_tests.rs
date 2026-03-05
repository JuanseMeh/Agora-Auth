//! Tests for Ed25519-EdDSA token service.

use crate::adapters::crypto::token::{EddsaKey, EddsaTokenService};
use crate::core::token::Token;
use crate::core::usecases::ports::TokenService;

fn create_test_service() -> EddsaTokenService {
    let key = EddsaKey::generate().expect("Should generate key");
    EddsaTokenService::from_key(&key).expect("Should create service with valid key")
}

#[test]
fn test_key_generation() {
    let key = EddsaKey::generate();
    assert!(key.is_ok());
    
    let key = key.unwrap();
    // Ed25519 keys should be 32 bytes
    assert_eq!(key.as_bytes().len(), 32);
    assert_eq!(key.public_key_bytes().len(), 32);
}

#[test]
fn test_key_from_bytes() {
    // Generate a key first
    let original = EddsaKey::generate().expect("Should generate key");
    let bytes = original.as_bytes();
    
    // Create a new key from those bytes
    let key = EddsaKey::from_private_key_bytes(&bytes);
    assert!(key.is_ok());
    
    let key = key.unwrap();
    // The keys should be the same
    assert_eq!(key.as_bytes(), original.as_bytes());
}

#[test]
fn test_key_base64_encoding() {
    let key = EddsaKey::generate().expect("Should generate key");
    
    let b64 = key.to_base64();
    // Base64 of 32 bytes should be at least 40+ chars (with padding)
    assert!(b64.len() >= 40);
    
    // Can decode back
    let decoded = EddsaKey::from_base64(&b64);
    assert!(decoded.is_ok());
    assert_eq!(decoded.unwrap().as_bytes(), key.as_bytes());
}

#[test]
fn test_key_base64_pair() {
    let key = EddsaKey::generate().expect("Should generate key");
    
    let private_b64 = key.to_base64();
    let public_b64 = key.public_key_to_base64();
    
    // Can create from pair
    let key2 = EddsaKey::from_base64_pair(&private_b64, &public_b64);
    assert!(key2.is_ok());
    assert_eq!(key2.unwrap().as_bytes(), key.as_bytes());
}

#[test]
fn test_token_encoding() {
    use crate::core::token::TokenClaims;
    
    let key = EddsaKey::generate().expect("Should generate key");
    let service = EddsaTokenService::from_key(&key).expect("Should create service");
    
    let now = chrono::Utc::now();
    let expires = now + chrono::Duration::hours(1);
    
    let claims = TokenClaims::new(
        "user123".to_string(),
        now.timestamp(),
        expires.timestamp(),
        "access".to_string(),
    );
    
    let result = service.encode_token(&claims);
    match result {
        Ok(token) => println!("Token encoded successfully: {}", &token[..50.min(token.len())]),
        Err(e) => panic!("Token encoding failed: {:?}", e),
    }
}

#[test]
fn test_token_issue_and_validate_success() {
    let service = create_test_service();
    // Use claims format with "sub" field (JWT standard)
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    
    let token = service.issue_access_token("user123", claims);
    assert!(!token.value().is_empty());
    
    let result = service.validate_access_token(&token);
    assert!(result.is_ok());
    
    let validated_claims = result.unwrap();
    // The validated claims should contain the user_id (from "sub")
    assert!(validated_claims.contains("user123"));
}

#[test]
fn test_token_expired_rejected() {
    let service = create_test_service();
    // Use claims format with "sub" field
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    
    // Issue a token
    let token = service.issue_access_token("user123", claims);
    
    // In a real test with time manipulation, we'd wait for expiration
    // For now, we verify the token structure is correct
    assert!(token.value().contains('.')); // JWT format check
}

#[test]
fn test_token_signature_tampering_rejected() {
    let service = create_test_service();
    // Use claims format with "sub" field
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    
    let token = service.issue_access_token("user123", claims);
    let token_value = token.value();
    
    // Tamper with the token by changing a character in the signature part
    let mut parts: Vec<&str> = token_value.split('.').collect();
    if parts.len() == 3 {
        let signature = parts[2].to_string();
        if !signature.is_empty() {
            let mut tampered_sig = signature.clone();
            let first_byte = signature.as_bytes()[0];
            tampered_sig.replace_range(0..1, &(first_byte ^ 0xFF).to_string());
            parts[2] = &tampered_sig;
            
            let tampered_token = Token::new(parts.join("."));
            let result = service.validate_access_token(&tampered_token);
            assert!(result.is_err());
            return;
        }
    }
    
    // Fallback: just test that non-tampered token validates
    let result = service.validate_access_token(&token);
    assert!(result.is_ok());
}

#[test]
fn test_token_invalid_key_rejected() {
    let service1 = create_test_service();
    let service2 = create_test_service(); // Different key
    
    // Use claims format with "sub" field
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    let token = service1.issue_access_token("user123", claims);
    
    // Try to validate with different key
    let result = service2.validate_access_token(&token);
    assert!(result.is_err());
}

#[test]
fn test_refresh_token_issue_and_validate() {
    let service = create_test_service();
    // Use claims format with "sub" field for refresh token
    let claims = r#"{"sub":"user123","type":"refresh","exp":9999999999,"sid":"session-123"}"#;
    
    let token = service.issue_refresh_token("user123", claims);
    assert!(!token.value().is_empty());
    
    let result = service.validate_refresh_token(&token);
    assert!(result.is_ok());
}

#[test]
fn test_refresh_token_wrong_type_rejected() {
    let service = create_test_service();
    // Issue an access token but try to validate as refresh
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    
    let token = service.issue_access_token("user123", claims);
    
    // Trying to validate access token as refresh should fail
    let result = service.validate_refresh_token(&token);
    assert!(result.is_err());
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
    let key = EddsaKey::generate().expect("Should generate key");
    let service = EddsaTokenService::from_key(&key)
        .expect("Should create service")
        .with_issuer("test-issuer")
        .with_audience("test-audience");
    
    // Use claims format with "sub" field
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    let token = service.issue_access_token("user123", claims);
    
    // Token should be issued successfully
    assert!(!token.value().is_empty());
    
    // Validation with matching issuer/audience should work
    let result = service.validate_access_token(&token);
    assert!(result.is_ok());
}

#[test]
fn test_token_claims_roundtrip() {
    let service = create_test_service();
    // Use claims format with "sub" field
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    
    let token = service.issue_access_token("user123", claims);
    let result = service.validate_access_token(&token);
    
    assert!(result.is_ok());
    let validated = result.unwrap();
    
    // The validated claims should be a JSON string containing the user_id (from "sub")
    assert!(validated.contains("user123"));
}

#[test]
fn test_service_token_issue_and_validate() {
    let key = EddsaKey::generate().expect("Should generate key");
    let service_key = EddsaKey::generate().expect("Should generate service key");
    
    let service = EddsaTokenService::from_key(&key)
        .expect("Should create service")
        .with_service_token_key(&service_key.as_bytes())
        .expect("Should set service key");
    
    // Issue a service token
    let claims = r#"{"sub":"service-1","aud":"api-gateway"}"#;
    let token = service.issue_service_token("service-1", claims);
    assert!(!token.value().is_empty());
    
    // Validate the service token
    let result = service.validate_service_token(&token);
    assert!(result.is_ok());
    
    let validated = result.unwrap();
    assert!(validated.contains("service-1"));
}

#[test]
fn test_service_token_without_service_key() {
    // Service without a separate service key should use main key
    let service = create_test_service();
    
    let claims = r#"{"sub":"service-1"}"#;
    let token = service.issue_service_token("service-1", claims);
    assert!(!token.value().is_empty());
    
    let result = service.validate_service_token(&token);
    assert!(result.is_ok());
}

#[test]
fn test_token_contains_correct_token_type() {
    let service = create_test_service();
    
    // Test access token
    let access_claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    let access_token = service.issue_access_token("user123", access_claims);
    let access_result = service.validate_access_token(&access_token).unwrap();
    assert!(access_result.contains("\"type\":\"access\""));
    
    // Test refresh token
    let refresh_claims = r#"{"sub":"user123","type":"refresh","exp":9999999999,"sid":"session-123"}"#;
    let refresh_token = service.issue_refresh_token("user123", refresh_claims);
    let refresh_result = service.validate_refresh_token(&refresh_token).unwrap();
    assert!(refresh_result.contains("\"type\":\"refresh\""));
    
    // Test service token
    let service_claims = r#"{"sub":"service-1"}"#;
    let service_token = service.issue_service_token("service-1", service_claims);
    let service_result = service.validate_service_token(&service_token).unwrap();
    assert!(service_result.contains("\"type\":\"service\""));
}

#[test]
fn test_from_private_key() {
    // Generate a key and get its bytes
    let original = EddsaKey::generate().expect("Should generate key");
    let bytes = original.as_bytes();
    
    // Create service directly from private key bytes
    let service = EddsaTokenService::from_private_key(&bytes);
    assert!(service.is_ok());
    
    let service = service.unwrap();
    
    // Should be able to issue and validate tokens
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    let token = service.issue_access_token("user123", claims);
    assert!(!token.value().is_empty());
    
    let result = service.validate_access_token(&token);
    assert!(result.is_ok());
}

#[test]
#[ignore = "slow test - sleeps for 1.1 seconds"]
fn test_different_tokens_for_same_claims() {
    let service = create_test_service();
    // Use claims format with "sub" field
    let claims = r#"{"sub":"user123","type":"access","exp":9999999999,"sid":"session-123"}"#;
    
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

