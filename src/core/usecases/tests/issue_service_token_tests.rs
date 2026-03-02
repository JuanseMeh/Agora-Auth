//! Tests for IssueServiceToken use case.

use std::sync::Arc;

use crate::core::credentials::StoredCredential;
use crate::core::error::CoreError;
use crate::core::token::Token;
use crate::core::usecases::issue_service_token::{IssueServiceToken, IssueServiceTokenInput};
use crate::core::usecases::ports::{PasswordHasher, ServiceRegistry, TokenService};

// ============================================================================
// Mock Implementations
// ============================================================================

/// Mock PasswordHasher for testing
struct MockPasswordHasher;

impl PasswordHasher for MockPasswordHasher {
    fn hash(&self, raw: &str) -> StoredCredential {
        StoredCredential::from_hash(format!("hashed_{}", raw))
    }

    fn verify(&self, raw: &str, stored: &StoredCredential) -> bool {
        // Simple verification: check if the stored hash matches "hashed_" + raw password
        let expected_hash = format!("hashed_{}", raw);
        stored.as_hash_str() == expected_hash
    }
}

/// Mock ServiceRegistry for testing
struct MockServiceRegistry {
    /// Map of service_id -> (hashed_secret, is_active)
    services: std::sync::RwLock<std::collections::HashMap<String, (String, bool)>>,
}

impl MockServiceRegistry {
    fn new() -> Self {
        let mut services = std::collections::HashMap::new();
        // Add a valid active service
        services.insert(
            "active_service".to_string(),
            ("hashed_correct_secret".to_string(), true),
        );
        // Add an inactive service
        services.insert(
            "inactive_service".to_string(),
            ("hashed_correct_secret".to_string(), false),
        );
        Self {
            services: std::sync::RwLock::new(services),
        }
    }
}

impl ServiceRegistry for MockServiceRegistry {
    fn validate_api_key(&self, api_key: &str) -> Option<String> {
        let services = self.services.read().unwrap();
        services
            .keys()
            .find(|_| api_key.starts_with("key_"))
            .cloned()
    }

    fn is_service_active(&self, service_name: &str) -> bool {
        let services = self.services.read().unwrap();
        services
            .get(service_name)
            .map(|(_, is_active)| *is_active)
            .unwrap_or(false)
    }

    fn validate_credentials(
        &self,
        service_id: &str,
        service_secret: &str,
        password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
    ) -> Option<String> {
        let services = self.services.read().unwrap();
        // Only check if credentials are valid (don't check active status here)
        // The active status is checked separately in the use case
        if let Some((stored_hash, _)) = services.get(service_id) {
            let stored_credential = StoredCredential::from_hash(stored_hash);
            if password_hasher.verify(service_secret, &stored_credential) {
                return Some(service_id.to_string());
            }
        }
        None
    }
}

/// Mock TokenService for testing
struct MockTokenService;

impl TokenService for MockTokenService {
    fn issue_access_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(&format!("access_token_for_{}", subject))
    }

    fn issue_refresh_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(&format!("refresh_token_for_{}", subject))
    }

    fn issue_service_token(&self, subject: &str, _claims: &str) -> Token {
        Token::new(&format!("service_token_for_{}", subject))
    }

    fn validate_access_token(&self, token: &Token) -> Result<String, ()> {
        if token.value().contains("access_token_for_") {
            Ok("user123".to_string())
        } else {
            Err(())
        }
    }

    fn validate_refresh_token(&self, token: &Token) -> Result<String, ()> {
        if token.value().contains("refresh_token_for_") {
            Ok("user123".to_string())
        } else {
            Err(())
        }
    }

    fn validate_service_token(&self, token: &Token) -> Result<String, ()> {
        if token.value().contains("service_token_for_") {
            Ok("service123".to_string())
        } else {
            Err(())
        }
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[tokio::test]
async fn test_issue_service_token_success() {
    let service_registry = MockServiceRegistry::new();
    let password_hasher: Arc<dyn PasswordHasher + Send + Sync> = Arc::new(MockPasswordHasher);
    let token_service = MockTokenService;

    let use_case = IssueServiceToken::new(
        &service_registry,
        password_hasher.clone(),
        &token_service,
        3600, // service_token_ttl_seconds
    );

    let input = IssueServiceTokenInput {
        service_id: "active_service".to_string(),
        service_secret: "correct_secret".to_string(),
    };

    let result = use_case.execute(input).await;
    assert!(result.is_ok(), "Service token should be issued successfully");

    let output = result.unwrap();
    assert!(!output.access_token.value().is_empty());
    assert_eq!(output.expires_in, 3600);
}

#[tokio::test]
async fn test_issue_service_token_invalid_credentials() {
    let service_registry = MockServiceRegistry::new();
    let password_hasher: Arc<dyn PasswordHasher + Send + Sync> = Arc::new(MockPasswordHasher);
    let token_service = MockTokenService;

    let use_case = IssueServiceToken::new(
        &service_registry,
        password_hasher.clone(),
        &token_service,
        3600,
    );

    let input = IssueServiceTokenInput {
        service_id: "active_service".to_string(),
        service_secret: "wrong_secret".to_string(),
    };

    let result = use_case.execute(input).await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        CoreError::Authentication(auth_err) => {
            assert!(auth_err.is_invalid_credentials());
        }
        _ => panic!("Expected Authentication error"),
    }
}

#[tokio::test]
async fn test_issue_service_token_service_not_active() {
    let service_registry = MockServiceRegistry::new();
    let password_hasher: Arc<dyn PasswordHasher + Send + Sync> = Arc::new(MockPasswordHasher);
    let token_service = MockTokenService;

    let use_case = IssueServiceToken::new(
        &service_registry,
        password_hasher.clone(),
        &token_service,
        3600,
    );

    let input = IssueServiceTokenInput {
        service_id: "inactive_service".to_string(),
        service_secret: "correct_secret".to_string(),
    };

    let result = use_case.execute(input).await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        CoreError::Authentication(auth_err) => {
            assert!(auth_err.is_service_not_active());
        }
        _ => panic!("Expected Authentication error"),
    }
}

#[tokio::test]
async fn test_issue_service_token_nonexistent_service() {
    let service_registry = MockServiceRegistry::new();
    let password_hasher: Arc<dyn PasswordHasher + Send + Sync> = Arc::new(MockPasswordHasher);
    let token_service = MockTokenService;

    let use_case = IssueServiceToken::new(
        &service_registry,
        password_hasher.clone(),
        &token_service,
        3600,
    );

    let input = IssueServiceTokenInput {
        service_id: "nonexistent_service".to_string(),
        service_secret: "some_secret".to_string(),
    };

    let result = use_case.execute(input).await;
    assert!(result.is_err());

    let err = result.unwrap_err();
    match err {
        CoreError::Authentication(auth_err) => {
            assert!(auth_err.is_invalid_credentials());
        }
        _ => panic!("Expected Authentication error"),
    }
}

#[tokio::test]
async fn test_issue_service_token_different_ttl_values() {
    let service_registry = MockServiceRegistry::new();
    let password_hasher: Arc<dyn PasswordHasher + Send + Sync> = Arc::new(MockPasswordHasher);
    let token_service = MockTokenService;

    // Test with different TTL values
    let ttl_values = vec![300, 1800, 3600, 7200];

    for ttl in ttl_values {
        let use_case = IssueServiceToken::new(
            &service_registry,
            password_hasher.clone(),
            &token_service,
            ttl,
        );

        let input = IssueServiceTokenInput {
            service_id: "active_service".to_string(),
            service_secret: "correct_secret".to_string(),
        };

        let result = use_case.execute(input).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().expires_in, ttl);
    }
}

