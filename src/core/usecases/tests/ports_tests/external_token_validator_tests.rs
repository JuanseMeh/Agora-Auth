//! Tests for ExternalTokenValidator port.

use crate::core::usecases::ports::ExternalTokenValidator;
use crate::core::identity::ExternalIdentity;
use crate::core::error::{CoreError, AuthenticationError};
use futures::future::{self, BoxFuture};

#[derive(Clone)]
struct MockValidator;

impl ExternalTokenValidator for MockValidator {
    fn validate(&self, token: &str) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        if token.starts_with("valid.") {
            let identity = ExternalIdentity {
                provider: "google".to_string(),
                provider_user_id: "123456".to_string(),
                email: Some("user@example.com".to_string()),
                name: None,
                family_name: None,
                picture: None,
            };
            Box::pin(future::ok(identity))
        } else {
            let err = CoreError::Authentication(AuthenticationError::InvalidExternalToken {
                reason: "Invalid token".to_string(),
            });
            Box::pin(future::err(err))
        }
    }
}

#[tokio::test]
async fn validate_valid_token_returns_identity() {
    let validator = MockValidator;
    let result = validator.validate("valid.eyJzdWIiOiIxMjM0NTYiLCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20ifQ").await;
    let identity = result.expect("expected success");
    assert_eq!(identity.provider, "google");
    assert_eq!(identity.provider_user_id, "123456");
    assert_eq!(identity.email.as_deref(), Some("user@example.com"));
}

#[tokio::test]
async fn validate_invalid_token_returns_error() {
    let validator = MockValidator;
    let result = validator.validate("invalid.token").await;
    assert!(result.is_err());
}

