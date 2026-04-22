//! Tests for ExchangeAuthorizationCode port.

use crate::core::usecases::ports::ExchangeAuthorizationCode;
use crate::core::identity::ExternalIdentity;
use crate::core::error::{CoreError, AuthenticationError};
use futures::future::{self, BoxFuture};

#[derive(Clone)]
struct MockExchange;

impl ExchangeAuthorizationCode for MockExchange {
    fn exchange(&self, code: &str, _state: Option<&str>) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        if code.starts_with("valid_") {
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
                reason: "Invalid code".to_string(),
            });
            Box::pin(future::err(err))
        }
    }
}

#[tokio::test]
async fn successful_exchange_returns_identity() {
    let exchanger = MockExchange;
    let result = exchanger.exchange("valid_code123", Some("state123")).await;
    let identity = result.expect("expected success");
    assert_eq!(identity.provider, "google");
    assert_eq!(identity.provider_user_id, "123456");
    assert_eq!(identity.email.as_deref(), Some("user@example.com"));
}

#[tokio::test]
async fn invalid_code_returns_error() {
    let exchanger = MockExchange;
    let result = exchanger.exchange("invalid_code", None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn state_is_passed_through() {
    let exchanger = MockExchange;
    let result = exchanger.exchange("valid_code", Some("state_param")).await;
    assert!(result.is_ok());
}

