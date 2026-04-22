use crate::adapters::clients::google::{GoogleCodeExchanger, GoogleCodeExchangerConfig};
use crate::core::error::{CoreError, AuthenticationError};
use crate::core::identity::ExternalIdentity;
use crate::core::usecases::ports::ExchangeAuthorizationCode;
use crate::core::usecases::ports::ExternalTokenValidator;
use mockall::mock;
use mockall::predicate::eq;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use wiremock::{MockServer, Mock};
use wiremock::matchers::{method, path};
use wiremock::ResponseTemplate;


mock! {
    ExternalTokenValidatorMock {}
    
    impl ExternalTokenValidator for ExternalTokenValidatorMock {
        fn validate(&self, token: &str) -> futures::future::BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
            Box::pin(async move { unimplemented!() })
        }
    }
}

#[tokio::test]
async fn test_new_google_code_exchanger() {
    let config = GoogleCodeExchangerConfig {
        client_id: "test_client_id".to_string(),
        client_secret: "test_client_secret".to_string(),
        token_url: "http://localhost/token".to_string(),
        redirect_uri: "http://localhost/callback".to_string(),
        timeout: Duration::from_secs(10),
        max_retries: 3,
    };
    let http_client = reqwest::Client::new();
    let validator = Arc::new(MockExternalTokenValidatorMock::new());

    let _exchanger = GoogleCodeExchanger::new(config, http_client, validator);
    // Compilation success
}

#[tokio::test]
async fn test_exchange_happy_path() {
    let mock_server = MockServer::start().await;
    let config = GoogleCodeExchangerConfig {
        client_id: "client_id".to_string(),
        client_secret: "client_secret".to_string(),
        token_url: mock_server.uri(),
        redirect_uri: "http://localhost/callback".to_string(),
        timeout: Duration::from_secs(5),
        max_retries: 0,
    };

    let mut validator_mock = MockExternalTokenValidatorMock::new();
    validator_mock.expect_validate()
        .with(eq("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."))
        .times(1)
        .return_once(|_| Box::pin(async move {
            Ok(
                ExternalIdentity::new(
                    "google".to_string(),
                    "test_sub".to_string(),
                    Some("test@example.com".to_string()),
                    None, None, None
                ).unwrap()
            )
        }));
    let validator = Arc::new(validator_mock);
    
    let http_client = reqwest::Client::new();
    let exchanger = GoogleCodeExchanger::new(config, http_client, validator);

let _mock = Mock::given(method("POST"))
    .and(path("/"))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access_token",
            "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "Bearer"
        })))
    .mount(&mock_server)
    .await;



    let result: Result<ExternalIdentity, CoreError> = exchanger.exchange("valid_code", None).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_exchange_invalid_code_400_no_retry() {
    let mock_server = MockServer::start().await;
    let config = GoogleCodeExchangerConfig {
        client_id: "client_id".to_string(),
        client_secret: "client_secret".to_string(),
        token_url: mock_server.uri(),
        redirect_uri: "http://localhost/callback".to_string(),
        timeout: Duration::from_secs(5),
        max_retries: 3,
    };

    let validator = Arc::new(MockExternalTokenValidatorMock::new());
    let http_client = reqwest::Client::new();
    let exchanger = GoogleCodeExchanger::new(config, http_client, validator);

let _mock = Mock::given(method("POST"))
    .and(path("/"))
    .respond_with(ResponseTemplate::new(400))
    .mount(&mock_server)
    .await;


    let result: Result<ExternalIdentity, CoreError> = exchanger.exchange("invalid_code", None).await;
    let err = result.unwrap_err();
    assert!(matches!(err, CoreError::Authentication(AuthenticationError::InvalidExternalToken { .. })));
}

#[tokio::test]
async fn test_exchange_server_error_retries() {
    let mock_server = MockServer::start().await;
    let config = GoogleCodeExchangerConfig {
        client_id: "client_id".to_string(),
        client_secret: "client_secret".to_string(),
        token_url: mock_server.uri(),
        redirect_uri: "http://localhost/callback".to_string(),
        timeout: Duration::from_secs(1),
        max_retries: 1, // Test 2 attempts
    };

    let validator = Arc::new(MockExternalTokenValidatorMock::new());
    let http_client = reqwest::Client::new();
    let exchanger = GoogleCodeExchanger::new(config, http_client, validator);

    // Setup 2 mocks for 500 responses (1 retry + final fail)
let _mock1 = Mock::given(method("POST"))
    .and(path("/"))
    .respond_with(ResponseTemplate::new(500))
    .mount(&mock_server)
    .await;
let _mock2 = Mock::given(method("POST"))
    .and(path("/"))
    .respond_with(ResponseTemplate::new(500))
    .mount(&mock_server)
    .await;


    let result: Result<ExternalIdentity, CoreError> = exchanger.exchange("retry_code", None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_exchange_missing_id_token() {
    let mock_server = MockServer::start().await;
    let config = GoogleCodeExchangerConfig {
        client_id: "client_id".to_string(),
        client_secret: "client_secret".to_string(),
        token_url: mock_server.uri(),
        redirect_uri: "http://localhost/callback".to_string(),
        timeout: Duration::from_secs(5),
        max_retries: 0,
    };

    let validator = Arc::new(MockExternalTokenValidatorMock::new());
    let http_client = reqwest::Client::new();
    let exchanger = GoogleCodeExchanger::new(config, http_client, validator);

let _mock = Mock::given(method("POST"))
    .and(path("/"))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access_token",
            "token_type": "Bearer"
        })))
    .mount(&mock_server)
    .await;


    let result: Result<ExternalIdentity, CoreError> = exchanger.exchange("code", None).await;
    let err = result.unwrap_err();
    assert!(matches!(err, CoreError::Authentication(AuthenticationError::InvalidExternalToken { .. })));
}

#[tokio::test]
async fn test_exchange_validator_fails() {
    let mock_server = MockServer::start().await;
    let config = GoogleCodeExchangerConfig {
        client_id: "client_id".to_string(),
        client_secret: "client_secret".to_string(),
        token_url: mock_server.uri(),
        redirect_uri: "http://localhost/callback".to_string(),
        timeout: Duration::from_secs(5),
        max_retries: 0,
    };

    let mut validator_mock = MockExternalTokenValidatorMock::new();
    validator_mock.expect_validate()
        .with(eq("some_id_token"))
        .times(1)
        .return_once(|_| 
            Box::pin(async move {
                Err(CoreError::Authentication(AuthenticationError::InvalidExternalToken {
                    reason: "Validator failed".to_string(),
                }))
            })
        );
    let validator = Arc::new(validator_mock);

    let http_client = reqwest::Client::new();
    let exchanger = GoogleCodeExchanger::new(config, http_client, validator);

let _mock = Mock::given(method("POST"))
    .and(path("/"))
    .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id_token": "some_id_token"
        })))
    .mount(&mock_server)
    .await;


    let result: Result<ExternalIdentity, CoreError> = exchanger.exchange("code", None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_exchange_json_parse_error() {
    let mock_server = MockServer::start().await;
    let config = GoogleCodeExchangerConfig {
        client_id: "client_id".to_string(),
        client_secret: "client_secret".to_string(),
        token_url: mock_server.uri(),
        redirect_uri: "http://localhost/callback".to_string(),
        timeout: Duration::from_secs(5),
        max_retries: 0,
    };

    let validator = Arc::new(MockExternalTokenValidatorMock::new());
    let http_client = reqwest::Client::new();
    let exchanger = GoogleCodeExchanger::new(config, http_client, validator);

let _mock = Mock::given(method("POST"))
    .and(path("/"))
    .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
    .mount(&mock_server)
    .await;


    let result: Result<ExternalIdentity, CoreError> = exchanger.exchange("code", None).await;
    let err = result.unwrap_err();
    assert!(matches!(err, CoreError::Authentication(AuthenticationError::InvalidExternalToken { .. })));
}
