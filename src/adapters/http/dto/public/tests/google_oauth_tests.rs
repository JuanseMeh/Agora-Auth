//! Tests for Google OAuth DTOs

use crate::adapters::http::dto::public::google_oauth::{
    GoogleCodeExchangeRequest, GoogleCodeExchangeResponse,
};
use serde_json::{json, Value};

// ============================================================================
// GoogleCodeExchangeRequest Tests
// ============================================================================

#[test]
fn test_google_code_exchange_request_validation_success() {
    let request = GoogleCodeExchangeRequest {
        code: "valid_google_code_123".to_string(),
        state: Some("csrf_state_xyz".to_string()),
    };

    assert!(request.validate().is_ok());
}

#[test]
fn test_google_code_exchange_request_validation_success_no_state() {
    let request = GoogleCodeExchangeRequest {
        code: "valid_google_code_123".to_string(),
        state: None,
    };

    assert!(request.validate().is_ok());
}

#[test]
fn test_google_code_exchange_request_empty_code() {
    let request = GoogleCodeExchangeRequest {
        code: "".to_string(),
        state: None,
    };

    let result = request.validate();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Authorization code required".to_string());
}

#[test]
fn test_google_code_exchange_request_whitespace_code() {
    let request = GoogleCodeExchangeRequest {
        code: "   ".to_string(),
        state: None,
    };

    let result = request.validate();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Authorization code required".to_string());
}

#[test]
fn test_google_code_exchange_request_serialization() {
    let request = GoogleCodeExchangeRequest {
        code: "auth_code_456".to_string(),
        state: Some("state_789".to_string()),
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(json.contains(r#"code":"auth_code_456"#));
    assert!(json.contains(r#"state":"state_789"#));
}

#[test]
fn test_google_code_exchange_request_deserialization_valid() {
    let json = json!({
        "code": "auth_code_456",
        "state": "state_789"
    });

    let request: GoogleCodeExchangeRequest = serde_json::from_value(json).unwrap();
    assert_eq!(request.code, "auth_code_456".to_string());
    assert_eq!(request.state, Some("state_789".to_string()));
}

#[test]
fn test_google_code_exchange_request_deserialization_no_state() {
    let json = json!({
        "code": "auth_code_456"
    });

    let request: GoogleCodeExchangeRequest = serde_json::from_value(json).unwrap();
    assert_eq!(request.code, "auth_code_456".to_string());
    assert_eq!(request.state, None);
}

#[test]
fn test_google_code_exchange_request_deserialization_missing_code() {
    let json = json!({
        "state": "state_789"
    });

    let result: Result<GoogleCodeExchangeRequest, _> = serde_json::from_value(json);
    assert!(result.is_err());
}

// ============================================================================
// GoogleCodeExchangeResponse Tests
// ============================================================================

#[test]
fn test_google_code_exchange_response_structure() {
    let response = GoogleCodeExchangeResponse {
        access_token: "jwt.access.token".to_string(),
        refresh_token: "refresh.token".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 3600,
        session_id: "session_uuid".to_string(),
    };

    assert_eq!(response.access_token, "jwt.access.token".to_string());
    assert_eq!(response.refresh_token, "refresh.token".to_string());
    assert_eq!(response.token_type, "Bearer".to_string());
    assert_eq!(response.expires_in, 3600u64);
    assert_eq!(response.session_id, "session_uuid".to_string());
}

#[test]
fn test_google_code_exchange_response_serialization() {
    let response = GoogleCodeExchangeResponse {
        access_token: "new_jwt".to_string(),
        refresh_token: "new_refresh".to_string(),
        token_type: "Bearer".to_string(),
        expires_in: 7200,
        session_id: "new_session".to_string(),
    };

    let json_str = serde_json::to_string(&response).unwrap();
    let parsed: Value = serde_json::from_str(&json_str).unwrap();

    assert_eq!(parsed["access_token"], "new_jwt");
    assert_eq!(parsed["token_type"], "Bearer");
    assert_eq!(parsed["expires_in"], 7200);
}

