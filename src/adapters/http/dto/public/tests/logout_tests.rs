//! Tests for logout DTOs

use crate::adapters::http::dto::public::{LogoutRequest, LogoutResponse};

// ============================================================================
// LogoutRequest Tests
// ============================================================================

#[test]
fn test_logout_request_valid_with_session_id() {
    let request = LogoutRequest {
        session_id: Some("session-123".to_string()),
        refresh_token: None,
    };
    
    assert!(request.validate().is_ok());
}

#[test]
fn test_logout_request_valid_with_refresh_token() {
    let request = LogoutRequest {
        session_id: None,
        refresh_token: Some("refresh-token-abc".to_string()),
    };
    
    assert!(request.validate().is_ok());
}

#[test]
fn test_logout_request_valid_with_both() {
    let request = LogoutRequest {
        session_id: Some("session-123".to_string()),
        refresh_token: Some("refresh-token-abc".to_string()),
    };
    
    assert!(request.validate().is_ok());
}

#[test]
fn test_logout_request_invalid_neither_provided() {
    let request = LogoutRequest {
        session_id: None,
        refresh_token: None,
    };
    
    let result = request.validate();
    assert!(result.is_err());
    let err_msg = result.unwrap_err();
    assert!(err_msg.contains("session_id") || err_msg.contains("refresh_token"));
}

#[test]
fn test_logout_request_empty_session_id_valid() {
    // Empty string is still a provided value
    let request = LogoutRequest {
        session_id: Some("".to_string()),
        refresh_token: None,
    };
    
    assert!(request.validate().is_ok());
}

#[test]
fn test_logout_request_empty_refresh_token_valid() {
    // Empty string is still a provided value
    let request = LogoutRequest {
        session_id: None,
        refresh_token: Some("".to_string()),
    };
    
    assert!(request.validate().is_ok());
}

// ============================================================================
// LogoutResponse Tests
// ============================================================================

#[test]
fn test_logout_response_success() {
    let response = LogoutResponse {
        success: true,
        message: "Successfully logged out".to_string(),
        session_id: Some("session-123".to_string()),
    };
    
    assert!(response.success);
    assert_eq!(response.message, "Successfully logged out");
    assert_eq!(response.session_id, Some("session-123".to_string()));
}

#[test]
fn test_logout_response_failure() {
    let response = LogoutResponse {
        success: false,
        message: "Session not found".to_string(),
        session_id: None,
    };
    
    assert!(!response.success);
    assert_eq!(response.message, "Session not found");
    assert_eq!(response.session_id, None);
}

#[test]
fn test_logout_response_serialization() {
    let response = LogoutResponse {
        success: true,
        message: "Logged out".to_string(),
        session_id: Some("sess-abc".to_string()),
    };
    
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"success\":true"));
    assert!(json.contains("\"message\":\"Logged out\""));
    assert!(json.contains("\"session_id\":\"sess-abc\""));
}

#[test]
fn test_logout_request_deserialization() {
    let json = r#"{"session_id":"sess-123","refresh_token":"token-abc"}"#;
    let request: LogoutRequest = serde_json::from_str(json).unwrap();
    
    assert_eq!(request.session_id, Some("sess-123".to_string()));
    assert_eq!(request.refresh_token, Some("token-abc".to_string()));
}

#[test]
fn test_logout_request_deserialization_partial() {
    let json = r#"{"session_id":"sess-123"}"#;
    let request: LogoutRequest = serde_json::from_str(json).unwrap();
    
    assert_eq!(request.session_id, Some("sess-123".to_string()));
    assert_eq!(request.refresh_token, None);
}
