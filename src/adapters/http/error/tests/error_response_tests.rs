// Tests for error response projection and serialization
use crate::adapters::http::error::{http_error::*, error_response::*};

#[test]
fn test_error_response_from_validation_error() {
    let error = HttpError::Validation(ValidationError::with_field("Required", "email"));
    let response = ErrorResponse::from_http_error(&error);

    assert_eq!(response.status, 400);
    assert_eq!(response.code, "VALIDATION_ERROR");
    assert!(response.details.is_some());
    assert_eq!(response.details.as_ref().unwrap().field, Some("email".to_string()));
}

#[test]
fn test_error_response_from_unauthorized_error() {
    let error = HttpError::Unauthorized(UnauthorizedError::new("Invalid token"));
    let response = ErrorResponse::from_http_error(&error);

    assert_eq!(response.status, 401);
    assert_eq!(response.code, "UNAUTHORIZED");
    assert!(response.details.is_none());
}

#[test]
fn test_error_response_from_conflict_error() {
    let error = HttpError::Conflict(ConflictError::with_resource("Duplicate entry", "Credential"));
    let response = ErrorResponse::from_http_error(&error);

    assert_eq!(response.status, 409);
    assert_eq!(response.code, "CONFLICT");
    assert!(response.details.is_some());
}

#[test]
fn test_error_response_from_not_found_error() {
    let error = HttpError::NotFound(NotFoundError::with_resource_type("Not found", "Session"));
    let response = ErrorResponse::from_http_error(&error);

    assert_eq!(response.status, 404);
    assert_eq!(response.code, "NOT_FOUND");
    assert!(response.details.is_some());
}

#[test]
fn test_error_response_internal_hides_sensitive_info() {
    let error = HttpError::Internal(InternalError::with_details(
        "Database connection failed",
        "Password: secret, Host: internal-db.local",
    ));
    let response = ErrorResponse::from_http_error(&error);

    assert_eq!(response.status, 500);
    assert_eq!(response.code, "INTERNAL_SERVER_ERROR");
    assert!(!response.message.contains("Database"));
    assert!(!response.message.contains("secret"));
}

#[test]
fn test_error_response_serialization() {
    let error = HttpError::Validation(ValidationError::with_field("Invalid format", "date"));
    let response = ErrorResponse::from_http_error(&error);
    let json = serde_json::to_string(&response).expect("Should serialize");

    assert!(json.contains("VALIDATION_ERROR"));
    assert!(json.contains("400"));
    assert!(json.contains("date"));
}

#[test]
fn test_error_response_details_not_included_when_empty() {
    let error = HttpError::Unauthorized(UnauthorizedError::new("Missing credentials"));
    let response = ErrorResponse::from_http_error(&error);
    let json = serde_json::to_string(&response).expect("Should serialize");

    // details field should not be in JSON if None
    assert!(!json.contains("details"));
}
