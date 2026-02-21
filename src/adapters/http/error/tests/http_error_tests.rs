// Tests for HttpError type and status code mapping
use crate::adapters::http::error::http_error::*;

#[test]
fn test_http_error_validation_status_code() {
    let error = HttpError::Validation(ValidationError::new("Invalid input"));
    assert_eq!(error.status_code(), 400);
}

#[test]
fn test_http_error_unauthorized_status_code() {
    let error = HttpError::Unauthorized(UnauthorizedError::new("Missing token"));
    assert_eq!(error.status_code(), 401);
}

#[test]
fn test_http_error_conflict_status_code() {
    let error = HttpError::Conflict(ConflictError::new("Resource exists"));
    assert_eq!(error.status_code(), 409);
}

#[test]
fn test_http_error_not_found_status_code() {
    let error = HttpError::NotFound(NotFoundError::new("Not found"));
    assert_eq!(error.status_code(), 404);
}

#[test]
fn test_http_error_internal_status_code() {
    let error = HttpError::Internal(InternalError::new("Server error"));
    assert_eq!(error.status_code(), 500);
}

#[test]
fn test_http_error_type_checks() {
    let validation_error = HttpError::Validation(ValidationError::new("Invalid"));
    assert!(validation_error.is_validation());
    assert!(!validation_error.is_unauthorized());

    let unauthorized_error = HttpError::Unauthorized(UnauthorizedError::new("Unauthorized"));
    assert!(unauthorized_error.is_unauthorized());
    assert!(!unauthorized_error.is_validation());
}

#[test]
fn test_validation_error_with_field() {
    let error = ValidationError::with_field("Too weak", "password");
    assert_eq!(error.field, Some("password".to_string()));
    assert!(error.to_string().contains("password"));
    assert!(error.to_string().contains("Too weak"));
}

#[test]
fn test_validation_error_without_field() {
    let error = ValidationError::new("Generic error");
    assert_eq!(error.field, None);
    assert_eq!(error.to_string(), "Generic error");
}

#[test]
fn test_conflict_error_with_resource() {
    let error = ConflictError::with_resource("Already exists", "User");
    assert_eq!(error.resource, Some("User".to_string()));
}

#[test]
fn test_not_found_error_with_resource_type() {
    let error = NotFoundError::with_resource_type("User 123 not found", "User");
    assert_eq!(error.resource_type, Some("User".to_string()));
}

#[test]
fn test_internal_error_with_details() {
    let error = InternalError::with_details("Failed", "DB timeout");
    assert_eq!(error.details, Some("DB timeout".to_string()));
}
