// HTTP-specific error types for the authentication adapter.

/*
This module defines errors specific to the HTTP adapter layer.

These errors represent failures in HTTP request handling, validation, and projection,
independent of business logic. They are NOT domain errors.

Design Principles:
 - **Isolation**: HTTP errors never leak domain or persistence details upward
 - **Projection**: Domain errors are mapped to appropriate HTTP status codes
 - **No panic**: All HTTP operations return Results
 - **User-safe**: Error messages are safe to expose to clients
 - **Semantic**: Each error type has clear meaning for HTTP handlers

Errors are organized by concern:
 - `ValidationError`: Input validation failures (400)
 - `AuthenticationError`: Authentication failures (401)
 - `ConflictError`: Resource conflict (409)
 - `NotFoundError`: Resource not found (404)
 - `InternalError`: Unexpected server errors (500)
 - `HttpError`: Top-level enum that wraps all of the above
*/

use std::fmt;

#[derive(Debug, Clone)]
pub enum HttpError {
    /// Input validation failed (400 Bad Request)
    Validation(ValidationError),
    /// Authentication failed (401 Unauthorized)
    Unauthorized(UnauthorizedError),
    /// Resource conflict (409 Conflict)
    Conflict(ConflictError),
    /// Resource not found (404 Not Found)
    NotFound(NotFoundError),
    /// Account locked (423 Locked)
    Locked(LockedError),
    /// Unexpected server error (500 Internal Server Error)
    Internal(InternalError),
}

impl HttpError {
    /// Returns the HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        match self {
            HttpError::Validation(_) => 400,
            HttpError::Unauthorized(_) => 401,
            HttpError::Conflict(_) => 409,
            HttpError::NotFound(_) => 404,
            HttpError::Locked(_) => 423,
            HttpError::Internal(_) => 500,
        }
    }

    /// Returns true if this is a validation error
    pub fn is_validation(&self) -> bool {
        matches!(self, HttpError::Validation(_))
    }

    /// Returns true if this is an unauthorized error
    pub fn is_unauthorized(&self) -> bool {
        matches!(self, HttpError::Unauthorized(_))
    }

    /// Returns true if this is a conflict error
    pub fn is_conflict(&self) -> bool {
        matches!(self, HttpError::Conflict(_))
    }

    /// Returns true if this is a not found error
    pub fn is_not_found(&self) -> bool {
        matches!(self, HttpError::NotFound(_))
    }

    /// Returns true if this is an internal error
    pub fn is_internal(&self) -> bool {
        matches!(self, HttpError::Internal(_))
    }

    /// Returns true if this is a locked error
    pub fn is_locked(&self) -> bool {
        matches!(self, HttpError::Locked(_))
    }
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Validation(e) => write!(f, "Validation error: {}", e),
            HttpError::Unauthorized(e) => write!(f, "Unauthorized: {}", e),
            HttpError::Conflict(e) => write!(f, "Conflict: {}", e),
            HttpError::NotFound(e) => write!(f, "Not found: {}", e),
            HttpError::Locked(e) => write!(f, "Locked: {}", e),
            HttpError::Internal(e) => write!(f, "Internal error: {}", e),
        }
    }
}

impl std::error::Error for HttpError {}

impl axum::response::IntoResponse for HttpError {
    fn into_response(self) -> axum::response::Response {
        use axum::http::StatusCode;
        use axum::Json;
        
        let status = StatusCode::from_u16(self.status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        
        let error_response = crate::adapters::http::error::error_response::ErrorResponse::from_http_error(&self);
        
        (status, Json(error_response)).into_response()
    }
}

// ============================================================================
// Specific Error Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub message: String,
    pub field: Option<String>,
}

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            field: None,
        }
    }

    pub fn with_field(message: impl Into<String>, field: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            field: Some(field.into()),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(field) = &self.field {
            write!(f, "{}: {}", field, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnauthorizedError {
    pub reason: String,
}

impl UnauthorizedError {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for UnauthorizedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)
    }
}

#[derive(Debug, Clone)]
pub struct ConflictError {
    pub message: String,
    pub resource: Option<String>,
}

impl ConflictError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            resource: None,
        }
    }

    pub fn with_resource(message: impl Into<String>, resource: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            resource: Some(resource.into()),
        }
    }
}

impl fmt::Display for ConflictError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(resource) = &self.resource {
            write!(f, "{}: {}", resource, self.message)
        } else {
            write!(f, "{}", self.message)
        }
    }
}

#[derive(Debug, Clone)]
pub struct NotFoundError {
    pub message: String,
    pub resource_type: Option<String>,
}

impl NotFoundError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            resource_type: None,
        }
    }

    pub fn with_resource_type(message: impl Into<String>, resource_type: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            resource_type: Some(resource_type.into()),
        }
    }
}

impl fmt::Display for NotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, Clone)]
pub struct LockedError {
    pub message: String,
    pub retry_after: Option<u64>,
}

impl LockedError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            retry_after: None,
        }
    }

    pub fn with_retry_after(message: impl Into<String>, retry_after: u64) -> Self {
        Self {
            message: message.into(),
            retry_after: Some(retry_after),
        }
    }
}

impl fmt::Display for LockedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

#[derive(Debug, Clone)]
pub struct InternalError {
    pub message: String,
    pub details: Option<String>,
}

impl InternalError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(message: impl Into<String>, details: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            details: Some(details.into()),
        }
    }
}

impl fmt::Display for InternalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
