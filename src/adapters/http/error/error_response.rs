// HTTP error response projection and serialization.

/*
This module defines how domain and adapter errors are projected to HTTP responses.

It is responsible for:
 - Converting HttpError to JSON response bodies
 - Mapping status codes to response structures
 - Hiding sensitive information from client responses
 - Maintaining consistent error response format

Design Principles:
 - **User-safe**: No internal details leak to clients
 - **Semantic**: Response structure matches HTTP semantics
 - **Structured**: Responses are consistent and machine-readable
 - **Idempotent**: Same error always produces same response
*/

use serde::{Deserialize, Serialize};
use super::http_error::*;

/// Standard error response format for HTTP responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// HTTP status code
    pub status: u16,
    /// Machine-readable error code
    pub code: String,
    /// Human-readable error message
    pub message: String,
    /// Additional error details (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<ErrorDetails>,
}

/// Additional error context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetails {
    /// Field that caused the error (for validation errors)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Resource type that was affected
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Resource identifier if applicable
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
}

impl ErrorResponse {
    /// Create an error response from an HttpError
    pub fn from_http_error(error: &HttpError) -> Self {
        match error {
            HttpError::Validation(e) => Self::validation(e),
            HttpError::Unauthorized(e) => Self::unauthorized(e),
            HttpError::Conflict(e) => Self::conflict(e),
            HttpError::NotFound(e) => Self::not_found(e),
            HttpError::Locked(e) => Self::locked(e),
            HttpError::Internal(e) => Self::internal(e),
        }
    }

    /// Create a validation error response
    fn validation(error: &ValidationError) -> Self {
        Self {
            status: 400,
            code: "VALIDATION_ERROR".to_string(),
            message: error.to_string(),
            details: error.field.as_ref().map(|field| ErrorDetails {
                field: Some(field.clone()),
                resource_type: None,
                resource_id: None,
            }),
        }
    }

    /// Create an unauthorized error response
    fn unauthorized(error: &UnauthorizedError) -> Self {
        Self {
            status: 401,
            code: "UNAUTHORIZED".to_string(),
            message: error.to_string(),
            details: None,
        }
    }

    /// Create a conflict error response
    fn conflict(error: &ConflictError) -> Self {
        Self {
            status: 409,
            code: "CONFLICT".to_string(),
            message: error.to_string(),
            details: error.resource.as_ref().map(|resource| ErrorDetails {
                field: None,
                resource_type: Some(resource.clone()),
                resource_id: None,
            }),
        }
    }

    /// Create a not found error response
    fn not_found(error: &NotFoundError) -> Self {
        Self {
            status: 404,
            code: "NOT_FOUND".to_string(),
            message: error.to_string(),
            details: error.resource_type.as_ref().map(|resource_type| ErrorDetails {
                field: None,
                resource_type: Some(resource_type.clone()),
                resource_id: None,
            }),
        }
    }

    /// Create an internal error response (hides details from client)
    fn internal(_error: &InternalError) -> Self {
        Self {
            status: 500,
            code: "INTERNAL_SERVER_ERROR".to_string(),
            message: "An unexpected error occurred. Please try again later.".to_string(),
            details: None,
        }
    }

    /// Create a locked error response (423 Locked)
    fn locked(error: &LockedError) -> Self {
        Self {
            status: 423,
            code: "ACCOUNT_LOCKED".to_string(),
            message: error.to_string(),
            details: error.retry_after.map(|_seconds| ErrorDetails {
                field: None,
                resource_type: None,
                resource_id: None,
            }),
        }
    }
}
