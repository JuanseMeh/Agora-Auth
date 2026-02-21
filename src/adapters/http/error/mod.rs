// HTTP adapter error types and response projection.

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
 - `HttpError`: Core HTTP error type with semantic variants
 - `ErrorResponse`: Projection of HttpError to JSON response format
*/

pub mod http_error;
pub mod error_response;

pub use http_error::{
    HttpError, ValidationError, UnauthorizedError, ConflictError, NotFoundError, LockedError, InternalError,
};
pub use error_response::ErrorResponse;

#[cfg(test)]
mod tests;