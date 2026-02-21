// HTTP middleware for request processing and security

/*
This module defines middleware for HTTP request processing.

Middleware handles:
 - Authentication (Bearer tokens, service credentials)
 - Authorization (permission checks)
 - Cross-cutting concerns (tracing, rate limiting)

Design Principles:
 - **Composable**: Middleware can be combined and ordered
 - **Non-invasive**: Middleware doesn't affect handler business logic
 - **Early rejection**: Invalid requests are rejected before handlers run
 - **Clear separation**: Internal vs public middleware are separate

Middleware types:
 - `auth`: Validates Bearer tokens for public endpoints
 - `service_auth`: Validates service credentials for internal endpoints
*/

pub mod auth;
pub mod service_auth;

pub use auth::bearer_auth;
pub use service_auth::service_auth;

#[cfg(test)]
pub mod tests;