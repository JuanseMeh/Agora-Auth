// HTTP adapter — Axum-based REST API layer for authentication

/*
This module implements the HTTP transport layer for the authentication service.

It is responsible for:
 - Accepting HTTP requests and mapping them to domain operations
 - Validating request structure and format
 - Delegating business logic to application services
 - Mapping domain errors to appropriate HTTP status codes
 - Returning structured JSON responses

It is NOT responsible for:
 - Business logic or policy enforcement (delegated to services)
 - Database persistence (delegated to repositories)
 - Cryptography (delegated to crypto adapter)
 - Token generation/validation (delegated to token services)

All modules in this adapter implement or use patterns defined in domain and ports.
HTTP errors are mapped to domain-level errors and back to response codes.

# Route Structure

- `/internal/ *` - Service-to-service endpoints (require service auth)
- `/public/ *` - User-facing endpoints (require bearer auth or rate limiting)
- `/health/ *` - Liveness and readiness probes (no auth required)

# Architecture Layers

- `dto`: HTTP Data Transfer Objects (request/response contracts)
- `handlers`: HTTP request handlers (deserialization, validation, response)
- `middleware`: Cross-cutting concerns (auth, logging, rate limiting)
- `error`: HTTP error types and response projection
- `state`: Shared application state
- `router`: Route configuration and setup
*/

pub mod dto;
pub mod handlers;
pub mod middleware;
pub mod error;
pub mod state;
pub mod router;

pub use dto::{
    CreateCredentialRequest, CreateCredentialResponse,
    AuthenticateRequest, AuthenticateResponse,
    RefreshTokenRequest, RefreshTokenResponse,
};
pub use error::{
    HttpError, ErrorResponse,
    ValidationError, UnauthorizedError, ConflictError, NotFoundError, InternalError,
};
pub use state::AppState;
pub use router::create_router;

#[cfg(test)]
pub mod tests;