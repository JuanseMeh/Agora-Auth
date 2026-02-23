// HTTP handlers for all endpoints

/*
This module defines all HTTP request handlers.

Handlers are organized by visibility:
 - `internal`: Handlers for internal service-to-service communication (requires mTLS/service auth)
 - `public`: Handlers for public-facing endpoints (requires rate limiting)

Design Principles:
 - **Transport layer**: Handlers only deserialize requests and serialize responses
 - **Validation delegation**: Structural validation happens on DTOs, business validation in services
 - **Error projection**: Domain/adapter errors are converted to HTTP errors
 - **No business logic**: All orchestration delegated to application services
 - **Clean separation**: Internal vs public handlers are strictly separated

Each handler is responsible for:
 1. Deserializing the request via Axum extractors
 2. Validating request structure via DTO.validate()
 3. Calling the application service
 4. Mapping results to HTTP responses
 5. Projecting errors to HTTP status codes
*/

pub mod internal;
pub mod public;

pub use internal::create_credential;
pub use public::{authenticate, logout, refresh_token, validate_token};