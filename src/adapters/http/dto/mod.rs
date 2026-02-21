// HTTP Data Transfer Objects (DTOs)

/*
This module defines all DTOs for HTTP requests and responses.

DTOs are organized by visibility:
 - `internal`: DTOs for internal service-to-service communication (requires mTLS/service auth)
 - `public`: DTOs for public-facing endpoints

Design Principles:
 - **Transport only**: DTOs are never used in business logic
 - **Validation**: DTOs validate structure but not business rules
 - **Serialization**: All DTOs are JSON-serializable via serde
 - **Immutable**: DTOs are data containers with no behavior
 - **Clean separation**: Internal vs public DTOs are strictly separated
*/

pub mod internal;
pub mod public;

pub use internal::{CreateCredentialRequest, CreateCredentialResponse};
pub use public::{AuthenticateRequest, AuthenticateResponse, RefreshTokenRequest, RefreshTokenResponse};
