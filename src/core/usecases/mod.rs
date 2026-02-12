
//! Core authentication use cases and business orchestration layer.
//!
//! This module defines the orchestration logic for authentication, session, and token flows.
//! It coordinates the core domain types (identity, credentials, token) and enforces business rules
//! via policies and input/output contracts. All infrastructure concerns are abstracted via ports.
//!
//! # Responsibilities
//!
//! - Orchestrate identity, credential, token, and session flows
//! - Enforce business policies (lockout, token lifetime, session rotation)
//! - Define input/output contracts for use cases
//! - Depend only on core domain and ports
//! - Contain zero infrastructure logic
//!
//! # Constraints
//!
//! - No direct database, HTTP, or cryptographic logic
//! - No infrastructure types or models
//! - All external dependencies are abstracted via ports
//!
//! # Main Use Cases
//!
//! - [`AuthenticateUser`]
//! - [`IssueSession`]
//! - [`RefreshSession`]
//! - [`RevokeSession`]
//! - [`ValidateAccessToken`]
//!
//! # Policies
//!
//! - [`LockoutPolicy`]
//! - [`TokenPolicy`]
//!
//! # Ports
//!
//! - [`IdentityRepository`]
//! - [`CredentialRepository`]
//! - [`SessionRepository`]
//! - [`PasswordHasher`]
//! - [`TokenService`]
//! - [`Clock`]

pub mod authenticate_user;
pub mod issue_session;
pub mod refresh_session;
pub mod revoke_session;
pub mod validate_access_token;

pub mod policies;
pub mod ports;

pub use authenticate_user::*;
pub use issue_session::*;
pub use refresh_session::*;
pub use revoke_session::*;
pub use validate_access_token::*;

pub use policies::*;
pub use ports::*;