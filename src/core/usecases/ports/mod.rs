//! Port definitions for the core usecases module.
//!
//! These traits define the contracts for all external dependencies required by the use cases layer.
//! No infrastructure or implementation details are present here.
//!
//! Adapters must implement these traits to provide concrete behavior.

pub mod identity_repository;
pub mod credential_repository;
pub mod session_repository;
pub mod password_hasher;
pub mod token_service;
pub mod clock;
pub mod service_registry;


pub use identity_repository::IdentityRepository;
pub use credential_repository::CredentialRepository;
pub use session_repository::SessionRepository;
pub use password_hasher::PasswordHasher;
pub use token_service::TokenService;
pub use clock::Clock;
pub use service_registry::ServiceRegistry;
