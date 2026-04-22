//! Port definitions for the core usecases module.
//!
//! These traits define the contracts for all external dependencies required by the use cases layer.
//! No infrastructure or implementation details are present here.
//!
//! Adapters must implement these traits to provide concrete behavior.

pub mod identity_repository;
pub mod external_identity_repository;
pub mod credential_repository;
pub mod session_repository;
pub mod password_hasher;
pub mod token_service;
pub mod clock;
pub mod service_registry;
pub mod external_token_validator;
pub mod exchange_authorization_code;
pub mod user_service_client;

pub use identity_repository::IdentityRepository;
pub use external_identity_repository::ExternalIdentityRepository;
pub use credential_repository::CredentialRepository;
pub use session_repository::SessionRepository;
pub use password_hasher::PasswordHasher;
pub use token_service::TokenService;
pub use clock::Clock;
pub use service_registry::ServiceRegistry;
pub use external_token_validator::{ExternalTokenValidator, ExternalClaims};
pub use exchange_authorization_code::ExchangeAuthorizationCode;
pub use user_service_client::{UserServiceClient, RegisterGoogleUserRequest};

