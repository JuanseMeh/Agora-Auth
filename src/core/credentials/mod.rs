//! Core credential domain types and validation primitives.
//
// These modules define the vocabulary and semantics for credentials in the core
// authentication domain. They intentionally avoid any hashing, persistence, or
// cryptographic details — those belong to adapters and ports.

pub mod raw_credential;
pub mod stored_credential;
pub mod credential_status;
pub mod credential_policy;
pub mod recovery_token;

pub use raw_credential::RawCredential;
pub use stored_credential::StoredCredential;
pub use credential_status::CredentialStatus;
pub use credential_policy::CredentialPolicy;
pub use recovery_token::RecoveryToken;

#[cfg(test)]
mod tests;

