// Internal service DTOs
pub mod create_credential;

pub use create_credential::{CreateCredentialRequest, CreateCredentialResponse};

#[cfg(test)]
pub mod tests;
