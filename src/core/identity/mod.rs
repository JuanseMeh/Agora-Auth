// Core identity vocabulary for the authentication domain.

pub mod user_identity;
pub mod contextual_identity;
pub mod identity_claims;
pub mod external_identity;

pub use user_identity::UserIdentity;
pub use contextual_identity::ContextualIdentity;
pub use identity_claims::IdentityClaims;
pub use external_identity::ExternalIdentity;

#[cfg(test)]
mod tests;
