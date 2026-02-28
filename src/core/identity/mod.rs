// Core identity vocabulary for the authentication domain.

pub mod user_identity;
pub mod workspace_identity;
pub mod contextual_identity;
pub mod identity_claims;

pub use user_identity::UserIdentity;
pub use workspace_identity::WorkspaceIdentity;
pub use contextual_identity::ContextualIdentity;
pub use identity_claims::IdentityClaims;

#[cfg(test)]
mod tests;
