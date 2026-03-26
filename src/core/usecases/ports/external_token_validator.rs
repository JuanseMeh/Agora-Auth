/// Port for external (OAuth/OpenID) token validation.
///
/// Abstracts provider-specific ID token verification (Google RS256, GitHub JWT, etc.).
/// Returns domain ExternalIdentity on success.
/// Providers implement this trait in adapters/crypto/token/.

use crate::core::identity::ExternalIdentity;
use crate::core::error::{CoreError};
use futures::future::BoxFuture;

/// Trait for validating external provider ID tokens (e.g., Google ID token).
///
/// Implementations handle:
/// - Signature verification (RS256, etc.)
/// - Issuer validation
/// - Audience validation
/// - Claims extraction -> ExternalIdentity
pub trait ExternalTokenValidator: Send + Sync {
    /// Validate external ID token and extract identity.
    ///
    /// # Errors
    /// - InvalidExternalToken: Signature/issuer/audience/expiry failure
    /// - InvalidExternalIdentity: Malformed claims (missing sub)
    fn validate(&self, token: &str) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>>;
}

/// Claims extracted from external tokens before mapping to ExternalIdentity.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct ExternalClaims {
    pub sub: String,
    pub email: Option<String>,
    // Additional claims as needed (iss, aud verified by impl)
}
