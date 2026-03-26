/// Port for exchanging OAuth authorization code for ExternalIdentity.
///
/// Abstracts the complete server-side authorization code flow step:
/// 1. Exchange code for tokens (HTTP call to provider)
/// 2. Validate ID token signature/claims
/// 3. Extract/map to ExternalIdentity domain type
///
/// This port encapsulates provider-specific logic (Google, GitHub, etc.) in adapters.
/// Core use cases depend only on this domain result, remaining provider-agnostic.
///
/// Returns ExternalIdentity on success, or appropriate AuthError on failure.
use crate::core::identity::ExternalIdentity;
use crate::core::error::CoreError;
use futures::future::BoxFuture;

pub trait ExchangeAuthorizationCode: Send + Sync {
    /// Exchange OAuth authorization code for validated ExternalIdentity.
    ///
    /// # Parameters
    /// - `code`: Authorization code from provider redirect (short-lived)
    /// - Optional `state`: CSRF protection parameter
    ///
    /// # Errors
    /// - Network/HTTP failures during token exchange
    /// - Invalid code, missing client credentials
    /// - ID token validation failure (sig, issuer, aud, exp)
    /// - Malformed claims (missing sub)
    ///
    /// # Example Flow (Google)
    /// 1. POST code to https://oauth2.googleapis.com/token
    /// 2. Extract id_token from response
    /// 3. Validate id_token using Google JWKS/RS256
    /// 4. Map claims.sub/email -> ExternalIdentity
    fn exchange(&self, code: &str, state: Option<&str>) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>>;
}

