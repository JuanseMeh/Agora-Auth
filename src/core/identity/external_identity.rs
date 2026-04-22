use crate::core::error::{CoreError, AuthenticationError};

/// Domain representation of an external identity from OAuth/OpenID providers.
///
/// Maps directly to `external_identities` table structure.
/// Provider-agnostic: works for Google, GitHub, etc.
///
/// # Design
/// - Value object (immutable)
/// - No provider-specific fields
/// - Serializable for claims/DTOs
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExternalIdentity {
    /// OAuth provider name (google, github, etc.)
    pub provider: String,
    /// Provider's unique user ID (sub claim)
    pub provider_user_id: String,
    /// Email (if provided by provider)
    pub email: Option<String>,
    /// Name (Optional non stored field)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Family name (Optional non stored field)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    /// Picture URL (Optional non stored field)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

impl ExternalIdentity {
    /// Create new ExternalIdentity.
    pub fn new(
        provider: String, 
        provider_user_id: String, 
        email: Option<String>, 
        name: Option<String>, 
        family_name: Option<String>, 
        picture: Option<String>
        
    ) -> Result<Self, CoreError> {
    if provider.trim().is_empty() {
        return Err(AuthenticationError::InvalidExternalIdentity {
            reason: "empty provider name".to_string()
        }.into());
    }
    if provider_user_id.trim().is_empty() {
        return Err(AuthenticationError::InvalidExternalIdentity {
            reason: "empty provider user ID".to_string()
        }.into());
    }
        Ok(Self {
            provider,
            provider_user_id,
            email,
            name,
            family_name,
            picture,
        })
    }
}

