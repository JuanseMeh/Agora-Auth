//! Use case: ExchangeGoogleCode
//!
//! Orchestrates server-side OAuth authorization code exchange for Google.
//! 
//! This use case is Google-specific in name but uses provider-agnostic ports.
//! It represents the complete \"code -> identity\" step of the OAuth flow.
//!
//! Responsibilities:
//! - Validate input parameters (non-empty code)
//! - Delegate to ExchangeAuthorizationCode port (handles HTTP exchange + ID token validation)
//! - Return domain ExternalIdentity for higher layers (user resolution / session issuance)
//!
//! Does NOT handle user resolution or session issuance (separate use cases).

use crate::core::error::{CoreError, AuthenticationError};
use crate::core::identity::ExternalIdentity;
use crate::core::usecases::ports::ExchangeAuthorizationCode;

/// Input contract for ExchangeGoogleCode use case.
#[derive(Debug, Clone)]
pub struct ExchangeGoogleCodeInput {
    /// OAuth authorization code from Google redirect
    pub code: String,
    /// CSRF state parameter (recommended)
    pub state: Option<String>,
}

/// Output contract - validated ExternalIdentity from Google claims.
#[derive(Debug, Clone)]
pub struct ExchangeGoogleCodeOutput {
    pub identity: ExternalIdentity,
}

/// Use case orchestrator for Google OAuth code exchange.
pub struct ExchangeGoogleCode<'a> {
    exchange_port: &'a (dyn ExchangeAuthorizationCode + Send + Sync),
}

impl<'a> ExchangeGoogleCode<'a> {
    pub fn new(
        exchange_port: &'a (dyn ExchangeAuthorizationCode + Send + Sync),
    ) -> Self {
        Self { exchange_port }
    }

    pub async fn execute(&self, input: ExchangeGoogleCodeInput) -> Result<ExchangeGoogleCodeOutput, CoreError> {
        // Input validation
        if input.code.trim().is_empty() {
            return Err(AuthenticationError::IncompleteFlow {
stage: "empty authorization code".to_string(),
            }.into());
        }

        // Delegate to port (handles exchange + validation)
        let identity = self.exchange_port
            .exchange(&input.code, input.state.as_deref())
            .await?;

        Ok(ExchangeGoogleCodeOutput { identity })
    }
}

