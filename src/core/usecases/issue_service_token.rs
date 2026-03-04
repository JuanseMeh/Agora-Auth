//! Use case: IssueServiceToken
//!
//! Orchestrates service-to-service authentication token issuance.
//!
//! Responsibilities:
//! - Validate service credentials via ServiceRegistry
//! - Issue JWT with typ: service claim for security
//! - Return service token and expiration

use std::sync::Arc;

use crate::core::error::CoreError;
use crate::core::token::Token;
use crate::core::usecases::ports::{PasswordHasher, ServiceRegistry, TokenService};

/// Input contract for IssueServiceToken use case.
pub struct IssueServiceTokenInput {
    /// Service identifier (e.g., "user_service")
    pub service_id: String,
    /// Service secret to validate
    pub service_secret: String,
}

/// Output contract for IssueServiceToken use case.
#[derive(Debug)]
pub struct IssueServiceTokenOutput {
    /// JWT token for service authentication
    pub access_token: Token,
    /// Token expiration time in seconds
    pub expires_in: u64,
}

/// Use case for issuing service-to-service authentication tokens.
pub struct IssueServiceToken<'a> {
    service_registry: &'a (dyn ServiceRegistry + Send + Sync),
    password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
    token_service: &'a (dyn TokenService + Send + Sync),
    service_token_ttl_seconds: u64,
}

impl<'a> IssueServiceToken<'a> {
    /// Create a new IssueServiceToken use case with dependencies.
    pub fn new(
        service_registry: &'a (dyn ServiceRegistry + Send + Sync),
        password_hasher: Arc<dyn PasswordHasher + Send + Sync>,
        token_service: &'a (dyn TokenService + Send + Sync),
        service_token_ttl_seconds: u64,
    ) -> Self {
        Self {
            service_registry,
            password_hasher,
            token_service,
            service_token_ttl_seconds,
        }
    }

    /// Execute the service token issuance use case.
    pub async fn execute(
        &self,
        input: IssueServiceTokenInput,
    ) -> Result<IssueServiceTokenOutput, CoreError> {
        // Step 1: Validate service credentials
        tracing::debug!(
            "[ISSUE_SERVICE_TOKEN] Validating credentials for service: {}",
            input.service_id
        );

        let valid_service_id = self
            .service_registry
            .validate_credentials(
                &input.service_id,
                &input.service_secret,
                self.password_hasher.clone(),
            )
            .ok_or_else(|| {
                tracing::warn!(
                    "[ISSUE_SERVICE_TOKEN] Invalid credentials for service: {}",
                    input.service_id
                );
                CoreError::Authentication(
                    crate::core::error::AuthenticationError::InvalidCredentials,
                )
            })?;

        tracing::debug!(
            "[ISSUE_SERVICE_TOKEN] Credentials validated for service: {}",
            valid_service_id
        );

        // Step 2: Check if service is active
        if !self.service_registry.is_service_active(&valid_service_id) {
            tracing::warn!(
                "[ISSUE_SERVICE_TOKEN] Service is not active: {}",
                valid_service_id
            );
            return Err(CoreError::Authentication(
                crate::core::error::AuthenticationError::ServiceNotActive,
            ));
        }

        // Step 3: Build service token claims
        let claims = self.build_service_claims(&valid_service_id);

        // Step 4: Issue service token
        tracing::debug!(
            "[ISSUE_SERVICE_TOKEN] Issuing service token for: {}",
            valid_service_id
        );
        let access_token = self.token_service.issue_service_token(&valid_service_id, &claims);

        tracing::info!(
            "[ISSUE_SERVICE_TOKEN] Service token issued successfully for: {}",
            valid_service_id
        );

        Ok(IssueServiceTokenOutput {
            access_token,
            expires_in: self.service_token_ttl_seconds,
        })
    }

    fn build_service_claims(&self, service_id: &str) -> String {
        // Build claims for service token including typ: service for security
        format!(
            r#"{{"sub":"{}","type":"service","exp":{},"iss":"auth_service","aud":"auth_service"}}"#,
            service_id,
            chrono::Utc::now().timestamp() + self.service_token_ttl_seconds as i64
        )
    }
}

