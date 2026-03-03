// Internal service token handler
// Handles POST /internal/service/token - exchanges service credentials for JWT

use axum::{
    extract::State,
    Json,
};

use crate::adapters::http::{
    dto::internal::{IssueServiceTokenRequest, IssueServiceTokenResponse},
    error::{HttpError, ServiceUnauthorizedError, ValidationError, InternalError},
    state::AppState,
};

/// Issue a service token (service-to-service authentication)
///
/// # Returns
/// - 200 OK with service JWT token
/// - 400 Bad Request if validation fails
/// - 401 Unauthorized if credentials are invalid
/// - 500 Internal Server Error on server failure
pub async fn issue_service_token(
    State(state): State<AppState>,
    Json(request): Json<IssueServiceTokenRequest>,
) -> Result<Json<IssueServiceTokenResponse>, HttpError> {
    // Validate request
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    tracing::debug!(
        "[ISSUE_SERVICE_TOKEN] Request received for service: {}",
        request.service_id
    );

    // Create and execute the use case
    let use_case = crate::core::usecases::IssueServiceToken::new(
        state.service_registry.as_ref(),
        state.password_hasher.clone(),
        state.token_service.as_ref(),
        state.service_token_ttl_seconds,
    );

    let input = crate::core::usecases::IssueServiceTokenInput {
        service_id: request.service_id.clone(),
        service_secret: request.service_secret,
    };

    match use_case.execute(input).await {
        Ok(output) => {
            tracing::info!(
                "[ISSUE_SERVICE_TOKEN] Service token issued successfully for: {}",
                request.service_id
            );

            Ok(Json(IssueServiceTokenResponse {
                access_token: output.access_token.value().to_string(),
                expires_in: output.expires_in,
                token_type: "Bearer".to_string(),
            }))
        }
        Err(e) => {
            tracing::warn!(
                "[ISSUE_SERVICE_TOKEN] Failed to issue token for service {}: {}",
                request.service_id,
                e
            );

            // Map core errors to HTTP errors
            if let Some(auth_err) = e.as_authentication() {
                if auth_err.is_invalid_credentials() {
                    return Err(HttpError::ServiceUnauthorized(
                        ServiceUnauthorizedError::new("Invalid service credentials"),
                    ));
                }
                if auth_err.is_service_not_active() {
                    return Err(HttpError::ServiceUnauthorized(
                        ServiceUnauthorizedError::new("Service is not active"),
                    ));
                }
            }

            Err(HttpError::Internal(InternalError::new(format!(
                "Failed to issue service token: {}",
                e
            ))))
        }
    }
}
