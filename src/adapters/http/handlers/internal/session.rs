// Internal session token handler
// Handles POST /internal/token/issue - issues session tokens for a user

use axum::{
    extract::State,
    extract::Extension,
    Json,
};

use crate::adapters::http::{
    dto::internal::{IssueSessionTokensRequest, IssueSessionTokensResponse},
    error::{HttpError, ValidationError, InternalError},
    error::http_error::IdentityNotFoundError,
    middleware::ServiceContext,
    state::AppState,
};

/// Issue session tokens for an identity (internal endpoint)
///
/// # Returns
/// - 200 OK with access and refresh tokens
/// - 400 Bad Request if validation fails
/// - 404 Not Found if identity doesn't exist
/// - 500 Internal Server Error on server failure
pub async fn issue_session_tokens(
    State(state): State<AppState>,
    Extension(service_context): Extension<ServiceContext>,
    Json(request): Json<IssueSessionTokensRequest>,
) -> Result<Json<IssueSessionTokensResponse>, HttpError> {
    // Validate request
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    tracing::debug!(
        "[ISSUE_SESSION_TOKENS] Request received for user: {}",
        request.user_id
    );

    // Get the service that issued this request for audit
    let issued_by_service_id = Some(service_context.service_id.clone());

    // Create and execute the use case
    let use_case = crate::core::usecases::IssueSessionForIdentity::new(
        state.identity_repo.as_ref(),
        state.session_repo.as_ref(),
        state.token_service.as_ref(),
        state.access_token_ttl_seconds,
        state.refresh_token_ttl_days,
    );

    let input = crate::core::usecases::IssueSessionForIdentityInput {
        user_id: request.user_id.clone(),
        issued_by_service_id,
    };

    match use_case.execute(input).await {
        Ok(output) => {
            tracing::info!(
                "[ISSUE_SESSION_TOKENS] Session tokens issued successfully for user: {}",
                request.user_id
            );

            Ok(Json(IssueSessionTokensResponse {
                access_token: output.access_token,
                refresh_token: output.refresh_token,
                session_id: output.session_id,
                expires_in: output.expires_in,
                token_type: "Bearer".to_string(),
            }))
        }
        Err(e) => {
            tracing::warn!(
                "[ISSUE_SESSION_TOKENS] Failed to issue tokens for user {}: {}",
                request.user_id,
                e
            );

            // Map core errors to HTTP errors
            if let Some(auth_err) = e.as_authentication() {
                if matches!(auth_err, crate::core::error::AuthenticationError::UserNotFound { .. }) {
                    return Err(HttpError::IdentityNotFound(
                        IdentityNotFoundError::new(request.user_id.clone()),
                    ));
                }
            }

            Err(HttpError::Internal(InternalError::new(format!(
                "Failed to issue session tokens: {}",
                e
            ))))
        }
    }
}
