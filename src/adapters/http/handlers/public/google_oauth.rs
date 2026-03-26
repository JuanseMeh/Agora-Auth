use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use tracing::instrument;

use crate::adapters::http::dto::public::google_oauth::{GoogleCodeExchangeRequest, GoogleCodeExchangeResponse};
use crate::adapters::http::error::{HttpError, UnauthorizedError, InternalError, ValidationError};
use crate::adapters::http::router::CleanJson;
use crate::adapters::http::state::AppState;
use crate::core::error::CoreError;
use crate::core::usecases::issue_session_for_identity::{IssueSessionForIdentity, IssueSessionForIdentityInput};

/// Exchange Google OAuth authorization code for session tokens.
///
/// POST /auth/google/callback
#[instrument(skip(state, request), fields(has_state = request.state.is_some()))]
pub async fn exchange_google_code(
    State(state): State<AppState>,
    CleanJson(request): CleanJson<GoogleCodeExchangeRequest>,
) -> Result<(StatusCode, Json<GoogleCodeExchangeResponse>), HttpError> {
    // Step 1: Validate DTO
    request.validate().map_err(|e| HttpError::Validation(ValidationError::new(e)))?;

    // Step 2: Exchange OAuth code -> ExternalIdentity
    let identity = state.google_code_exchanger
        .exchange(&request.code, request.state.as_deref())
        .await
        .map_err(|e| match e {
            CoreError::Authentication(_) => HttpError::Unauthorized(
                UnauthorizedError::new("Invalid or expired authorization code")
            ),
            _ => HttpError::Internal(
                InternalError::new(format!("Code exchange failed: {}", e))
            ),
        })?;

    // Step 3: Resolve ExternalIdentity -> internal user ID
    let user_id = state.external_identity_repo
    .find_by_provider_user(&identity.provider, &identity.provider_user_id)
    .await
    .map_err(|e| HttpError::Internal(
        InternalError::new(format!("External identity lookup failed: {}", e))
    ))?
    .ok_or_else(|| HttpError::Unauthorized(
        UnauthorizedError::new("No account linked to this Google identity")
    ))?;

    // Step 4: Issue session tokens for the linked user
    let issue_usecase = IssueSessionForIdentity::new(
        &*state.identity_repo,
        &*state.session_repo,
        &*state.token_service,
        state.access_token_ttl_seconds,
        state.refresh_token_ttl_days,
    );

    let issue_output = issue_usecase
    .execute(IssueSessionForIdentityInput {
        user_id: user_id.to_string(), // Uuid -> String
        issued_by_service_id: None,
    })
    .await
    .map_err(|e| match e {
        CoreError::Authentication(_) => HttpError::Unauthorized(
            UnauthorizedError::new("Failed to issue session")
        ),
        _ => HttpError::Internal(
            InternalError::new(format!("Session issuance failed: {}", e))
        ),
    })?;

    Ok((StatusCode::OK, Json(GoogleCodeExchangeResponse {
        access_token: issue_output.access_token,
        refresh_token: issue_output.refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: issue_output.expires_in,
        session_id: issue_output.session_id,
    })))
}