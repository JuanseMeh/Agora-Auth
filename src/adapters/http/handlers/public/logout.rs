// Public logout handler
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use crate::adapters::http::{
    dto::public::{LogoutRequest, LogoutResponse},
    error::{HttpError, ValidationError, UnauthorizedError, InternalError},
    state::AppState,
};
use crate::core::usecases::revoke_session::{RevokeSession, RevokeSessionInput};
use crate::core::error::CoreError;

/// Logout a user by revoking their session
///
/// # Returns
/// - 200 OK on successful logout
/// - 400 Bad Request if validation fails
/// - 401 Unauthorized if session not found
/// - 500 Internal Server Error on server failure
pub async fn logout(
    State(state): State<AppState>,
    Json(request): Json<LogoutRequest>,
) -> Result<(StatusCode, Json<LogoutResponse>), HttpError> {
    // Validate request structure
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    // Execute revoke session use case
    let use_case = RevokeSession::new(&*state.session_repo);

    // Build input - use session_id if provided, otherwise use refresh_token hash
    let input = RevokeSessionInput {
        session_id: request.session_id,
        refresh_token_hash: request.refresh_token,
    };

    let output = use_case.execute(input)
        .map_err(|e| match e {
            CoreError::Authentication(_) => {
                HttpError::Unauthorized(UnauthorizedError::new("session not found"))
            }
            _ => HttpError::Internal(InternalError::new(format!("logout failed: {}", e))),
        })?;

    // Build response
    let response = LogoutResponse {
        success: output.revoked,
        message: "Successfully logged out".to_string(),
        session_id: output.session_id,
    };

    Ok((StatusCode::OK, Json(response)))
}
