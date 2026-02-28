// Public logout handler
use axum::{
    extract::{State, Extension},
    http::StatusCode,
    Json,
};
use crate::adapters::http::{
    dto::public::{LogoutRequest, LogoutResponse},
    error::{HttpError, UnauthorizedError, InternalError},
    router::CleanJson,
    state::AppState,
};
use crate::core::usecases::revoke_session::{RevokeSession, RevokeSessionInput};
use crate::core::usecases::validate_access_token::{ValidateAccessToken, ValidateAccessTokenInput};
use crate::core::token::Token;
use crate::core::error::CoreError;

/// Logout a user by revoking their session
///
/// # Returns
/// - 200 OK on successful logout
/// - 400 Bad Request if validation fails
/// - 401 Unauthorized if session not found or token invalid
/// - 500 Internal Server Error on server failure
pub async fn logout(
    State(state): State<AppState>,
    Extension(bearer_token): Extension<String>,
    CleanJson(_request): CleanJson<LogoutRequest>,
) -> Result<(StatusCode, Json<LogoutResponse>), HttpError> {
    // Use Bearer token from middleware to get session_id
    let access_token = Token::new(bearer_token);
    
    // Validate the access token to extract session_id
    let use_case = ValidateAccessToken::new(
        &*state.token_service,
        &*state.session_repo,
    );

    let output = use_case.execute(ValidateAccessTokenInput { access_token }).await
        .map_err(|e| HttpError::Internal(InternalError::new(format!("token validation failed: {}", e))))?;

    // Check if token is valid
    if !output.valid {
        return Err(HttpError::Unauthorized(UnauthorizedError::new(
            output.reason.as_deref().unwrap_or("invalid token")
        )));
    }

    // Extract session_id from validated token claims
    let session_id = output.session_id
        .ok_or_else(|| HttpError::Unauthorized(UnauthorizedError::new("session id not found in token")))?;

    // Execute revoke session use case
    let use_case = RevokeSession::new(&*state.session_repo);

    let input = RevokeSessionInput {
        session_id: Some(session_id),
        refresh_token_hash: None,
    };

    let output = use_case.execute(input).await
        .map_err(|e| match e {
            CoreError::Authentication(auth_err) => {
                // Preserve the actual error message from use case
                HttpError::Unauthorized(UnauthorizedError::new(auth_err.to_string()))
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
