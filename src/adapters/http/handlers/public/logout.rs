// Public logout handler
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use crate::adapters::http::{
    dto::public::{LogoutRequest, LogoutResponse},
    error::{HttpError, ValidationError, UnauthorizedError, InternalError},
    router::CleanJson,
    state::AppState,
};
use crate::core::usecases::revoke_session::{RevokeSession, RevokeSessionInput};
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
    CleanJson(request): CleanJson<LogoutRequest>,
) -> Result<(StatusCode, Json<LogoutResponse>), HttpError> {
    // Validate request structure
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    // If refresh_token is provided, validate it first
    let session_id = if let Some(refresh_token) = request.refresh_token {
        let token = Token::new(refresh_token);
        
        // Validate the refresh token signature
        let claims = state.token_service.validate_refresh_token(&token)
            .map_err(|_| HttpError::Unauthorized(UnauthorizedError::new("invalid refresh token")))?;
        
        // Extract session_id from validated token claims
        extract_session_id(&claims)
            .ok_or_else(|| HttpError::Unauthorized(UnauthorizedError::new("session id not found in token")))?
    } else if let Some(session_id) = request.session_id {
        session_id
    } else {
        return Err(HttpError::Validation(ValidationError::new(
            "either session_id or refresh_token must be provided"
        )));
    };

    // Execute revoke session use case
    let use_case = RevokeSession::new(&*state.session_repo);

    let input = RevokeSessionInput {
        session_id: Some(session_id),
        refresh_token_hash: None, // We already validated the token, use session_id
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

/// Extract session_id from token claims JSON
fn extract_session_id(claims: &str) -> Option<String> {
    claims
        .split("\"sid\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string())
}
