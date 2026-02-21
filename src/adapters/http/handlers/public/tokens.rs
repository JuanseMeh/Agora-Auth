// Public token handler
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use crate::adapters::http::{
    dto::public::{RefreshTokenRequest, RefreshTokenResponse},
    error::{HttpError, ValidationError, UnauthorizedError, InternalError},
    state::AppState,
};
use crate::core::usecases::refresh_session::{RefreshSession, RefreshSessionInput};
use crate::core::token::Token;
use crate::core::error::CoreError;

/// Refresh an access token using a refresh token
///
/// # Returns
/// - 200 OK with new access token
/// - 400 Bad Request if validation fails
/// - 401 Unauthorized if refresh token is invalid/expired
/// - 500 Internal Server Error on server failure
pub async fn refresh_token(
    State(state): State<AppState>,
    Json(request): Json<RefreshTokenRequest>,
) -> Result<(StatusCode, Json<RefreshTokenResponse>), HttpError> {
    // Validate request structure
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    // Create refresh token from request
    let refresh_token = Token::new(request.refresh_token);

    // Execute refresh session use case
    let use_case = RefreshSession::new(
        &*state.session_repo,
        &*state.token_service,
        state.access_token_ttl_seconds,
        state.rotate_refresh_tokens,
    );

    let input = RefreshSessionInput {
        refresh_token,
    };

    let output = use_case.execute(input)
        .map_err(|e| match e {
            CoreError::Authentication(_) | CoreError::Token(_) => {
                HttpError::Unauthorized(UnauthorizedError::new("invalid or expired refresh token"))
            }
            _ => HttpError::Internal(InternalError::new(format!("failed to refresh token: {}", e))),
        })?;

    // Build response
    let response = RefreshTokenResponse {
        access_token: output.access_token.value().to_string(),
        token_type: output.token_type,
        expires_in: output.expires_in,
    };

    Ok((StatusCode::OK, Json(response)))
}
