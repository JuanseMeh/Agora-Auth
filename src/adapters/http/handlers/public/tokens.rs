// Public token handler
use axum::{
    extract::{State, Extension},
    http::StatusCode,
    Json,
};
use crate::adapters::http::{
    dto::public::{RefreshTokenRequest, RefreshTokenResponse},
    error::{HttpError, ValidationError, UnauthorizedError, InternalError},
    router::CleanJson,
    state::AppState,
};
use crate::core::usecases::refresh_session::{RefreshSession, RefreshSessionInput};
use crate::core::usecases::validate_access_token::{ValidateAccessToken, ValidateAccessTokenInput};
use crate::core::token::Token;
use crate::core::error::CoreError;

/// Refresh an access token using a valid session
///
/// # Returns
/// - 200 OK with new access token
/// - 400 Bad Request if validation fails
/// - 401 Unauthorized if access token is invalid/expired
/// - 500 Internal Server Error on server failure
pub async fn refresh_token(
    State(state): State<AppState>,
    Extension(bearer_token): Extension<String>,
    CleanJson(request): CleanJson<RefreshTokenRequest>,
) -> Result<(StatusCode, Json<RefreshTokenResponse>), HttpError> {
    // Validate request structure
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    // Validate the Bearer access token to get session_id
    let access_token = Token::new(bearer_token);
    
    let validate_use_case = ValidateAccessToken::new(
        &*state.token_service,
        &*state.session_repo,
    );

    let validate_output = validate_use_case.execute(ValidateAccessTokenInput { access_token }).await
        .map_err(|e| HttpError::Internal(InternalError::new(format!("token validation failed: {}", e))))?;

    // Check if token is valid
    if !validate_output.valid {
        return Err(HttpError::Unauthorized(UnauthorizedError::new(
            validate_output.reason.as_deref().unwrap_or("invalid access token")
        )));
    }

    // Extract session_id from validated token
    let _session_id = validate_output.session_id
        .ok_or_else(|| HttpError::Unauthorized(UnauthorizedError::new("session id not found in token")))?;

    // Get the stored refresh token from the session repository using session_id
    // Then execute refresh session use case to rotate tokens
    let use_case = RefreshSession::new(
        &*state.session_repo,
        &*state.token_service,
        state.access_token_ttl_seconds,
        state.rotate_refresh_tokens,
    );

    // We need to get the refresh token from the session - use the request's refresh_token
    // or we could fetch it from the session store
    let refresh_token = Token::new(request.refresh_token);

    let input = RefreshSessionInput {
        refresh_token,
    };

    let output = use_case.execute(input).await
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
