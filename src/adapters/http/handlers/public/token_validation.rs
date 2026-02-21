// Public token validation handler
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use crate::adapters::http::{
    dto::public::{TokenValidationRequest, TokenValidationResponse},
    error::{HttpError, ValidationError, UnauthorizedError, InternalError},
    state::AppState,
};
use crate::core::usecases::validate_access_token::{ValidateAccessToken, ValidateAccessTokenInput};
use crate::core::token::Token;

/// Validate an access token and extract claims
///
/// # Returns
/// - 200 OK with user_id and session_id
/// - 400 Bad Request if validation fails
/// - 401 Unauthorized if token is invalid/expired
/// - 500 Internal Server Error on server failure
pub async fn validate_token(
    State(state): State<AppState>,
    Json(request): Json<TokenValidationRequest>,
) -> Result<(StatusCode, Json<TokenValidationResponse>), HttpError> {
    // Validate request structure
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    // Create access token from request
    let access_token = Token::new(request.token);

    // Execute validate access token use case
    let use_case = ValidateAccessToken::new(&*state.token_service);

    let input = ValidateAccessTokenInput {
        access_token,
    };

    let output = use_case.execute(input)
        .map_err(|e| HttpError::Internal(InternalError::new(format!("token validation failed: {}", e))))?;

    // Check if token is valid
    if !output.valid {
        return Err(HttpError::Unauthorized(UnauthorizedError::new(
            output.reason.as_deref().unwrap_or("invalid token")
        )));
    }

    // Extract user_id and session_id (should be present if valid)
    let user_id = output.user_id
        .ok_or_else(|| HttpError::Internal(InternalError::new("missing user_id in valid token")))?;
    let session_id = output.session_id
        .ok_or_else(|| HttpError::Internal(InternalError::new("missing session_id in valid token")))?;

    // Build response
    let response = TokenValidationResponse {
        user_id,
        session_id,
    };

    Ok((StatusCode::OK, Json(response)))
}
