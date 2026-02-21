// Public authentication handler
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use crate::adapters::http::{
    dto::public::{AuthenticateRequest, AuthenticateResponse},
    error::{HttpError, ValidationError, LockedError, UnauthorizedError, InternalError},
    state::AppState,
};
use crate::core::usecases::authenticate_user::{AuthenticateUser, AuthenticateUserInput};
use crate::core::usecases::issue_session::{IssueSession, IssueSessionInput};
use crate::core::error::CoreError;

/// Authenticate a user and return tokens
///
/// # Returns
/// - 200 OK with access and refresh tokens
/// - 400 Bad Request if validation fails
/// - 401 Unauthorized if credentials are invalid
/// - 423 Locked if account is locked
/// - 500 Internal Server Error on server failure
pub async fn authenticate(
    State(state): State<AppState>,
    Json(request): Json<AuthenticateRequest>,
) -> Result<(StatusCode, Json<AuthenticateResponse>), HttpError> {
    // Validate request structure
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    // Step 1: Authenticate the user
    let auth_use_case = AuthenticateUser::new(
        &*state.identity_repo,
        &*state.credential_repo,
        &*state.password_hasher,
        5,  // max_attempts
        30, // lockout_duration_minutes
    );

    let auth_input = AuthenticateUserInput {
        identifier: request.identifier,
        password: request.password,
    };

    let auth_result = auth_use_case.execute(auth_input);

    let user = match auth_result {
        Ok(output) => output.user,
        Err(CoreError::Authentication(auth_err)) => {
            if auth_err.is_account_locked() {
                return Err(HttpError::Locked(LockedError::new("account is locked")));
            } else {
                return Err(HttpError::Unauthorized(UnauthorizedError::new("invalid credentials")));
            }
        }
        Err(e) => {
            return Err(HttpError::Internal(InternalError::new(format!("authentication failed: {}", e))));
        }
    };

    // Step 2: Issue session with tokens
    let session_use_case = IssueSession::new(
        &*state.session_repo,
        &*state.token_service,
        state.access_token_ttl_seconds,
        state.refresh_token_ttl_days,
    );

    let session_input = IssueSessionInput {
        user,
        ip_address: "0.0.0.0".to_string(), // TODO: Extract from request
        user_agent: "unknown".to_string(),  // TODO: Extract from request
    };

    let session_output = session_use_case.execute(session_input)
        .map_err(|e| HttpError::Internal(InternalError::new(format!("failed to issue session: {}", e))))?;

    // Step 3: Return response
    let response = AuthenticateResponse {
        access_token: session_output.access_token.value().to_string(),
        refresh_token: session_output.refresh_token.value().to_string(),
        token_type: "Bearer".to_string(),
        expires_in: session_output.expires_in,
        session_id: session_output.session_id,
    };

    Ok((StatusCode::OK, Json(response)))
}
