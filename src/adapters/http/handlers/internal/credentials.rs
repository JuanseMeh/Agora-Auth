// Internal credential creation handler
use axum::{
    extract::State,
    http::StatusCode,
    Json,
};
use uuid::Uuid;
use crate::adapters::http::{
    dto::internal::{CreateCredentialRequest, CreateCredentialResponse},
    error::{HttpError, ValidationError, ConflictError, InternalError},
    state::AppState,
};

/// Create a new credential (internal endpoint)
///
/// # Returns
/// - 201 Created with credential details
/// - 400 Bad Request if validation fails
/// - 409 Conflict if identifier already exists
/// - 500 Internal Server Error on server failure
pub async fn create_credential(
    State(state): State<AppState>,
    Json(request): Json<CreateCredentialRequest>,
) -> Result<(StatusCode, Json<CreateCredentialResponse>), HttpError> {
    // Validate request structure
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    // Step 1: Check if identifier already exists
    if state.identity_repo.find_by_identifier(&request.identifier).is_some() {
        return Err(HttpError::Conflict(ConflictError::new("identifier already exists")));
    }

    // Step 2: Hash the password
    let hashed_credential = state.password_hasher.hash(&request.password);

    // Step 3: Create the identity
    let user_id = Uuid::new_v7(uuid::Timestamp::now(uuid::NoContext));
    let created_at = chrono::Utc::now();

    state.identity_repo.create(
        &user_id,
        &request.identifier,
        hashed_credential.as_hash_str(),
        "", // salt is embedded in the hash string (PHC format)
        "", // algorithm is embedded in the hash string
        0,  // iterations is embedded in the hash string
    ).map_err(|e| HttpError::Internal(InternalError::new(format!("Failed to create identity: {}", e))))?;

    // Step 4: Initialize credential state (failed attempts = 0, no lock)
    state.credential_repo.initialize_credential_state(&user_id.to_string())
        .map_err(|e| HttpError::Internal(InternalError::new(format!("Failed to initialize credential state: {}", e))))?;

    // Step 5: Return success response
    let response = CreateCredentialResponse {
        user_id: user_id.to_string(),
        identifier: request.identifier,
        created_at: created_at.to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}
