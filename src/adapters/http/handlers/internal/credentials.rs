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
    router::CleanJson,
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
    CleanJson(request): CleanJson<CreateCredentialRequest>,
) -> Result<(StatusCode, Json<CreateCredentialResponse>), HttpError> {
    // Validate request structure
    request.validate()
        .map_err(|msg| HttpError::Validation(ValidationError::new(msg)))?;

    // Parse the user_id provided by the User Service
    let user_id = Uuid::parse_str(&request.user_id)
        .map_err(|_| HttpError::Validation(ValidationError::new("invalid user_id format")))?;

    // Step 1: Check if identifier already exists
    if state.identity_repo.find_by_identifier(&request.identifier).await.is_some() {
        return Err(HttpError::Conflict(ConflictError::new("identifier already exists")));
    }

    // Step 2: Hash the password
    let hashed_credential = state.password_hasher.hash(&request.password);

    // Step 3: Create the identity using the provided user_id
    let created_at = chrono::Utc::now();

    state.identity_repo.create(
        &user_id,
        &request.identifier,
        hashed_credential.as_hash_str(),
        "", // salt is embedded in the hash string (PHC format)
        "", // algorithm is embedded in the hash string
        0,  // iterations is embedded in the hash string
    ).await.map_err(|e| HttpError::Internal(InternalError::new(format!("Failed to create identity: {}", e))))?;

    // Step 4: Initialize credential state (failed attempts = 0, no lock)
    state.credential_repo.initialize_credential_state(&user_id.to_string()).await
        .map_err(|e| HttpError::Internal(InternalError::new(format!("Failed to initialize credential state: {}", e))))?;

    // Step 5: Return success response
    let response = CreateCredentialResponse {
        user_id: user_id.to_string(),
        identifier: request.identifier,
        created_at: created_at.to_rfc3339(),
    };

    Ok((StatusCode::CREATED, Json(response)))
}
