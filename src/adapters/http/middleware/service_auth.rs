// Service-to-service authentication middleware

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    http::StatusCode,
};
use std::sync::Arc;
use crate::core::usecases::ports::ServiceRegistry;

/// Validate service authentication via X-Service-Key header
///
/// For internal endpoints, validates that the request includes a valid service key
/// registered in the service registry and that the service is active.
/// 
/// Returns 401 Unauthorized if:
/// - X-Service-Key header is missing
/// - X-Service-Key value is empty
/// - API key is invalid or not registered
/// - Service is inactive
pub async fn service_auth(
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check for service API key header
    let api_key = request
        .headers()
        .get("X-Service-Key")
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Validate key is not empty
    if api_key.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Extract service registry from request extensions
    let registry = request
        .extensions()
        .get::<Arc<dyn ServiceRegistry + Send + Sync>>()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    // Validate API key against service registry
    let service_name = registry.validate_api_key(api_key)
        .ok_or(StatusCode::UNAUTHORIZED)?;

    // Check if service is active
    if !registry.is_service_active(&service_name) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}
