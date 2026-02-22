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
) -> Response {
    // Check for service API key header
    let api_key = match request
        .headers()
        .get("X-Service-Key")
        .and_then(|header| header.to_str().ok())
    {
        Some(key) if !key.is_empty() => key,
        _ => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(axum::body::Body::empty())
                .unwrap();
        }
    };

    // Extract service registry from request extensions
    let registry = match request
        .extensions()
        .get::<Arc<dyn ServiceRegistry + Send + Sync>>()
    {
        Some(reg) => reg,
        None => {
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(axum::body::Body::empty())
                .unwrap();
        }
    };

    // Validate API key against service registry
    let service_name = match registry.validate_api_key(api_key) {
        Some(name) => name,
        None => {
            return Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(axum::body::Body::empty())
                .unwrap();
        }
    };

    // Check if service is active
    if !registry.is_service_active(&service_name) {
        return Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(axum::body::Body::empty())
            .unwrap();
    }

    next.run(request).await
}
