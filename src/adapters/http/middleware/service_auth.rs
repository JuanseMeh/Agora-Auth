// Service-to-service authentication middleware

use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use crate::core::usecases::ports::ServiceRegistry;
use crate::adapters::http::error::{HttpError, InternalError, ServiceUnauthorizedError};

/// Service context injected into request extensions after successful authentication
#[derive(Debug, Clone)]
pub struct ServiceContext {
    /// The service identifier (e.g., "user_service")
    pub service_id: String,
}

impl ServiceContext {
    /// Create a new service context
    pub fn new(service_id: String) -> Self {
        Self { service_id }
    }
}

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
            let error = HttpError::ServiceUnauthorized(
                ServiceUnauthorizedError::new("Missing or empty X-Service-Key header")
            );
            return error.into_response();
        }
    };

    // Extract service registry from request extensions
    let registry = match request
        .extensions()
        .get::<Arc<dyn ServiceRegistry + Send + Sync>>()
    {
        Some(reg) => reg,
        None => {
            let error = HttpError::Internal(InternalError::new("Service registry not available"));
            return error.into_response();
        }
    };

    // Validate API key against service registry
    let service_name = match registry.validate_api_key(api_key) {
        Some(name) => name,
        None => {
            let error = HttpError::ServiceUnauthorized(
                ServiceUnauthorizedError::new("Invalid or unregistered service API key")
            );
            return error.into_response();
        }
    };

    // Check if service is active
    if !registry.is_service_active(&service_name) {
        let error = HttpError::ServiceUnauthorized(
            ServiceUnauthorizedError::with_service_id("Service is not active", &service_name)
        );
        return error.into_response();
    }

    next.run(request).await
}

/// JWT-based service authentication middleware
///
/// Validates service JWT tokens for internal endpoints.
/// This middleware validates the Bearer token and checks for `typ: service` claim
/// to prevent token confusion attacks.
///
/// Returns 401 Unauthorized if:
/// - Authorization header is missing or malformed
/// - Token is invalid or expired
/// - Token type is not "service" (prevents token confusion)
pub async fn service_jwt_auth(
    mut request: Request,
    next: Next,
) -> Response {
    use axum::http::header;
    use crate::core::token::Token;
    use crate::adapters::http::error::UnauthorizedError;

    // Extract token from Authorization header
    let token_string = {
        let auth_header = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok());

        match auth_header {
            Some(header) if header.starts_with("Bearer ") => {
                let token_str = &header[7..];
                if token_str.is_empty() {
                    let error = HttpError::Unauthorized(UnauthorizedError::new("Token is empty"));
                    return error.into_response();
                }
                token_str.to_string()
            }
            _ => {
                let error = HttpError::Unauthorized(UnauthorizedError::new("Missing Authorization header"));
                return error.into_response();
            }
        }
    };

    // Get TokenService from app state (we need to get it from extensions set earlier)
    let token_service = match request
        .extensions()
        .get::<Arc<dyn crate::core::usecases::ports::TokenService + Send + Sync>>()
    {
        Some(ts) => ts,
        None => {
            let error = HttpError::Internal(InternalError::new("Token service not available"));
            return error.into_response();
        }
    };

    // Validate the service token
    let token = Token::new(token_string.as_str());
    let claims = match token_service.validate_service_token(&token) {
        Ok(c) => c,
        Err(_) => {
            let error = HttpError::ServiceUnauthorized(ServiceUnauthorizedError::new("Invalid or expired service token"));
            return error.into_response();
        }
    };

    // Validate token type is "service" to prevent token confusion attacks
    let token_type = claims
        .split("\"type\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string());

    if token_type.as_deref() != Some("service") {
        tracing::warn!(
            "[SERVICE_JWT_AUTH] Invalid token type: expected 'service', got {:?}",
            token_type
        );
        let error = HttpError::ServiceUnauthorized(ServiceUnauthorizedError::new("Invalid token type: expected service token"));
        return error.into_response();
    }

    // Extract service_id from claims (sub claim)
    let service_id = claims
        .split("\"sub\":\"")
        .nth(1)
        .and_then(|s| s.split('"').next())
        .map(|s| s.to_string());

    let service_id = match service_id {
        Some(id) if !id.is_empty() => id,
        _ => {
            let error = HttpError::ServiceUnauthorized(ServiceUnauthorizedError::new("Invalid token: missing service identifier"));
            return error.into_response();
        }
    };

    // Inject ServiceContext into request extensions
    request.extensions_mut().insert(ServiceContext::new(service_id));

    next.run(request).await
}
