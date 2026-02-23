// Bearer token authentication middleware

use axum::{
    extract::Request,
    middleware::Next,
    response::{IntoResponse, Response},
    http::header,
};
use crate::adapters::http::error::{HttpError, UnauthorizedError};

/// Extract Bearer token from Authorization header and store in request extensions
/// 
/// Returns 401 Unauthorized if:
/// - Authorization header is missing
/// - Header does not start with "Bearer "
/// - Token is empty
pub async fn bearer_auth(
    mut request: Request,
    next: Next,
) -> Response {
    // Extract token from Authorization header
    let token = {
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

    // Store token in request extensions for handlers to use
    request.extensions_mut().insert(token);

    next.run(request).await
}
