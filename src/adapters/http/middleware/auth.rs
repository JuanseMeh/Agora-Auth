// Bearer token authentication middleware

use axum::{
    extract::Request,
    middleware::Next,
    response::Response,
    http::{header, StatusCode},
};

/// Extract Bearer token from Authorization header and store in request extensions
/// 
/// Returns 401 Unauthorized if:
/// - Authorization header is missing
/// - Header does not start with "Bearer "
/// - Token is empty
pub async fn bearer_auth(
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract token from Authorization header
    let token = {
        let auth_header = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|header| header.to_str().ok())
            .ok_or(StatusCode::UNAUTHORIZED)?;

        if !auth_header.starts_with("Bearer ") {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let token_str = &auth_header[7..];
        if token_str.is_empty() {
            return Err(StatusCode::UNAUTHORIZED);
        }

        token_str.to_string()
    };

    // Store token in request extensions for handlers to use
    request.extensions_mut().insert(token);

    Ok(next.run(request).await)
}
