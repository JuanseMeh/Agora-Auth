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
                    return Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body(axum::body::Body::empty())
                        .unwrap();
                }
                token_str.to_string()
            }
            _ => {
                return Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .body(axum::body::Body::empty())
                    .unwrap();
            }
        }
    };

    // Store token in request extensions for handlers to use
    request.extensions_mut().insert(token);

    next.run(request).await
}
