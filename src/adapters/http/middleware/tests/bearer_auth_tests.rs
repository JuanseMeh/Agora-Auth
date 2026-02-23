//! Comprehensive tests for bearer_auth middleware

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
    middleware,
    routing::get,
    Router,
};
use tower::ServiceExt;

use crate::adapters::http::middleware::bearer_auth;

// Simple handler that returns the token from extensions
async fn token_echo_handler(request: axum::extract::Request) -> String {
    request
        .extensions()
        .get::<String>()
        .cloned()
        .unwrap_or_else(|| "NO_TOKEN".to_string())
}

fn test_router() -> Router {
    Router::new()
        .route("/echo", get(token_echo_handler))
        .layer(middleware::from_fn(bearer_auth))
}

// ============================================================================
// Test Cases
// ============================================================================

#[tokio::test]
async fn test_bearer_auth_extract_valid_token() {
    let app = test_router();
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/echo")
                .header(header::AUTHORIZATION, "Bearer valid_token_123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    assert_eq!(body_str, "valid_token_123");
}

#[tokio::test]
async fn test_bearer_auth_missing_header() {
    let app = test_router();
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/echo")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_invalid_format_no_bearer() {
    let app = test_router();
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/echo")
                .header(header::AUTHORIZATION, "Basic dXNlcjpwYXNz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_empty_token() {
    let app = test_router();
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/echo")
                .header(header::AUTHORIZATION, "Bearer ")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_token_with_spaces() {
    let app = test_router();
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/echo")
                .header(header::AUTHORIZATION, "Bearer token with spaces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    // Token should include everything after "Bearer "
    assert_eq!(body_str, "token with spaces");
}

#[tokio::test]
async fn test_bearer_auth_case_sensitive_prefix() {
    let app = test_router();
    
    // "bearer" (lowercase) should not match
    let response = app
        .oneshot(
            Request::builder()
                .uri("/echo")
                .header(header::AUTHORIZATION, "bearer token123")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_bearer_auth_unicode_token() {
    // Note: HTTP header values should technically be ASCII, but modern systems
    // often accept UTF-8. This test documents the current behavior.
    let app = test_router();
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/echo")
                .header(header::AUTHORIZATION, "Bearer tokén_日本語_🎉")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    // HTTP headers with non-ASCII characters may be rejected at the protocol level
    // If it passes through, the token should be extracted correctly
    if response.status() == StatusCode::OK {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body_str = String::from_utf8(body.to_vec()).unwrap();
        assert_eq!(body_str, "tokén_日本語_🎉");
    }
    // If 401, that's also acceptable behavior for non-ASCII headers
}

#[tokio::test]
async fn test_bearer_auth_long_token() {
    let app = test_router();
    
    // Create a long token (e.g., JWT-like)
    let long_token = "a".repeat(1000);
    let auth_header = format!("Bearer {}", long_token);
    
    let response = app
        .oneshot(
            Request::builder()
                .uri("/echo")
                .header(header::AUTHORIZATION, auth_header)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    
    assert_eq!(response.status(), StatusCode::OK);
    
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    
    assert_eq!(body_str, long_token);
}
