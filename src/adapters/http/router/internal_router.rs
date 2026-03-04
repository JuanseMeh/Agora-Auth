// Internal service-to-service routes

use axum::{
    extract::{Request, State},
    middleware::{self as axum_middleware, Next},
    response::Response,
    routing::{get, post},
    Router,
};

use crate::adapters::http::{handlers, middleware, state::AppState};

/// Layer to inject service registry into request extensions
async fn inject_service_registry(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(state.service_registry.clone());
    next.run(request).await
}

/// Layer to inject token service into request extensions
async fn inject_token_service(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(state.token_service.clone());
    next.run(request).await
}

/// Protected internal routes (require service JWT authentication)
pub fn protected_internal_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/credentials", post(handlers::create_credential))
        .route("/token/issue", post(handlers::issue_session_tokens))
        // Service JWT auth - validates Bearer token with typ:service claim
        .layer(axum_middleware::from_fn(middleware::service_jwt_auth))
        .layer(axum_middleware::from_fn_with_state(state.clone(), inject_token_service))
        .layer(axum_middleware::from_fn_with_state(state, inject_service_registry))
}

/// Public internal routes (no authentication required)
pub fn public_internal_routes() -> Router<AppState> {
    Router::new()
        .route("/service/token", post(handlers::issue_service_token))
        .route("/health", get(|| async { "OK" }))
}
