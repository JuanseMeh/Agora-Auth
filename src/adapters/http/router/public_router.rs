// Public user-facing routes

use axum::{routing::post, Router};
use crate::adapters::http::{handlers, middleware, state::AppState};

pub fn public_routes() -> Router<AppState> {
    // Public endpoint - authentication without Bearer token (credentials in body)
    let authenticate = Router::new()
        .route("/auth/authenticate", post(handlers::authenticate));

    // Protected endpoints - require Bearer token in Authorization header
    let protected = Router::new()
        .route("/auth/refresh", post(handlers::refresh_token))
        .route("/auth/validate", post(handlers::validate_token))
        .route("/auth/logout", post(handlers::logout))
        .layer(axum::middleware::from_fn(middleware::bearer_auth));

    Router::new()
        .merge(authenticate)
        .merge(protected)
}
