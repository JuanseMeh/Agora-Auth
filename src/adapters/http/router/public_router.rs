// Public user-facing routes

use axum::{routing::post, Router};
use crate::adapters::http::{handlers, state::AppState};

pub fn public_routes() -> Router<AppState> {
    // All public endpoints - tokens are passed in request body, not Authorization header
    Router::new()
        .route("/auth/authenticate", post(handlers::authenticate))
        .route("/auth/refresh", post(handlers::refresh_token))
        .route("/auth/validate", post(handlers::validate_token))
        .route("/auth/logout", post(handlers::logout))
}
