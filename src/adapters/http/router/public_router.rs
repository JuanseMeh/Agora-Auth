// Public user-facing routes (require bearer auth)

use axum::{routing::post, Router};
use crate::adapters::http::{handlers, middleware, state::AppState};

pub fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/auth/authenticate", post(handlers::authenticate))
        .route("/auth/refresh", post(handlers::refresh_token))
        .route("/auth/validate", post(handlers::validate_token))
        .route("/auth/logout", post(handlers::logout))
        .layer(axum::middleware::from_fn(middleware::bearer_auth))
}
