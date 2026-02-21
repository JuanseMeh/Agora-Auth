// Router definition and assembly

use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;

use crate::adapters::http::state::AppState;

use super::{internal_routes, public_routes};

/// Build the complete HTTP router with all routes and middleware
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .nest("/internal", internal_routes(state.clone()))
        .nest("/public", public_routes())
        .nest("/health", health_routes())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Health check routes (no authentication required)
fn health_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(health_check))
        .route("/ready", get(readiness_check))
}

/// Liveness probe - always returns 200 if service is running
async fn health_check() -> &'static str {
    "OK"
}

/// Readiness probe - checks if service is ready to handle traffic
async fn readiness_check() -> &'static str {
    // TODO: Check database connection, cache availability, etc.
    "READY"
}
