// Public user-facing routes

use axum::{routing::post, Router};
use crate::adapters::http::{handlers, middleware, state::AppState};

pub fn public_routes() -> Router<AppState> {
    // Public endpoints (no auth required)
    let public_router = Router::new()
        .route("/auth/authenticate", post(handlers::authenticate));
    
    // Protected endpoints (require bearer auth)
    let protected_router = Router::new()
        .route("/auth/refresh", post(handlers::refresh_token))
        .route("/auth/validate", post(handlers::validate_token))
        .route("/auth/logout", post(handlers::logout))
        .route_layer(axum::middleware::from_fn(middleware::bearer_auth));
    
    public_router.merge(protected_router)
}
