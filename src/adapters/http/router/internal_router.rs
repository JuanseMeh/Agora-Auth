// Internal service-to-service routes (require service auth)

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self as axum_middleware, Next},
    response::Response,
    routing::post,
    Router,
};

use crate::adapters::http::{handlers, middleware, state::AppState};
/// Layer to inject service registry into request extensions
async fn inject_service_registry(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    request.extensions_mut().insert(state.service_registry.clone());
    Ok(next.run(request).await)
}

pub fn internal_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/credentials", post(handlers::create_credential))
        .layer(axum_middleware::from_fn(middleware::service_auth))
        .layer(axum_middleware::from_fn_with_state(state, inject_service_registry))
}
