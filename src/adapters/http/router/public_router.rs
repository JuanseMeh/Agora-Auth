// Public user-facing routes

use axum::{routing::post, Router};
use crate::adapters::http::{handlers, middleware, state::AppState};
use crate::adapters::http::handlers::public::exchange_google_code;
use crate::adapters::http::handlers::public::credential_recovery::{
    handle_confirm_recovery, handle_request_recovery, RecoveryRateLimiter,
};
use std::time::Duration;


pub fn public_routes(state: &AppState) -> Router<AppState> {
    // Public endpoint - authentication without Bearer token (credentials in body)
    let authenticate = Router::new()
        .route("/auth/authenticate", post(handlers::authenticate))
        .route("/auth/google/callback", post(exchange_google_code));

    let limiter = RecoveryRateLimiter::new(
        5,                          // max 5 requests
        Duration::from_secs(15 * 60), // per 15-minute window
    );

    let recovery = Router::new()
        .route(
            "/auth/recovery/request",
            post(handle_request_recovery)
                .with_state((
                    state.request_recovery.clone(),
                    state.notification_client.clone(),
                    limiter,
                )),
        )
        .route(
            "/auth/recovery/confirm",
            post(handle_confirm_recovery)
                .with_state(state.confirm_recovery.clone()),
        );

    // Protected endpoints - require Bearer token in Authorization header
    let protected = Router::new()
        .route("/auth/refresh", post(handlers::refresh_token))
        .route("/auth/validate", post(handlers::validate_token))
        .route("/auth/logout", post(handlers::logout))
        .layer(axum::middleware::from_fn(middleware::bearer_auth));

    Router::new()
        .merge(authenticate)
        .merge(protected)
        .merge(recovery)
}
