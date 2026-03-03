// Router definition and assembly

use axum::{
    extract::rejection::JsonRejection,
    routing::get,
    Json, Router,
};
use tower_http::trace::TraceLayer;

use crate::adapters::http::{
    error::{HttpError, ValidationError},
    state::AppState,
};

use super::{protected_internal_routes, public_internal_routes, public_routes};

/// Build the complete HTTP router with all routes and middleware
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Internal routes - public (no auth required)
        .nest("/internal", public_internal_routes())
        // Internal routes - protected (require X-Service-Key header)
        .nest("/internal", protected_internal_routes(state.clone()))
        // Public routes
        .nest("/public", public_routes())
        // Health check routes
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

/// Custom JSON extractor that provides clean error messages
pub struct CleanJson<T>(pub T);

impl<S, T> axum::extract::FromRequest<S> for CleanJson<T>
where
    S: Send + Sync,
    T: serde::de::DeserializeOwned + Send,
{
    type Rejection = HttpError;

    fn from_request(
        req: axum::extract::Request,
        state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            match Json::<T>::from_request(req, state).await {
                Ok(value) => Ok(CleanJson(value.0)),
                Err(rejection) => {
                    let message = match &rejection {
                        JsonRejection::JsonSyntaxError(_) => "Invalid JSON syntax".to_string(),
                        JsonRejection::JsonDataError(e) => {
                            // Extract a clean message from serde's error
                            let err_str = e.to_string();
                            // Remove the "Failed to deserialize the JSON body into the target type: " prefix
                            if let Some(pos) = err_str.find("missing field") {
                                format!("Missing required field: {}", &err_str[pos..])
                            } else if let Some(pos) = err_str.find("unknown field") {
                                format!("Unknown field: {}", &err_str[pos..])
                            } else if let Some(pos) = err_str.find("invalid type") {
                                format!("Invalid field type: {}", &err_str[pos..])
                            } else {
                                "Invalid request data".to_string()
                            }
                        }
                        JsonRejection::MissingJsonContentType(_) => {
                            "Content-Type must be application/json".to_string()
                        }
                        JsonRejection::BytesRejection(_) => "Failed to read request body".to_string(),
                        _ => "Invalid request".to_string(),
                    };
                    Err(HttpError::Validation(ValidationError::new(message)))
                }
            }
        }
    }
}
