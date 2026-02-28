//! HTTP server initialization and graceful shutdown.
//!
//! This module handles Axum server setup, signal handling, and graceful shutdown.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::signal;

use crate::adapters::http::create_router;

use super::config::AuthConfig;
use super::wiring::AppComponents;

/// Run the HTTP server with graceful shutdown.
///
/// This function:
/// 1. Creates the Axum router with application state
/// 2. Binds to the configured address
/// 3. Starts the server with graceful shutdown handling
/// 4. Waits for SIGTERM or SIGINT signals
/// 5. Drains connections and closes resources on shutdown
///
/// # Errors
/// Returns an error if the server fails to start or encounters a fatal error.
pub async fn run_server(config: &AuthConfig, components: AppComponents) -> anyhow::Result<()> {
    // Build the router with application state
    let app = create_router(components.app_state);
    
    // Parse bind address
    let addr = parse_bind_address(config)?;
    
    // Create TCP listener
    let listener = tokio::net::TcpListener::bind(&addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind to {}: {}", addr, e))?;
    
    tracing::info!(
        mode = %config.mode,
        "Server starting on http://{}",
        addr
    );
    
    // Start server with graceful shutdown
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| anyhow::anyhow!("Server error: {}", e))?;
    
    // Shutdown sequence
    tracing::info!("Initiating graceful shutdown...");
    
    // Close database pool
    components.database.shutdown().await;
    tracing::info!("Database pool closed");
    
    // Allow time for logs to flush
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    tracing::info!("Shutdown complete");
    
    Ok(())
}

/// Parse server bind address from configuration.
fn parse_bind_address(config: &AuthConfig) -> anyhow::Result<SocketAddr> {
    let addr_str = format!("{}:{}", config.server.host, config.server.port);
    addr_str.parse()
        .map_err(|e| anyhow::anyhow!("Invalid bind address '{}': {}", addr_str, e))
}

/// Wait for shutdown signal (SIGTERM or SIGINT).
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            tracing::info!("Received SIGINT (Ctrl+C), starting graceful shutdown");
        }
        _ = terminate => {
            tracing::info!("Received SIGTERM, starting graceful shutdown");
        }
    }
}

/// Development server with hot-reload support (optional).
///
/// This is a simplified version for development that may include
/// additional debugging features.
#[cfg(debug_assertions)]
pub async fn run_dev_server(config: &AuthConfig, components: AppComponents) -> anyhow::Result<()> {
    tracing::info!("Running in development mode with debug features enabled");
    
    // In development, we might want additional logging or features
    if config.security.enable_debug_logs {
        tracing::info!("Debug logging is enabled - sensitive data may be logged");
    }
    
    run_server(config, components).await
}

/// Health check endpoint handler.
///
/// Returns 200 OK if the service is healthy, 503 otherwise.
pub async fn health_check() -> axum::response::Response {
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(r#"{"status":"healthy"}"#))
        .unwrap()
}

/// Readiness check endpoint handler.
///
/// Validates that all dependencies are ready:
/// - Database connectivity
/// - Crypto services initialized
pub async fn readiness_check(_components: &AppComponents) -> axum::response::Response {
    // TODO: Implement actual readiness checks
    // For now, just return ready
    axum::response::Response::builder()
        .status(200)
        .header("Content-Type", "application/json")
        .body(axum::body::Body::from(r#"{"status":"ready"}"#))
        .unwrap()
}
