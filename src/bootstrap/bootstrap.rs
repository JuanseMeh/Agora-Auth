//! Main bootstrap orchestration logic.
//!
//! This module contains the primary bootstrap flow that wires together
//! all components and starts the server.

use super::config::AuthConfig;
use super::server;
use super::wiring::{initialize_components, AppComponents};

/// Main entry point for bootstrapping the application.
///
/// This function orchestrates the entire startup sequence:
/// 1. Load .env file if present
/// 2. Load configuration from environment
/// 3. Initialize tracing/logging
/// 4. Build all application components
/// 5. Start the HTTP server
///
/// # Errors
/// Returns an error if any bootstrap step fails. This should be treated
/// as a fatal error and the process should exit.
///
/// # Example
///
/// ```rust,no_run
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     auth::bootstrap::run().await
/// }
/// ```
pub async fn run() -> anyhow::Result<()> {
    // Step 1: Load .env file if present (ignores errors if file doesn't exist)
    let _ = dotenvy::dotenv();
    
    // Step 2: Load configuration
    let config = AuthConfig::from_env()
        .map_err(|e| {
            eprintln!("Failed to load configuration: {}", e);
            e
        })?;
    
    // Step 3: Initialize logging
    init_logging(&config);
    
    tracing::info!(
        mode = %config.mode,
        version = env!("CARGO_PKG_VERSION"),
        "Starting authentication service"
    );
    
    // Step 4: Initialize components
    let components = initialize_components(&config).await
        .map_err(|e| {
            tracing::error!("Component initialization failed: {}", e);
            e
        })?;
    
    tracing::info!("All components initialized successfully");
    
    // Step 5: Start server (blocks until shutdown)
    server::run_server(&config, components).await
        .map_err(|e| {
            tracing::error!("Server error: {}", e);
            e
        })?;
    
    Ok(())
}

/// Initialize structured logging based on configuration.
fn init_logging(config: &AuthConfig) {
    use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
    
    let filter = if config.security.enable_debug_logs {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(true)
                .with_thread_ids(true)
                .with_line_number(true)
        )
        .with(filter)
        .init();
    
    // Log configuration summary (without secrets)
    tracing::debug!(
        host = %config.server.host,
        port = %config.server.port,
        max_connections = %config.database.max_connections,
        access_token_ttl = %config.crypto.access_token_ttl_mins,
        refresh_token_ttl_days = %config.crypto.refresh_token_ttl_days,
        "Configuration loaded"
    );
}

/// Run bootstrap in test mode with provided configuration.
///
/// This is useful for integration tests that need a fully wired
/// application without loading from environment variables.
#[cfg(test)]
pub async fn run_with_config(config: AuthConfig) -> anyhow::Result<AppComponents> {
    init_logging(&config);
    initialize_components(&config).await
}

/// Force shutdown of all resources.
///
/// This is primarily used in tests to ensure clean state between runs.
pub async fn shutdown(components: AppComponents) {
    tracing::info!("Shutting down bootstrap components...");
    components.database.shutdown().await;
    tracing::info!("Shutdown complete");
}
