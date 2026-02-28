//! Bootstrap layer — composition root for the authentication service.
//!
//! This module is responsible for:
//! - Loading and validating configuration
//! - Initializing infrastructure (database, crypto)
//! - Building repositories and services
//! - Composing the HTTP application
//! - Starting the server with graceful shutdown

pub mod config;
pub mod server;
pub mod wiring;

// The bootstrap module contains the main orchestration logic
pub mod bootstrap;

pub use config::{AuthConfig, DeploymentMode};
pub use server::run_server;
pub use wiring::{initialize_components, AppComponents};

// Re-export the main run function for convenience
pub use self::bootstrap::run;

#[cfg(test)]
pub mod tests;