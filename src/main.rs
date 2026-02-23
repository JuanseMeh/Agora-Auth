//! Authentication service entry point.
//!
//! This is the minimal main.rs as recommended by the bootstrap README.
//! All initialization logic is delegated to the bootstrap layer.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    auth::bootstrap::run().await
}
