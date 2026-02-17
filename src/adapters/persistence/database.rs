// Database connection pool and transaction management.

use sqlx::postgres::{PgPool, PgPoolOptions, PgConnectOptions, PgConnection};
use std::time::Duration;
use std::str::FromStr;

use crate::adapters::persistence::error::{ConnectionError, PersistenceError};

/// Connection pool configuration.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of connections in the pool
    pub max_connections: u32,
    /// Connection idle timeout before being closed
    pub idle_timeout: Duration,
    /// Maximum lifetime of a connection
    pub max_lifetime: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 20,
            idle_timeout: Duration::from_secs(600),
            max_lifetime: Duration::from_secs(1800),
        }
    }
}

/// Database connection pool manager.
///
/// Handles creation, management, and lifecycle of database connections.
/// All repository operations must use this pool.
#[derive(Clone)]
pub struct Database {
    pool: PgPool,
}

impl Database {
    /// Create a new database connection pool.
    ///
    /// # Arguments
    ///
    /// * `database_url` - PostgreSQL connection string
    /// * `config` - Pool configuration
    ///
    /// # Errors
    ///
    /// Returns `PersistenceError::Connection` if the pool cannot be created
    /// or if the initial connection test fails.
    pub async fn new(
        database_url: &str,
        config: PoolConfig,
    ) -> Result<Self, PersistenceError> {
        if database_url.is_empty() {
            return Err(PersistenceError::Connection(ConnectionError::unavailable(
                "database URL cannot be empty",
            )));
        }

        let connect_options = PgConnectOptions::from_str(database_url).map_err(|e| {
            PersistenceError::Connection(ConnectionError::unavailable(format!(
                "invalid database url: {}",
                e
            )))
        })?;

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .idle_timeout(Some(config.idle_timeout))
            .max_lifetime(Some(config.max_lifetime))
            .connect_with(connect_options)
            .await
            .map_err(|e| {
                PersistenceError::Connection(ConnectionError::unavailable(format!(
                    "failed to create connection pool: {}",
                    e
                )))
            })?;

        // Test the connection
        sqlx::query("SELECT 1")
            .execute(&pool)
            .await
            .map_err(|e| {
                PersistenceError::Connection(ConnectionError::unavailable(format!(
                    "failed to test connection: {}",
                    e
                )))
            })?;

        Ok(Self { pool })
    }

    /// Create a new database connection pool with default configuration.
    pub async fn new_default(database_url: &str) -> Result<Self, PersistenceError> {
        Self::new(database_url, PoolConfig::default()).await
    }

    /// Get a reference to the connection pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Acquire a single connection from the pool.
    pub async fn acquire(&self) -> Result<PgConnection, PersistenceError> {
        self.pool
            .acquire()
            .await
            .map(|conn| conn.detach())
            .map_err(|e| {
                PersistenceError::Connection(ConnectionError::pool_exhausted(format!(
                    "failed to acquire connection: {}",
                    e
                )))
            })
    }

    /// Close all connections in the pool.
    pub async fn shutdown(&self) {
        self.pool.close().await;
    }

    /// Get pool statistics for monitoring.
    pub fn pool_stats(&self) -> PoolStats {
        let size = self.pool.size();

        PoolStats {
            num_idle: size,
            pool_size: size,
        }
    }
}

/// Statistics about the connection pool state.
#[derive(Debug, Clone, Copy)]
pub struct PoolStats {
    /// Number of idle connections available
    pub num_idle: u32,
    /// Total pool size
    pub pool_size: u32,
}
