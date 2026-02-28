/// Database connection pool tests.

#[cfg(test)]
mod tests {
    use crate::adapters::persistence::{database::PoolConfig, Database};
    use std::time::Duration;

    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections, 20);
        assert_eq!(config.idle_timeout, Duration::from_secs(600));
        assert_eq!(config.max_lifetime, Duration::from_secs(1800));
    }

    #[test]
    fn test_pool_config_custom() {
        let config = PoolConfig {
            max_connections: 50,
            idle_timeout: Duration::from_secs(300),
            max_lifetime: Duration::from_secs(3600),
        };
        assert_eq!(config.max_connections, 50);
        assert_eq!(config.idle_timeout, Duration::from_secs(300));
        assert_eq!(config.max_lifetime, Duration::from_secs(3600));
    }

    #[ignore] // This test requires a running PostgreSQL instance defined in docker-compose
    #[tokio::test]
    async fn test_database_connection_to_docker_compose() {
        // Connection string for docker-compose PostgreSQL
        let database_url = "postgres://auth:password@localhost:5432/auth";

        // Create a new database connection pool
        let database = Database::new_default(database_url)
            .await
            .expect("Failed to connect to database");

        // Verify the connection works by executing a simple query
        let result = sqlx::query("SELECT 1")
            .execute(database.pool())
            .await
            .expect("Failed to execute test query");

        assert_eq!(result.rows_affected(), 1);

        // Clean up - close the pool
        database.shutdown().await;
    }
}
