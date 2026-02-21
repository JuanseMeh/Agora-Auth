//! Service registry port for validating service API keys

/// Port for service registry operations
/// 
/// This trait defines the interface for validating service API keys
/// and retrieving service information. Implementations may use
/// in-memory storage, databases, or external service registries.
pub trait ServiceRegistry: Send + Sync {
    /// Validate an API key and return the service name if valid
    /// 
    /// # Arguments
    /// * `api_key` - The API key to validate
    /// 
    /// # Returns
    /// * `Some(String)` - The service name if the key is valid
    /// * `None` - If the key is invalid or not found
    fn validate_api_key(&self, api_key: &str) -> Option<String>;
    
    /// Check if a service is active and allowed to make requests
    /// 
    /// # Arguments
    /// * `service_name` - The name of the service to check
    /// 
    /// # Returns
    /// * `true` - If the service is active
    /// * `false` - If the service is inactive or not found
    fn is_service_active(&self, service_name: &str) -> bool;
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::RwLock;
    
    /// Mock implementation of ServiceRegistry for testing
    pub struct MockServiceRegistry {
        valid_keys: RwLock<HashMap<String, String>>,
        active_services: RwLock<Vec<String>>,
    }
    
    impl MockServiceRegistry {
        /// Create a new mock registry with predefined keys
        pub fn new() -> Self {
            let mut valid_keys = HashMap::new();
            valid_keys.insert("valid-service-key-123".to_string(), "test-service".to_string());
            valid_keys.insert("internal-service-key-456".to_string(), "internal-service".to_string());
            
            let active_services = vec![
                "test-service".to_string(),
                "internal-service".to_string(),
            ];
            
            Self {
                valid_keys: RwLock::new(valid_keys),
                active_services: RwLock::new(active_services),
            }
        }
        
        /// Add a new API key for testing
        pub fn add_key(&self, key: &str, service_name: &str) {
            self.valid_keys.write().unwrap().insert(key.to_string(), service_name.to_string());
        }
        
        /// Deactivate a service for testing
        pub fn deactivate_service(&self, service_name: &str) {
            let mut services = self.active_services.write().unwrap();
            services.retain(|s| s != service_name);
        }
    }
    
    impl ServiceRegistry for MockServiceRegistry {
        fn validate_api_key(&self, api_key: &str) -> Option<String> {
            self.valid_keys.read().unwrap().get(api_key).cloned()
        }
        
        fn is_service_active(&self, service_name: &str) -> bool {
            self.active_services.read().unwrap().contains(&service_name.to_string())
        }
    }
}
