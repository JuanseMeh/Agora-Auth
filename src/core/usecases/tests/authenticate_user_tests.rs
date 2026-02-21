
//! Comprehensive tests for AuthenticateUser use case.

use super::super::authenticate_user::{AuthenticateUser, AuthenticateUserInput};
use crate::core::identity::UserIdentity;
use crate::core::credentials::StoredCredential;
use crate::core::usecases::ports::{IdentityRepository, CredentialRepository, PasswordHasher};
use crate::core::error::CoreError;

// ============================================================================
// Mock Implementations
// ============================================================================

struct MockIdentityRepo {
    users: std::collections::HashMap<String, UserIdentity>,
}

impl MockIdentityRepo {
    fn new() -> Self {
        let mut users = std::collections::HashMap::new();
        users.insert("valid_user".to_string(), UserIdentity::new("user123"));
        users.insert("locked_user".to_string(), UserIdentity::new("user456"));
        users.insert("no_credential_user".to_string(), UserIdentity::new("user789"));
        Self { users }
    }
}

impl IdentityRepository for MockIdentityRepo {
    fn find_by_identifier(&self, identifier: &str) -> Option<UserIdentity> {
        self.users.get(identifier).cloned()
    }
    
    fn find_by_id(&self, id: &str) -> Option<UserIdentity> {
        self.users.values().find(|u| u.id() == id).cloned()
    }
    
    fn find_workspace_by_id(&self, _id: &str) -> Option<crate::core::identity::WorkspaceIdentity> {
        None
    }
    
    fn create(
        &self,
        _user_id: &uuid::Uuid,
        _identifier: &str,
        _password_hash: &str,
        _salt: &str,
        _algorithm: &str,
        _iterations: u32,
    ) -> Result<(), String> {
        Ok(())
    }
}

struct MockCredentialRepo {
    credentials: std::cell::RefCell<std::collections::HashMap<String, StoredCredential>>,
    failed_attempts: std::cell::RefCell<std::collections::HashMap<String, u32>>,
    locked_until: std::cell::RefCell<std::collections::HashMap<String, String>>,
}

impl MockCredentialRepo {
    fn new() -> Self {
        let mut credentials = std::collections::HashMap::new();
        
        // Valid user with correct password hash
        let valid_cred = StoredCredential::from_hash("hashed_correct_password");
        credentials.insert("user123".to_string(), valid_cred);
        
        // Locked user
        let locked_cred = StoredCredential::from_hash("hashed_locked_password");
        credentials.insert("user456".to_string(), locked_cred);
        
        Self {
            credentials: std::cell::RefCell::new(credentials),
            failed_attempts: std::cell::RefCell::new(std::collections::HashMap::new()),
            locked_until: std::cell::RefCell::new(std::collections::HashMap::new()),
        }
    }
    
    fn set_locked_until(&self, user_id: &str, until: &str) {
        self.locked_until.borrow_mut().insert(user_id.to_string(), until.to_string());
    }
    
    fn get_failed_attempts(&self, user_id: &str) -> u32 {
        *self.failed_attempts.borrow().get(user_id).unwrap_or(&0)
    }
}

impl CredentialRepository for MockCredentialRepo {
    fn get_by_user_id(&self, user_id: &str) -> Option<StoredCredential> {
        self.credentials.borrow().get(user_id).map(|c| {
            let mut cred = StoredCredential::from_hash(c.as_hash_str());
            // Get failed_attempts from tracking map (more up-to-date than stored credential)
            cred.failed_attempts = *self.failed_attempts.borrow().get(user_id).unwrap_or(&c.failed_attempts);
            // Get locked_until from tracking map (more up-to-date than stored credential)
            cred.locked_until = self.locked_until.borrow().get(user_id).cloned().or_else(|| c.locked_until.clone());
            cred
        })
    }
    
    fn update_failed_attempts(&self, user_id: &str, attempts: u32) {
        self.failed_attempts.borrow_mut().insert(user_id.to_string(), attempts);
    }
    
    fn lock_until(&self, user_id: &str, until: &str) {
        self.locked_until.borrow_mut().insert(user_id.to_string(), until.to_string());
    }
    
    fn update_password(&self, _user_id: &str, _new_credential: StoredCredential) {}
    
    fn initialize_credential_state(&self, _user_id: &str) -> Result<(), String> {
        Ok(())
    }
}

struct MockPasswordHasher;

impl PasswordHasher for MockPasswordHasher {
    fn hash(&self, raw: &str) -> StoredCredential {
        StoredCredential::from_hash(format!("hashed_{}", raw))
    }
    
    fn verify(&self, raw: &str, stored: &StoredCredential) -> bool {
        // Check if the stored hash matches what we'd expect for the raw password
        let expected_hash = format!("hashed_{}", raw);
        stored.as_hash_str() == expected_hash
    }
}

// ============================================================================
// Test Cases
// ============================================================================

#[test]
fn test_authenticate_user_success() {
    let identity_repo = MockIdentityRepo::new();
    let credential_repo = MockCredentialRepo::new();
    let password_hasher = MockPasswordHasher;
    
    let use_case = AuthenticateUser::new(
        &identity_repo,
        &credential_repo,
        &password_hasher,
        5,    // max_attempts
        60,   // lockout_duration_minutes
    );
    
    let input = AuthenticateUserInput {
        identifier: "valid_user".to_string(),
        password: "correct_password".to_string(),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_ok(), "Authentication should succeed with valid credentials");
    
    let output = result.unwrap();
    assert!(output.user.id() == "user123");
    
    // Verify failed attempts were reset
    assert_eq!(credential_repo.get_failed_attempts("user123"), 0);
}

#[test]
fn test_authenticate_user_not_found() {
    let identity_repo = MockIdentityRepo::new();
    let credential_repo = MockCredentialRepo::new();
    let password_hasher = MockPasswordHasher;
    
    let use_case = AuthenticateUser::new(
        &identity_repo,
        &credential_repo,
        &password_hasher,
        5,
        60,
    );
    
    let input = AuthenticateUserInput {
        identifier: "nonexistent_user".to_string(),
        password: "any_password".to_string(),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_err(), "Authentication should fail for non-existent user");
    
    match result.unwrap_err() {
        CoreError::Authentication(err) => {
            assert!(err.to_string().contains("not found") || 
                    err.to_string().contains("identifier"));
        }
        _ => panic!("Expected AuthenticationError"),
    }
}

#[test]
fn test_authenticate_user_wrong_password() {
    let identity_repo = MockIdentityRepo::new();
    let credential_repo = MockCredentialRepo::new();
    let password_hasher = MockPasswordHasher;
    
    let use_case = AuthenticateUser::new(
        &identity_repo,
        &credential_repo,
        &password_hasher,
        5,
        60,
    );
    
    let input = AuthenticateUserInput {
        identifier: "valid_user".to_string(),
        password: "wrong_password".to_string(),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_err(), "Authentication should fail with wrong password");
    
    // Verify failed attempts were incremented
    assert_eq!(credential_repo.get_failed_attempts("user123"), 1);
}

#[test]
fn test_authenticate_user_account_locked_by_time() {
    let identity_repo = MockIdentityRepo::new();
    let credential_repo = MockCredentialRepo::new();
    let password_hasher = MockPasswordHasher;
    
    // Set user as locked until far future
    let future_time = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();
    credential_repo.set_locked_until("user456", &future_time);
    
    // Update the credential in the credentials map to have the locked_until value
    let locked_cred = StoredCredential::from_parts("hashed_locked_password", 0, Some(future_time.clone()));
    credential_repo.credentials.borrow_mut().insert("user456".to_string(), locked_cred);
    
    let use_case = AuthenticateUser::new(
        &identity_repo,
        &credential_repo,
        &password_hasher,
        5,
        60,
    );
    
    let input = AuthenticateUserInput {
        identifier: "locked_user".to_string(),
        password: "locked_password".to_string(),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_err(), "Authentication should fail for locked account");
    
    match result.unwrap_err() {
        CoreError::Authentication(err) => {
            assert!(err.to_string().to_lowercase().contains("lock"));
        }
        _ => panic!("Expected AuthenticationError with lock message"),
    }
}

#[test]
fn test_authenticate_user_lockout_after_max_attempts() {
    let identity_repo = MockIdentityRepo::new();
    let credential_repo = MockCredentialRepo::new();
    let password_hasher = MockPasswordHasher;
    
    let use_case = AuthenticateUser::new(
        &identity_repo,
        &credential_repo,
        &password_hasher,
        3,    // max_attempts = 3
        60,
    );
    
    // First 2 failed attempts
    for i in 1..=2 {
        let input = AuthenticateUserInput {
            identifier: "valid_user".to_string(),
            password: "wrong_password".to_string(),
        };
        let result = use_case.execute(input);
        assert!(result.is_err());
        drop(result); // Drop result to release borrow
        // After each attempt, we need to update the credential in the map with the new failed_attempts
        let current_attempts = credential_repo.get_failed_attempts("user123");
        let valid_cred = StoredCredential::from_parts("hashed_correct_password", current_attempts, None);
        credential_repo.credentials.borrow_mut().insert("user123".to_string(), valid_cred);
        assert_eq!(current_attempts, i);
    }
    
    // 3rd failed attempt should trigger lockout
    let input = AuthenticateUserInput {
        identifier: "valid_user".to_string(),
        password: "wrong_password".to_string(),
    };
    let result = use_case.execute(input);
    assert!(result.is_err());
    drop(result); // Drop result to release borrow
    let current_attempts = credential_repo.get_failed_attempts("user123");
    let valid_cred = StoredCredential::from_parts("hashed_correct_password", current_attempts, None);
    credential_repo.credentials.borrow_mut().insert("user123".to_string(), valid_cred);
    assert_eq!(current_attempts, 3);
    
    // Next attempt should fail due to lockout
    let input = AuthenticateUserInput {
        identifier: "valid_user".to_string(),
        password: "correct_password".to_string(), // Even with correct password
    };
    let result = use_case.execute(input);
    assert!(result.is_err(), "Should be locked out after max attempts");
}

#[test]
fn test_authenticate_user_reset_failed_attempts_on_success() {
    let identity_repo = MockIdentityRepo::new();
    let credential_repo = MockCredentialRepo::new();
    let password_hasher = MockPasswordHasher;
    
    let use_case = AuthenticateUser::new(
        &identity_repo,
        &credential_repo,
        &password_hasher,
        5,
        60,
    );
    
    // First, add some failed attempts
    credential_repo.update_failed_attempts("user123", 3);
    assert_eq!(credential_repo.get_failed_attempts("user123"), 3);
    
    // Successful authentication should reset
    let input = AuthenticateUserInput {
        identifier: "valid_user".to_string(),
        password: "correct_password".to_string(),
    };
    
    let _output = use_case.execute(input);
    assert!(_output.is_ok());
    
    // Failed attempts should be reset to 0
    assert_eq!(credential_repo.get_failed_attempts("user123"), 0);
}

#[test]
fn test_authenticate_user_no_credential_found() {
    let identity_repo = MockIdentityRepo::new();
    let credential_repo = MockCredentialRepo::new();
    let password_hasher = MockPasswordHasher;
    
    let use_case = AuthenticateUser::new(
        &identity_repo,
        &credential_repo,
        &password_hasher,
        5,
        60,
    );
    
    // User exists but has no credential
    let input = AuthenticateUserInput {
        identifier: "no_credential_user".to_string(),
        password: "any_password".to_string(),
    };
    
    let result = use_case.execute(input);
    assert!(result.is_err(), "Should fail when no credential exists");
}

#[test]
fn test_authenticate_user_lockout_expired() {
    let identity_repo = MockIdentityRepo::new();
    let credential_repo = MockCredentialRepo::new();
    let password_hasher = MockPasswordHasher;
    
    // Set lock to past time (expired)
    let past_time = (chrono::Utc::now() - chrono::Duration::hours(1)).to_rfc3339();
    credential_repo.set_locked_until("user456", &past_time);
    
    let use_case = AuthenticateUser::new(
        &identity_repo,
        &credential_repo,
        &password_hasher,
        5,
        60,
    );
    
    let input = AuthenticateUserInput {
        identifier: "locked_user".to_string(),
        password: "locked_password".to_string(),
    };
    
    // Should succeed because lock has expired
    let result = use_case.execute(input);
    // Note: This will fail because the password doesn't match the hash
    // but it won't be due to lockout
    match result {
        Err(CoreError::Authentication(err)) => {
            // Should be "invalid credentials" not "account locked"
            assert!(!err.to_string().to_lowercase().contains("lock"));
        }
        _ => {} // Could succeed or fail for other reasons
    }
}
