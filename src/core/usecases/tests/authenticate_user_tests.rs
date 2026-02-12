
//! Tests for AuthenticateUser use case.

use super::super::authenticate_user::{AuthenticateUserInput, AuthenticateUserOutput};
use crate::core::identity::UserIdentity;
use crate::core::credentials::StoredCredential;
use crate::core::usecases::ports::{IdentityRepository, CredentialRepository, PasswordHasher};
use crate::core::usecases::policies::LockoutPolicy;

struct MockIdentityRepo;
impl IdentityRepository for MockIdentityRepo {
    fn find_by_identifier(&self, identifier: &str) -> Option<UserIdentity> {
        if identifier == "valid_user" {
            Some(UserIdentity::new("user123"))
        } else {
            None
        }
    }
    fn find_by_id(&self, id: &str) -> Option<UserIdentity> {
        if id == "user123" {
            Some(UserIdentity::new(id))
        } else {
            None
        }
    }
    fn find_workspace_by_id(&self, _id: &str) -> Option<crate::core::identity::WorkspaceIdentity> {
        None
    }
}

struct MockCredentialRepo {
    pub failed_attempts: u32,
    pub locked_until: Option<u64>, // epoch seconds
}
impl CredentialRepository for MockCredentialRepo {
    fn get_by_user_id(&self, user_id: &str) -> Option<StoredCredential> {
        if user_id == "user123" {
            Some(StoredCredential::from_hash("hashed_password"))
        } else {
            None
        }
    }
    fn update_failed_attempts(&self, _user_id: &str, _attempts: u32) {}
    fn lock_until(&self, _user_id: &str, _until: &str) {}
    fn update_password(&self, _user_id: &str, _new_credential: StoredCredential) {}
}

struct MockPasswordHasher;
impl PasswordHasher for MockPasswordHasher {
    fn hash(&self, raw: &str) -> StoredCredential {
        StoredCredential::from_hash(format!("hashed_{}", raw))
    }
    fn verify(&self, raw: &str, stored: &StoredCredential) -> bool {
        stored.is_non_empty() && raw == "correct_password"
    }
}

#[test]
fn authenticate_user_success() {
    let input = AuthenticateUserInput {
        identifier: "valid_user".to_string(),
        password: "correct_password".to_string(),
    };
    let identity_repo = MockIdentityRepo;
    let credential_repo = MockCredentialRepo { failed_attempts: 0, locked_until: None };
    let password_hasher = MockPasswordHasher;
    let lockout_policy = LockoutPolicy::new(5, 3600, true);

    // Simulate AuthenticateUser orchestration
    let user = identity_repo.find_by_identifier(&input.identifier).expect("User not found");
    let stored_cred = credential_repo.get_by_user_id(user.id()).expect("Credential not found");
    assert!(!lockout_policy.is_locked(credential_repo.failed_attempts));
    assert!(password_hasher.verify(&input.password, &stored_cred));
    let output = AuthenticateUserOutput { user };
    assert_eq!(output.user.id(), "user123");
}

#[test]
fn authenticate_user_lockout() {
    let input = AuthenticateUserInput {
        identifier: "valid_user".to_string(),
        password: "wrong_password".to_string(),
    };
    let identity_repo = MockIdentityRepo;
    let credential_repo = MockCredentialRepo { failed_attempts: 5, locked_until: None };
    let password_hasher = MockPasswordHasher;
    let lockout_policy = LockoutPolicy::new(5, 3600, true);

    let user = identity_repo.find_by_identifier(&input.identifier).expect("User not found");
    let stored_cred = credential_repo.get_by_user_id(user.id()).expect("Credential not found");
    assert!(lockout_policy.is_locked(credential_repo.failed_attempts));
    assert!(!password_hasher.verify(&input.password, &stored_cred));
    // Lockout should prevent authentication
}

#[test]
fn authenticate_user_locked_until() {
    let input = AuthenticateUserInput {
        identifier: "valid_user".to_string(),
        password: "correct_password".to_string(),
    };
    let identity_repo = MockIdentityRepo;
    // Simulate user locked until a future time
    let now = 1_700_000_000u64;
    let locked_until = now + 3600; // locked for 1 hour
    let credential_repo = MockCredentialRepo { failed_attempts: 0, locked_until: Some(locked_until) };
    let password_hasher = MockPasswordHasher;
    let _lockout_policy = LockoutPolicy::new(5, 3600, true);

    let user = identity_repo.find_by_identifier(&input.identifier).expect("User not found");
    let stored_cred = credential_repo.get_by_user_id(user.id()).expect("Credential not found");
    // Simulate lockout check by time
    let is_locked = if let Some(locked_until) = credential_repo.locked_until {
        now < locked_until
    } else {
        false
    };
    assert!(is_locked, "User should be locked until a future time");
    // Authentication should not proceed
    assert!(password_hasher.verify(&input.password, &stored_cred)); // password is correct, but lockout blocks
}
