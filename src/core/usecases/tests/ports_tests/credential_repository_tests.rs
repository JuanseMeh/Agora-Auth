
//! Tests for CredentialRepository port.

use crate::core::credentials::StoredCredential;
use crate::core::usecases::ports::CredentialRepository;

struct MockCredentialRepo;
impl CredentialRepository for MockCredentialRepo {
    fn get_by_user_id(&self, user_id: &str) -> Option<StoredCredential> {
        if user_id == "user123" { Some(StoredCredential::from_hash("hash")) } else { None }
    }
    fn update_failed_attempts(&self, _user_id: &str, _attempts: u32) {}
    fn lock_until(&self, _user_id: &str, _until: &str) {}
    fn update_password(&self, _user_id: &str, _new_credential: StoredCredential) {}
    fn initialize_credential_state(&self, _user_id: &str) -> Result<(), String> {
        Ok(())
    }
}

#[test]
fn credential_repository_get_by_user_id() {
    let repo = MockCredentialRepo;
    assert!(repo.get_by_user_id("user123").is_some());
    assert!(repo.get_by_user_id("unknown").is_none());
}

#[test]
fn credential_repository_update_failed_attempts() {
    let repo = MockCredentialRepo;
    repo.update_failed_attempts("user123", 3);
    // No assertion needed, just check method call
}
