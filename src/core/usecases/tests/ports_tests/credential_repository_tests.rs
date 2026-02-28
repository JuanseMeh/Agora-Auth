//! Tests for CredentialRepository port.

use futures::future::BoxFuture;
use crate::core::credentials::StoredCredential;
use crate::core::usecases::ports::CredentialRepository;

struct MockCredentialRepo;
impl CredentialRepository for MockCredentialRepo {
    fn get_by_user_id(&self, user_id: &str) -> BoxFuture<'_, Option<StoredCredential>> {
        let user_id = user_id.to_string();
        Box::pin(async move {
            if user_id == "user123" { 
                Some(StoredCredential::from_hash("hash".to_string())) 
            } else { 
                None 
            }
        })
    }
    fn update_failed_attempts(&self, _user_id: &str, _attempts: u32) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    fn lock_until(&self, _user_id: &str, _until: &str) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    fn update_password(&self, _user_id: &str, _new_credential: StoredCredential) -> BoxFuture<'_, ()> {
        Box::pin(async move {})
    }
    fn initialize_credential_state(&self, _user_id: &str) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move { Ok(()) })
    }
}

#[tokio::test]
async fn credential_repository_get_by_user_id() {
    let repo = MockCredentialRepo;
    assert!(repo.get_by_user_id("user123").await.is_some());
    assert!(repo.get_by_user_id("unknown").await.is_none());
}

#[tokio::test]
async fn credential_repository_update_failed_attempts() {
    let repo = MockCredentialRepo;
    repo.update_failed_attempts("user123", 3).await;
    // No assertion needed, just check method call
}
