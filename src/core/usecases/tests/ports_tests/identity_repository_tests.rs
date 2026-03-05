//! Tests for IdentityRepository port.

use futures::future::BoxFuture;
use crate::core::identity::UserIdentity;
use crate::core::usecases::ports::IdentityRepository;

struct MockIdentityRepo;
impl IdentityRepository for MockIdentityRepo {
    fn find_by_identifier(&self, identifier: &str) -> BoxFuture<'_, Option<UserIdentity>> {
        let identifier = identifier.to_string();
        Box::pin(async move {
            if identifier == "user" { Some(UserIdentity::new("user123")) } else { None }
        })
    }
    fn find_by_id(&self, id: &str) -> BoxFuture<'_, Option<UserIdentity>> {
        let id = id.to_string();
        Box::pin(async move {
            if id == "user123" { Some(UserIdentity::new(&id)) } else { None }
        })
    }

    fn create(
        &self,
        _user_id: &uuid::Uuid,
        _identifier: &str,
        _password_hash: &str,
        _salt: &str,
        _algorithm: &str,
        _iterations: u32,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move { Ok(()) })
    }
}

#[tokio::test]
async fn identity_repository_find_by_identifier() {
    let repo = MockIdentityRepo;
    assert!(repo.find_by_identifier("user").await.is_some());
    assert!(repo.find_by_identifier("unknown").await.is_none());
}

#[tokio::test]
async fn identity_repository_find_by_id() {
    let repo = MockIdentityRepo;
    assert!(repo.find_by_id("user123").await.is_some());
    assert!(repo.find_by_id("unknown").await.is_none());
}
