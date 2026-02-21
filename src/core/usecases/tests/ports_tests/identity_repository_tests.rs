
//! Tests for IdentityRepository port.

use crate::core::identity::UserIdentity;
use crate::core::usecases::ports::IdentityRepository;

struct MockIdentityRepo;
impl IdentityRepository for MockIdentityRepo {
    fn find_by_identifier(&self, identifier: &str) -> Option<UserIdentity> {
        if identifier == "user" { Some(UserIdentity::new("user123")) } else { None }
    }
    fn find_by_id(&self, id: &str) -> Option<UserIdentity> {
        if id == "user123" { Some(UserIdentity::new(id)) } else { None }
    }
    fn find_workspace_by_id(&self, _id: &str) -> Option<crate::core::identity::WorkspaceIdentity> { None }
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

#[test]
fn identity_repository_find_by_identifier() {
    let repo = MockIdentityRepo;
    assert!(repo.find_by_identifier("user").is_some());
    assert!(repo.find_by_identifier("unknown").is_none());
}

#[test]
fn identity_repository_find_by_id() {
    let repo = MockIdentityRepo;
    assert!(repo.find_by_id("user123").is_some());
    assert!(repo.find_by_id("unknown").is_none());
}
