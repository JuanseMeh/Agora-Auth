

//! Tests for SessionRepository port.

use crate::core::identity::UserIdentity;
use crate::core::usecases::ports::SessionRepository;
use crate::core::usecases::session_repository::Session;

struct MockSessionRepo;
impl SessionRepository for MockSessionRepo {
    fn create_session(&self, _user: &UserIdentity, _refresh_token_hash: &str, _metadata: &str) {}
    fn find_by_refresh_token_hash(&self, _hash: &str) -> Option<Session> { None }
    fn revoke_session(&self, _session_id: &str) {}
    fn revoke_all_for_user(&self, _user_id: &str) {}
    fn delete_expired(&self) {}
}

#[test]
fn session_repository_create_session() {
    let repo = MockSessionRepo;
    let user = UserIdentity::new("user123");
    repo.create_session(&user, "hash", "metadata");
    // No assertion needed, just check method call
}

#[test]
fn session_repository_revoke_session() {
    let repo = MockSessionRepo;
    repo.revoke_session("session123");
    // No assertion needed, just check method call
}
