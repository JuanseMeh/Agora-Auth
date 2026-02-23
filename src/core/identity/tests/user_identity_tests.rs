use crate::core::identity::UserIdentity;

#[test]
fn user_identity_basics() {
    let a = UserIdentity::new("alice");
    let b = UserIdentity::new("alice");
    assert_eq!(a, b);
    assert_eq!(a.to_claims_id(), "alice".to_string());
}
