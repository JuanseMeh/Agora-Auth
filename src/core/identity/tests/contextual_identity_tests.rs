use crate::core::identity::{ContextualIdentity, UserIdentity};
use crate::core::error::InvariantError;

#[test]
fn contextual_requires_user() {
    let res = ContextualIdentity::new(None);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), InvariantError::invalid_configuration("ContextualIdentity requires a user"));
}

#[test]
fn contextual_to_claims() {
    let u = UserIdentity::new("u1");
    let ctx = ContextualIdentity::new(Some(u.clone())).unwrap();
    let claims = ctx.to_claims();
    assert_eq!(claims.user_id, Some(u.to_claims_id()));
}

#[test]
fn contextual_user_only() {
    let u = UserIdentity::new("alice");
    let ctx = ContextualIdentity::new(Some(u.clone())).unwrap();
    assert!(ctx.has_user());
    assert_eq!(ctx.user_id(), Some("alice"));
}

#[test]
fn contextual_display_user_only() {
    let u = UserIdentity::new("alice");
    let ctx = ContextualIdentity::new(Some(u)).unwrap();
    assert_eq!(ctx.to_string(), "UserIdentity(alice)");
}

#[test]
fn contextual_from_user() {
    let user = UserIdentity::new("bob");
    let ctx = ContextualIdentity::from(user);
    assert!(ctx.has_user());
    assert_eq!(ctx.user_id(), Some("bob"));
}

