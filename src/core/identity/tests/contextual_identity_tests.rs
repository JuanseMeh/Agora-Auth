use crate::core::identity::{ContextualIdentity, UserIdentity, WorkspaceIdentity};
use crate::core::error::InvariantError;

#[test]
fn contextual_requires_at_least_one() {
    let res = ContextualIdentity::new(None, None);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), InvariantError::invalid_configuration("ContextualIdentity requires a user or a workspace"));
}

#[test]
fn contextual_to_claims() {
    let u = UserIdentity::new("u1");
    let w = WorkspaceIdentity::new("w1");
    let ctx = ContextualIdentity::new(Some(u.clone()), Some(w.clone())).unwrap();
    let claims = ctx.to_claims();
    assert_eq!(claims.user_id, Some(u.to_claims_id()));
    assert_eq!(claims.workspace_id, Some(w.to_claims_id()));
}

#[test]
fn contextual_user_only() {
    let u = UserIdentity::new("alice");
    let ctx = ContextualIdentity::new(Some(u.clone()), None).unwrap();
    assert!(ctx.has_user());
    assert!(!ctx.has_workspace());
    assert_eq!(ctx.user_id(), Some("alice"));
    assert_eq!(ctx.workspace_id(), None);
}

#[test]
fn contextual_workspace_only() {
    let w = WorkspaceIdentity::new("ws-1");
    let ctx = ContextualIdentity::new(None, Some(w.clone())).unwrap();
    assert!(!ctx.has_user());
    assert!(ctx.has_workspace());
    assert_eq!(ctx.user_id(), None);
    assert_eq!(ctx.workspace_id(), Some("ws-1"));
}

#[test]
fn contextual_display_user_and_workspace() {
    let u = UserIdentity::new("alice");
    let w = WorkspaceIdentity::new("ws-1");
    let ctx = ContextualIdentity::new(Some(u), Some(w)).unwrap();
    assert_eq!(ctx.to_string(), "UserIdentity(alice)@WorkspaceIdentity(ws-1)");
}

#[test]
fn contextual_display_user_only() {
    let u = UserIdentity::new("alice");
    let ctx = ContextualIdentity::new(Some(u), None).unwrap();
    assert_eq!(ctx.to_string(), "UserIdentity(alice)");
}

#[test]
fn contextual_display_workspace_only() {
    let w = WorkspaceIdentity::new("ws-1");
    let ctx = ContextualIdentity::new(None, Some(w)).unwrap();
    assert_eq!(ctx.to_string(), "WorkspaceIdentity(ws-1)");
}

#[test]
fn contextual_from_user() {
    let user = UserIdentity::new("bob");
    let ctx = ContextualIdentity::from(user);
    assert!(ctx.has_user());
    assert!(!ctx.has_workspace());
    assert_eq!(ctx.user_id(), Some("bob"));
}

#[test]
fn contextual_from_workspace() {
    let workspace = WorkspaceIdentity::new("ws-2");
    let ctx = ContextualIdentity::from(workspace);
    assert!(!ctx.has_user());
    assert!(ctx.has_workspace());
    assert_eq!(ctx.workspace_id(), Some("ws-2"));
}

