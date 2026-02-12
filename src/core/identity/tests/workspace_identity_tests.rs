use crate::core::identity::WorkspaceIdentity;

#[test]
fn workspace_identity_basics() {
    let a = WorkspaceIdentity::new("ws-1");
    let b = WorkspaceIdentity::new("ws-1");
    assert_eq!(a, b);
    assert_eq!(a.to_claims_id(), "ws-1".to_string());
}
