use crate::core::identity::IdentityClaims;

#[test]
fn identity_claims_empty() {
    let c = IdentityClaims { user_id: None, workspace_id: None };
    assert!(c.is_empty());
}

#[test]
fn identity_claims_user_only() {
    let c = IdentityClaims { user_id: Some("alice".to_string()), workspace_id: None };
    assert!(!c.is_empty());
    assert_eq!(c.user_id, Some("alice".to_string()));
    assert_eq!(c.workspace_id, None);
}

#[test]
fn identity_claims_workspace_only() {
    let c = IdentityClaims { user_id: None, workspace_id: Some("ws-1".to_string()) };
    assert!(!c.is_empty());
    assert_eq!(c.user_id, None);
    assert_eq!(c.workspace_id, Some("ws-1".to_string()));
}

#[test]
fn identity_claims_both() {
    let c = IdentityClaims { 
        user_id: Some("alice".to_string()), 
        workspace_id: Some("ws-1".to_string()) 
    };
    assert!(!c.is_empty());
    assert_eq!(c.user_id, Some("alice".to_string()));
    assert_eq!(c.workspace_id, Some("ws-1".to_string()));
}

