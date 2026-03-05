use crate::core::identity::IdentityClaims;

#[test]
fn identity_claims_empty() {
    let c = IdentityClaims { user_id: None };
    assert!(c.is_empty());
}

#[test]
fn identity_claims_user_only() {
    let c = IdentityClaims { user_id: Some("alice".to_string()) };
    assert!(!c.is_empty());
    assert_eq!(c.user_id, Some("alice".to_string()));
}

