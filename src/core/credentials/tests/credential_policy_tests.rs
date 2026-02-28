use crate::core::credentials::CredentialPolicy;

#[test]
fn credential_policy_defaults() {
    let p = CredentialPolicy::default();
    assert_eq!(p.min_length, 8);
    assert!(p.require_complexity);
}
