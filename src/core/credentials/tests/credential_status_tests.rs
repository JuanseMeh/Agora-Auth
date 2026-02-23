use crate::core::credentials::CredentialStatus;

#[test]
fn credential_status_invariants() {
    assert!(CredentialStatus::Active.ensure_verifiable().is_ok());

    let revoked = CredentialStatus::Revoked { revoked_at: Some("2026-01-01".into()) };
    let e = revoked.ensure_verifiable();
    assert!(e.is_err());

    let expired = CredentialStatus::Expired { expired_at: Some("2024-01-01".into()) };
    assert!(expired.ensure_verifiable().is_err());

    let nyv = CredentialStatus::NotYetValid { valid_from: Some("2030-01-01".into()) };
    assert!(nyv.ensure_verifiable().is_err());
}
