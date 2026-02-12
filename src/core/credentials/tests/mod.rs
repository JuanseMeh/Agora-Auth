//! Tests for the core credentials module

mod raw_credential_tests;
mod stored_credential_tests;
mod credential_status_tests;
mod credential_policy_tests;
use super::*;

#[test]
fn raw_credential_basic_validation() {
	let policy = CredentialPolicy::default();

	// too short
	let short = RawCredential::new("abc");
	let res = policy.validate_raw(&short);
	assert!(res.is_err());

	// meets default min length
	let ok = RawCredential::new("longenoughpassword");
	let res = policy.validate_raw(&ok);
	assert!(res.is_ok());
}

#[test]
fn raw_credential_format_check() {
	// format_check forbids the letter 'x'
	fn forbids_x(s: &str) -> bool { !s.contains('x') }

	let policy = CredentialPolicy { format_check: Some(forbids_x), ..Default::default() };

	let bad = RawCredential::new("hasxchar");
	assert!(policy.validate_raw(&bad).is_err());

	let good = RawCredential::new("noproblemhere");
	assert!(policy.validate_raw(&good).is_ok());
}

#[test]
fn raw_into_inner_consumes() {
	let raw = RawCredential::new("secret123");
	let inner = raw.into_inner();
	assert_eq!(inner, "secret123");
}

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

#[test]
fn stored_credential_inspectors() {
	let s = StoredCredential::from_hash("hashed-value-abc");
	assert!(s.is_non_empty());
	assert_eq!(s.repr_len(), "hashed-value-abc".len());
	assert_eq!(format!("{:?}", s), "StoredCredential([REDACTED])");
}
