use crate::core::credentials::{RawCredential, CredentialPolicy};

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
