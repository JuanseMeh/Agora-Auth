use crate::core::credentials::StoredCredential;

#[test]
fn stored_credential_inspectors() {
    let s = StoredCredential::from_hash("hashed-value-abc");
    assert!(s.is_non_empty());
    assert_eq!(s.repr_len(), "hashed-value-abc".len());
    assert_eq!(format!("{:?}", s), "StoredCredential([REDACTED])");
}
