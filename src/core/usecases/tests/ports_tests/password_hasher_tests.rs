
//! Tests for PasswordHasher port.

use crate::core::credentials::StoredCredential;
use crate::core::usecases::ports::PasswordHasher;

struct MockPasswordHasher;
impl PasswordHasher for MockPasswordHasher {
    fn hash(&self, raw: &str) -> StoredCredential {
        StoredCredential::from_hash(format!("hashed_{}", raw))
    }
    fn verify(&self, raw: &str, stored: &StoredCredential) -> bool {
        stored.is_non_empty() && raw == "correct"
    }
}

#[test]
fn password_hasher_hash() {
    let hasher = MockPasswordHasher;
    let cred = hasher.hash("password");
    assert!(cred.is_non_empty());
}

#[test]
fn password_hasher_verify() {
    let hasher = MockPasswordHasher;
    let cred = hasher.hash("correct");
    assert!(hasher.verify("correct", &cred));
    assert!(!hasher.verify("wrong", &cred));
}
