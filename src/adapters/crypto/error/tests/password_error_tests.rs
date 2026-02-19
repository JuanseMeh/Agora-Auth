//! Tests for PasswordError type.
//! 
//! These tests verify the password error creation, display formatting,
//! and conversion to domain errors.

#[cfg(test)]
mod tests {
    use crate::adapters::crypto::error::PasswordError;
    use crate::core::error::CredentialError;

    #[test]
    fn test_hashing_error_creation() {
        let err = PasswordError::hashing("memory limit exceeded");
        assert!(err.to_string().contains("Password hashing failed"));
        assert!(err.to_string().contains("memory limit exceeded"));
    }

    #[test]
    fn test_verification_failed_error_creation() {
        let err = PasswordError::verification_failed("password mismatch");
        assert!(err.to_string().contains("Password verification failed"));
        assert!(err.to_string().contains("password mismatch"));
    }

    #[test]
    fn test_invalid_hash_error_creation() {
        let err = PasswordError::invalid_hash("corrupted format");
        assert!(err.to_string().contains("Invalid hash format"));
        assert!(err.to_string().contains("corrupted format"));
    }

    #[test]
    fn test_error_clone() {
        let err = PasswordError::hashing("test");
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn test_error_debug() {
        let err = PasswordError::hashing("test");
        let debug = format!("{:?}", err);
        assert!(debug.contains("Hashing"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_conversion_to_credential_error_hashing() {
        let password_err = PasswordError::hashing("argon2 failure");
        let cred_err: CredentialError = password_err.into();
        assert!(cred_err.to_string().contains("hashing failed"));
        assert!(cred_err.to_string().contains("argon2 failure"));
    }

    #[test]
    fn test_conversion_to_credential_error_verification() {
        let password_err = PasswordError::verification_failed("hash mismatch");
        let cred_err: CredentialError = password_err.into();
        assert!(cred_err.to_string().contains("verification failed"));
        assert!(cred_err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn test_conversion_to_credential_error_invalid_hash() {
        let password_err = PasswordError::invalid_hash("corrupted");
        let cred_err: CredentialError = password_err.into();
        assert!(cred_err.to_string().contains("Invalid password_hash format"));
        assert!(cred_err.to_string().contains("corrupted"));
    }

    #[test]
    fn test_implements_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(PasswordError::hashing("test"));
        assert!(err.to_string().contains("Password hashing failed"));
    }

    #[test]
    fn test_empty_reason() {
        let err = PasswordError::hashing("");
        assert!(err.to_string().contains("Password hashing failed"));
    }

    #[test]
    fn test_long_reason() {
        let long_reason = "a".repeat(1000);
        let err = PasswordError::hashing(&long_reason);
        assert!(err.to_string().contains(&long_reason));
    }
}
