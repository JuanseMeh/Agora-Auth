//! Tests for CryptoError type.
//! 
//! These tests verify the top-level crypto error enum functionality,
//! including creation methods, type checking, and display formatting.

#[cfg(test)]
mod tests {
    use crate::adapters::crypto::error::{CryptoError, JwtError, PasswordError};

    #[test]
    fn test_password_variant_creation() {
        let password_err = PasswordError::hashing("test reason");
        let crypto_err = CryptoError::password(password_err);
        assert!(crypto_err.is_password());
        assert!(!crypto_err.is_token());
    }

    #[test]
    fn test_token_variant_creation() {
        let jwt_err = JwtError::encoding("test reason");
        let crypto_err = CryptoError::token(jwt_err);
        assert!(crypto_err.is_token());
        assert!(!crypto_err.is_password());
    }

    #[test]
    fn test_password_display_formatting() {
        let password_err = PasswordError::hashing("buffer overflow");
        let crypto_err = CryptoError::password(password_err);
        let display = crypto_err.to_string();
        assert!(display.contains("Password hashing failed"));
        assert!(display.contains("buffer overflow"));
    }

    #[test]
    fn test_token_display_formatting() {
        let jwt_err = JwtError::encoding("key invalid");
        let crypto_err = CryptoError::token(jwt_err);
        let display = crypto_err.to_string();
        assert!(display.contains("Token encoding failed"));
        assert!(display.contains("key invalid"));
    }

    #[test]
    fn test_error_clone() {
        let err = CryptoError::password(PasswordError::hashing("test"));
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn test_error_debug() {
        let err = CryptoError::password(PasswordError::hashing("test"));
        let debug = format!("{:?}", err);
        assert!(debug.contains("Password"));
        assert!(debug.contains("Hashing"));
    }

    #[test]
    fn test_implements_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(CryptoError::password(PasswordError::hashing("test")));
        assert!(err.to_string().contains("Password hashing failed"));
    }

    #[test]
    fn test_nested_error_display() {
        let password_err = PasswordError::verification_failed("hash mismatch");
        let crypto_err = CryptoError::password(password_err);
        assert!(crypto_err.to_string().contains("Password verification failed"));
        assert!(crypto_err.to_string().contains("hash mismatch"));
    }

    #[test]
    fn test_both_variants_distinct() {
        let password_crypto = CryptoError::password(PasswordError::hashing("test"));
        let token_crypto = CryptoError::token(JwtError::encoding("test"));
        
        assert!(password_crypto.is_password());
        assert!(!password_crypto.is_token());
        
        assert!(token_crypto.is_token());
        assert!(!token_crypto.is_password());
    }
}
