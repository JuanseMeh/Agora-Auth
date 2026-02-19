//! Tests for JwtError type.
//! 
//! These tests verify the JWT error creation, display formatting,
//! and conversion to domain errors.

#[cfg(test)]
mod tests {
    use crate::adapters::crypto::error::JwtError;
    use crate::core::error::TokenError;

    #[test]
    fn test_encoding_error_creation() {
        let err = JwtError::encoding("invalid key format");
        assert!(err.to_string().contains("Token encoding failed"));
        assert!(err.to_string().contains("invalid key format"));
    }

    #[test]
    fn test_decoding_error_creation() {
        let err = JwtError::decoding("signature verification failed");
        assert!(err.to_string().contains("Token decoding failed"));
        assert!(err.to_string().contains("signature verification failed"));
    }

    #[test]
    fn test_invalid_token_error_creation() {
        let err = JwtError::invalid_token("malformed header");
        assert!(err.to_string().contains("Invalid token"));
        assert!(err.to_string().contains("malformed header"));
    }

    #[test]
    fn test_error_clone() {
        let err = JwtError::encoding("test");
        let cloned = err.clone();
        assert_eq!(err.to_string(), cloned.to_string());
    }

    #[test]
    fn test_error_debug() {
        let err = JwtError::encoding("test");
        let debug = format!("{:?}", err);
        assert!(debug.contains("Encoding"));
        assert!(debug.contains("test"));
    }

    #[test]
    fn test_conversion_to_token_error_encoding() {
        let jwt_err = JwtError::encoding("key failure");
        let token_err: TokenError = jwt_err.into();
        assert!(token_err.to_string().contains("encoding failed"));
        assert!(token_err.to_string().contains("key failure"));
    }

    #[test]
    fn test_conversion_to_token_error_decoding() {
        let jwt_err = JwtError::decoding("signature mismatch");
        let token_err: TokenError = jwt_err.into();
        assert!(token_err.to_string().contains("decoding failed"));
        assert!(token_err.to_string().contains("signature mismatch"));
    }

    #[test]
    fn test_conversion_to_token_error_invalid() {
        let jwt_err = JwtError::invalid_token("bad format");
        let token_err: TokenError = jwt_err.into();
        assert!(token_err.to_string().contains("bad format"));
    }

    #[test]
    fn test_implements_error_trait() {
        let err: Box<dyn std::error::Error> = Box::new(JwtError::encoding("test"));
        assert!(err.to_string().contains("Token encoding failed"));
    }

    #[test]
    fn test_empty_reason() {
        let err = JwtError::encoding("");
        assert!(err.to_string().contains("Token encoding failed"));
    }

    #[test]
    fn test_special_characters_in_reason() {
        let reason = "error: \"quoted\" and \\escaped\\";
        let err = JwtError::encoding(reason);
        assert!(err.to_string().contains(reason));
    }
}
