use crate::core::error::{CoreError, AuthenticationError};
use crate::core::identity::external_identity::ExternalIdentity;
use serde_json::json;

    #[test]
    fn test_new_success_with_email() {
        let result = ExternalIdentity::new("google".to_string(), "123456".to_string(), Some("user@example.com".to_string()));
        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.provider, "google");
        assert_eq!(identity.provider_user_id, "123456");
        assert_eq!(identity.email, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_new_success_without_email() {
        let result = ExternalIdentity::new("github".to_string(), "abcdef".to_string(), None);
        assert!(result.is_ok());
        let identity = result.unwrap();
        assert_eq!(identity.provider, "github");
        assert_eq!(identity.provider_user_id, "abcdef");
        assert!(identity.email.is_none());
    }

    #[test]
    fn test_new_empty_provider_error() {
        let result = ExternalIdentity::new("".to_string(), "123456".to_string(), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CoreError::Authentication(AuthenticationError::InvalidExternalIdentity { .. })));
        if let CoreError::Authentication(AuthenticationError::InvalidExternalIdentity { reason }) = err {
            assert_eq!(reason, "empty provider name");
        }
    }

    #[test]
    fn test_new_empty_provider_user_id_error() {
        let result = ExternalIdentity::new("google".to_string(), "".to_string(), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, CoreError::Authentication(AuthenticationError::InvalidExternalIdentity { .. })));
        if let CoreError::Authentication(AuthenticationError::InvalidExternalIdentity { reason }) = err {
            assert_eq!(reason, "empty provider user ID");
        }
    }

    #[test]
    fn test_new_whitespace_provider_error() {
        let result = ExternalIdentity::new("   ".to_string(), "123456".to_string(), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        if let CoreError::Authentication(AuthenticationError::InvalidExternalIdentity { reason }) = err {
            assert_eq!(reason, "empty provider name");
        }
    }

    #[test]
    fn test_new_unicode_success() {
        let result = ExternalIdentity::new("göögle".to_string(), "☃".to_string(), None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_partial_eq_same() {
        let id1 = ExternalIdentity::new("google".to_string(), "123".to_string(), Some("a@b.com".to_string())).unwrap();
        let id2 = ExternalIdentity::new("google".to_string(), "123".to_string(), Some("a@b.com".to_string())).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_partial_eq_different_provider() {
        let id1 = ExternalIdentity::new("google".to_string(), "123".to_string(), None).unwrap();
        let id2 = ExternalIdentity::new("github".to_string(), "123".to_string(), None).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_partial_eq_different_user_id() {
        let id1 = ExternalIdentity::new("google".to_string(), "123".to_string(), None).unwrap();
        let id2 = ExternalIdentity::new("google".to_string(), "456".to_string(), None).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_partial_eq_different_email() {
        let id1 = ExternalIdentity::new("google".to_string(), "123".to_string(), Some("a@b.com".to_string())).unwrap();
        let id2 = ExternalIdentity::new("google".to_string(), "123".to_string(), None).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_clone() {
        let original = ExternalIdentity::new("google".to_string(), "123".to_string(), None).unwrap();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_debug() {
        let identity = ExternalIdentity::new("google".to_string(), "123".to_string(), Some("test@example.com".to_string())).unwrap();
        let debug_str = format!("{:?}", identity);
        assert!(debug_str.contains("google"));
        assert!(debug_str.contains("123"));
        assert!(debug_str.contains("test@example.com"));
    }

    #[test]
    fn test_serde_roundtrip() {
        let original = ExternalIdentity::new("google".to_string(), "123456".to_string(), Some("user@example.com".to_string())).unwrap();
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: ExternalIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_serde_json_format() {
        let identity = ExternalIdentity::new("google".to_string(), "123456".to_string(), Some("user@example.com".to_string())).unwrap();
        let json_value = serde_json::to_value(&identity).unwrap();
        let expected = json!({
            "provider": "google",
            "provider_user_id": "123456",
            "email": "user@example.com"
        });
        assert_eq!(json_value, expected);
    }

