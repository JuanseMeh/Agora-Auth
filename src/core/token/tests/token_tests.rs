use crate::core::token::Token;

#[test]
fn token_new_creates_opaque_value() {
    let token = Token::new("opaque_jwt_string_here");
    assert_eq!(token.value(), "opaque_jwt_string_here");
}

#[test]
fn token_asref_str() {
    let token = Token::new("my_token");
    let s: &str = token.as_ref();
    assert_eq!(s, "my_token");
}

#[test]
fn token_len() {
    let token = Token::new("hello");
    assert_eq!(token.len(), 5);

    let empty = Token::new("");
    assert_eq!(empty.len(), 0);
}

#[test]
fn token_is_empty() {
    let token = Token::new("something");
    assert!(!token.is_empty());

    let empty = Token::new("");
    assert!(empty.is_empty());
}

#[test]
fn token_into_value_consumes() {
    let token = Token::new("secret_token");
    let value = token.into_value();
    assert_eq!(value, "secret_token");
}

#[test]
fn token_clone() {
    let token1 = Token::new("abc123");
    let token2 = token1.clone();
    assert_eq!(token1, token2);
}

#[test]
fn token_equality() {
    let token1 = Token::new("same");
    let token2 = Token::new("same");
    let token3 = Token::new("different");

    assert_eq!(token1, token2);
    assert_ne!(token1, token3);
}

#[test]
fn token_display_hides_value() {
    let token = Token::new("sensitive_token_12345");
    let display = format!("{}", token);
    assert_eq!(display, "Token(****)");
    // Verify the actual token value is not in the display
    assert!(!display.contains("sensitive"));
    assert!(!display.contains("12345"));
}
