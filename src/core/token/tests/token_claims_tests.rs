use crate::core::token::TokenClaims;

#[test]
fn token_claims_new_basic() {
    let claims = TokenClaims::new(
        "alice".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    );

    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.iat, 1772712911);
    assert_eq!(claims.exp, 1772716511);
    assert_eq!(claims.token_type, "access");
    assert!(claims.sid.is_none());
    assert!(claims.aud.is_none());
    assert!(claims.nbf.is_none());
    assert!(claims.scope.is_empty());
}

#[test]
fn token_claims_with_not_before() {
    let claims = TokenClaims::new(
        "bob".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    )
    .with_not_before(1772712911);

    assert_eq!(claims.nbf, Some(1772712911));
}

#[test]
fn token_claims_with_scopes() {
    let scopes = vec!["read".to_string(), "write".to_string()];
    let claims = TokenClaims::new(
        "charlie".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    )
    .with_scopes(scopes.clone());

    assert_eq!(claims.scope, scopes);
}

#[test]
fn token_claims_has_identity() {
    let claims_with = TokenClaims::new(
        "alice".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    );
    assert!(claims_with.has_identity());

    let claims_empty = TokenClaims::new(
        "".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    );
    assert!(!claims_empty.has_identity());
}

#[test]
fn token_claims_has_scopes() {
    let claims_no_scopes = TokenClaims::new(
        "user1".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    );
    assert!(!claims_no_scopes.has_scopes());

    let claims_with_scopes = TokenClaims::new(
        "user1".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    )
    .with_scopes(vec!["scope1".to_string()]);
    assert!(claims_with_scopes.has_scopes());

    // Empty scopes list counts as no scopes
    let claims_empty_scopes = TokenClaims::new(
        "user2".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    )
    .with_scopes(vec![]);
    assert!(!claims_empty_scopes.has_scopes());
}

#[test]
fn token_claims_scopes_as_slice() {
    let claims_no_scopes = TokenClaims::new(
        "user".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    );
    assert_eq!(claims_no_scopes.scopes(), &[] as &[String]);


    let scopes = vec!["read".to_string(), "write".to_string(), "admin".to_string()];
    let claims = TokenClaims::new(
        "user".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    )
    .with_scopes(scopes.clone());

    assert_eq!(claims.scopes(), scopes.as_slice());
}

#[test]
fn token_claims_with_sid() {
    let claims = TokenClaims::new(
        "alice".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    )
    .with_sid("session-123");

    assert_eq!(claims.sid, Some("session-123".to_string()));
}

#[test]
fn token_claims_with_audience() {
    let claims = TokenClaims::new(
        "alice".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    )
    .with_audience(vec!["orders_service".to_string(), "billing_service".to_string()]);

    assert_eq!(claims.aud, Some(vec!["orders_service".to_string(), "billing_service".to_string()]));
}

#[test]
fn token_claims_equality() {
    let claims1 = TokenClaims::new(
        "user".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    );

    let claims2 = TokenClaims::new(
        "user".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    );

    assert_eq!(claims1, claims2);
}

#[test]
fn token_claims_with_only_user() {
    let claims = TokenClaims::new(
        "user_id".to_string(),
        1772712911,
        1772716511,
        "access".to_string(),
    );

    assert!(claims.has_identity());
}
