use crate::core::token::TokenClaims;
use crate::core::identity::IdentityClaims;

#[test]
fn token_claims_new_basic() {
    let identity = IdentityClaims {
        user_id: Some("alice".to_string()),
        workspace_id: None,
    };

    let claims = TokenClaims::new(
        identity.clone(),
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    );

    assert_eq!(claims.identity, identity);
    assert_eq!(claims.issued_at, "2026-02-12T10:00:00Z");
    assert_eq!(claims.expires_at, "2026-02-12T11:00:00Z");
    assert!(claims.not_before.is_none());
    assert!(claims.scopes.is_none());
}

#[test]
fn token_claims_with_not_before() {
    let identity = IdentityClaims {
        user_id: Some("bob".to_string()),
        workspace_id: Some("ws123".to_string()),
    };

    let claims = TokenClaims::new(
        identity,
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    )
    .with_not_before("2026-02-12T10:30:00Z");

    assert_eq!(claims.not_before, Some("2026-02-12T10:30:00Z".to_string()));
}

#[test]
fn token_claims_with_scopes() {
    let identity = IdentityClaims {
        user_id: Some("charlie".to_string()),
        workspace_id: None,
    };

    let scopes = vec!["read".to_string(), "write".to_string()];
    let claims = TokenClaims::new(
        identity,
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    )
    .with_scopes(scopes.clone());

    assert_eq!(claims.scopes, Some(scopes));
}

#[test]
fn token_claims_has_identity() {
    let with_user = IdentityClaims {
        user_id: Some("alice".to_string()),
        workspace_id: None,
    };

    let claims_with = TokenClaims::new(
        with_user,
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    );
    assert!(claims_with.has_identity());

    let empty = IdentityClaims {
        user_id: None,
        workspace_id: None,
    };

    let claims_empty = TokenClaims::new(
        empty,
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    );
    assert!(!claims_empty.has_identity());
}

#[test]
fn token_claims_has_scopes() {
    let identity = IdentityClaims {
        user_id: Some("user1".to_string()),
        workspace_id: None,
    };

    let claims_no_scopes = TokenClaims::new(
        identity.clone(),
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    );
    assert!(!claims_no_scopes.has_scopes());

    let claims_with_scopes = TokenClaims::new(
        identity,
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    )
    .with_scopes(vec!["scope1".to_string()]);
    assert!(claims_with_scopes.has_scopes());

    // Empty scopes list counts as no scopes
    let claims_empty_scopes = TokenClaims::new(
        IdentityClaims {
            user_id: Some("user2".to_string()),
            workspace_id: None,
        },
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    )
    .with_scopes(vec![]);
    assert!(!claims_empty_scopes.has_scopes());
}

#[test]
fn token_claims_scopes_as_slice() {
    let identity = IdentityClaims {
        user_id: Some("user".to_string()),
        workspace_id: None,
    };

    let claims_no_scopes = TokenClaims::new(
        identity.clone(),
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    );
    assert_eq!(claims_no_scopes.scopes(), &[] as &[String]);


    let scopes = vec!["read".to_string(), "write".to_string(), "admin".to_string()];
    let claims = TokenClaims::new(
        identity,
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    )
    .with_scopes(scopes.clone());

    assert_eq!(claims.scopes(), scopes.as_slice());
}

#[test]
fn token_claims_chaining() {
    let identity = IdentityClaims {
        user_id: Some("alice".to_string()),
        workspace_id: Some("org1".to_string()),
    };

    let claims = TokenClaims::new(
        identity.clone(),
        "2026-02-12T10:00:00Z",
        "2026-02-12T12:00:00Z",
    )
    .with_not_before("2026-02-12T10:15:00Z")
    .with_scopes(vec!["read".to_string(), "write".to_string()]);

    assert_eq!(claims.identity, identity);
    assert_eq!(claims.issued_at, "2026-02-12T10:00:00Z");
    assert_eq!(claims.expires_at, "2026-02-12T12:00:00Z");
    assert_eq!(claims.not_before, Some("2026-02-12T10:15:00Z".to_string()));
    assert!(claims.has_scopes());
}

#[test]
fn token_claims_equality() {
    let identity = IdentityClaims {
        user_id: Some("user".to_string()),
        workspace_id: None,
    };

    let claims1 = TokenClaims::new(
        identity.clone(),
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    );

    let claims2 = TokenClaims::new(
        identity,
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    );

    assert_eq!(claims1, claims2);
}

#[test]
fn token_claims_with_only_workspace() {
    let identity = IdentityClaims {
        user_id: None,
        workspace_id: Some("workspace_id".to_string()),
    };

    let claims = TokenClaims::new(
        identity,
        "2026-02-12T10:00:00Z",
        "2026-02-12T11:00:00Z",
    );

    assert!(claims.has_identity());
}
