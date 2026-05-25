-- Database schema for Agora Auth

-- Table: identity_credential
-- Stores authentication credentials and account security state
CREATE TABLE IF NOT EXISTS identity_credential (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    identifier TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until TIMESTAMPTZ NULL,
    password_changed_at TIMESTAMPTZ NOT NULL,
    hash_version VARCHAR(32) NOT NULL DEFAULT 'argon2id-v19',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for looking up identity by identifier
CREATE INDEX IF NOT EXISTS idx_identity_credential_identifier ON identity_credential(identifier);

-- Table: auth_session
-- Stores refresh token sessions
CREATE TABLE IF NOT EXISTS auth_session (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    refresh_token_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NULL,
    ip_address TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    token_version VARCHAR(32) NOT NULL DEFAULT 'jwt-eddsa-v1',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Index for looking up session by refresh_token_hash
CREATE INDEX IF NOT EXISTS idx_auth_session_refresh_token_hash ON auth_session(refresh_token_hash);

-- Index for looking up sessions by user_id
CREATE INDEX IF NOT EXISTS idx_auth_session_user_id ON auth_session(user_id);

-- Index for finding expired sessions to clean up
CREATE INDEX IF NOT EXISTS idx_auth_session_expires_at ON auth_session(expires_at);

-- Partial index for active (non-revoked) sessions
CREATE INDEX IF NOT EXISTS idx_auth_session_active ON auth_session(expires_at)  WHERE revoked_at IS NULL;

-- Stores short-lived, single-use password recovery tokens (stored hashed).
 
CREATE TABLE IF NOT EXISTS credential_recovery (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL,
    token_hash  TEXT        NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ NULL,       -- NULL = unused; timestamp = consumed/invalidated
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
 
-- Lookup by hash (primary access pattern on confirm).
CREATE INDEX IF NOT EXISTS idx_credential_recovery_token_hash
    ON credential_recovery(token_hash);
 
-- Lookup all tokens for a user (used on invalidate_all_for_user).
CREATE INDEX IF NOT EXISTS idx_credential_recovery_user_id
    ON credential_recovery(user_id);
 
-- Used by a periodic cleanup job to purge expired rows.
CREATE INDEX IF NOT EXISTS idx_credential_recovery_expires_at
    ON credential_recovery(expires_at);
 


-- Table: external_identities
CREATE TABLE IF NOT EXISTS external_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    provider VARCHAR(32) NOT NULL,  -- 'google', 'github', etc.
    provider_user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, provider_user_id)
);