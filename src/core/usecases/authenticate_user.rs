//! Use case: AuthenticateUser
//!
//! Orchestrates user authentication with lockout policy enforcement.
//!
//! Responsibilities:
//! - Lookup user by identifier
//! - Check account lockout status
//! - Verify password against stored credential
//! - Track failed attempts and apply lockout policy
//! - Return authenticated user identity on success

use crate::core::error::{AuthenticationError, CoreError};
use crate::core::identity::UserIdentity;
use crate::core::usecases::ports::{CredentialRepository, IdentityRepository, PasswordHasher};

/// Input contract for AuthenticateUser use case.
pub struct AuthenticateUserInput {
    pub identifier: String,
    pub password: String,
}

/// Output contract for AuthenticateUser use case.
#[derive(Debug)]
pub struct AuthenticateUserOutput {
    pub user: UserIdentity,
}

/// Use case for authenticating a user with password.
pub struct AuthenticateUser<'a> {
    identity_repo: &'a dyn IdentityRepository,
    credential_repo: &'a dyn CredentialRepository,
    password_hasher: &'a dyn PasswordHasher,
    max_attempts: u32,
    lockout_duration_minutes: u32,
}

impl<'a> AuthenticateUser<'a> {
    /// Create a new AuthenticateUser use case with dependencies.
    pub fn new(
        identity_repo: &'a dyn IdentityRepository,
        credential_repo: &'a dyn CredentialRepository,
        password_hasher: &'a dyn PasswordHasher,
        max_attempts: u32,
        lockout_duration_minutes: u32,
    ) -> Self {
        Self {
            identity_repo,
            credential_repo,
            password_hasher,
            max_attempts,
            lockout_duration_minutes,
        }
    }

    /// Execute the authentication use case.
    pub fn execute(&self, input: AuthenticateUserInput) -> Result<AuthenticateUserOutput, CoreError> {
        // Step 1: Find user by identifier
        let user = self
            .identity_repo
            .find_by_identifier(&input.identifier)
            .ok_or_else(|| AuthenticationError::user_not_found("identifier not found"))?;

        // Step 2: Get credential state for lockout check
        let credential = self
            .credential_repo
            .get_by_user_id(&user.id);

        // Step 3: Check if account is locked
        if let Some(ref cred) = credential {
            if let Some(ref locked_until) = cred.locked_until {
                let now = chrono::Utc::now().to_rfc3339();
                if locked_until > &now {
                    return Err(AuthenticationError::account_locked(format!(
                        "account locked until {}",
                        locked_until
                    ))
                    .into());
                }
            }
        }

        // Step 4: Verify password
        let password_valid = credential
            .as_ref()
            .map(|cred| self.password_hasher.verify(&input.password, cred))
            .unwrap_or(false);

        if !password_valid {
            // Increment failed attempts
            let new_attempts = credential
                .as_ref()
                .map(|c| c.failed_attempts + 1)
                .unwrap_or(1);

            self.credential_repo
                .update_failed_attempts(&user.id, new_attempts);

            // Apply lockout if threshold reached
            if new_attempts >= self.max_attempts {
                let lockout_until = chrono::Utc::now()
                    + chrono::Duration::minutes(self.lockout_duration_minutes as i64);
                self.credential_repo
                    .lock_until(&user.id, &lockout_until.to_rfc3339());
            }

            return Err(AuthenticationError::user_not_found("invalid credentials").into());
        }

        // Step 5: Reset failed attempts on successful authentication
        self.credential_repo.update_failed_attempts(&user.id, 0);

        Ok(AuthenticateUserOutput { user })
    }
}
