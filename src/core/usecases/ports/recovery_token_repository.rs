use futures::future::BoxFuture;
use uuid::Uuid;
use crate::core::credentials::recovery_token::RecoveryToken;
use crate::core::error::CoreError;

pub trait RecoveryTokenRepository: Send + Sync {
    /// Persist a new recovery token.
    fn create(&self, token: &RecoveryToken) -> BoxFuture<'_, Result<(), CoreError>>;

    /// Find a token by its hash. Returns None if not found.
    fn find_by_hash(&self, token_hash: &str) -> BoxFuture<'_, Result<Option<RecoveryToken>, CoreError>>;

    /// Mark a token as used (sets used_at = now).
    fn mark_used(&self, token_id: Uuid) -> BoxFuture<'_, Result<(), CoreError>>;

    /// Invalidate all unused recovery tokens for a given user.
    /// Called before creating a new token to enforce single active token.
    fn invalidate_all_for_user(&self, user_id: Uuid) -> BoxFuture<'_, Result<(), CoreError>>;
}