//! Port for external identity persistence (OAuth linking).
//!
//! Finds or creates link between internal user and external provider.
//! Used for OAuth account linking.

use anyhow::Result;
use uuid::Uuid;
use futures::future::BoxFuture;

pub trait ExternalIdentityRepository: Send + Sync {
    /// Find external identity by provider + user ID.
    fn find_by_provider_user(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> BoxFuture<'_, Result<Option<Uuid>>>;

    /// Upsert external identity link (create if not exists, update if exists).
    /// Returns internal user ID.
    fn upsert(
        &self,
        provider: &str,
        provider_user_id: &str,
        user_id: Uuid,
        email: Option<&str>,
    ) -> BoxFuture<'_, Result<Uuid>>;

    /// Delete external identity link.
    fn delete(&self, provider: &str, provider_user_id: &str) -> BoxFuture<'_, Result<()>>;
}

