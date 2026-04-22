//! Port for registering a new user via Google OAuth in user_service.
//!
//! Auth service calls this during the Google registration branch,
//! after exchanging the code but before upserting the external identity.
//! Auth never stores name/family_name/picture — it only forwards them here.

use futures::future::BoxFuture;
use uuid::Uuid;

use crate::core::error::CoreError;

/// Data extracted from Google identity to seed the new user record.
/// Auth service passes this through without storing it.
pub struct RegisterGoogleUserRequest {
    pub email: Option<String>,
    pub name: Option<String>,
    pub family_name: Option<String>,
    pub picture: Option<String>,
}

pub trait UserServiceClient: Send + Sync {
    /// Call user_service to create a new user from Google identity data.
    /// Returns the newly created user's UUID.
    fn register_google_user(
        &self,
        request: RegisterGoogleUserRequest,
    ) -> BoxFuture<'_, Result<Uuid, CoreError>>;
}