use futures::future::BoxFuture;

use crate::core::error::CoreError;

pub struct RecoveryNotificationPayload {
    pub to: String,
    /// Raw token forwarded to the notification service — it builds the reset URL.
    pub recovery_token: String,
}

pub trait NotificationClient: Send + Sync {
    fn send_recovery_email(
        &self,
        payload: RecoveryNotificationPayload,
    ) -> BoxFuture<'_, Result<(), CoreError>>;
}