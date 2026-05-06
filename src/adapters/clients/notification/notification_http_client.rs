use futures::future::BoxFuture;
use futures::FutureExt;
use reqwest::Client;
use serde::Serialize;

use crate::core::error::CoreError;
use crate::core::usecases::ports::notification_client::{
    NotificationClient, RecoveryNotificationPayload,
};

#[derive(Serialize)]
struct RecoveryEmailRequest<'a> {
    to: &'a str,
    recovery_token: &'a str,
}

pub struct NotificationHttpClient {
    client: Client,
    base_url: String,
}

impl NotificationHttpClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: Client::new(),
            base_url,
        }
    }
}

impl NotificationClient for NotificationHttpClient {
    fn send_recovery_email(
        &self,
        payload: RecoveryNotificationPayload,
    ) -> BoxFuture<'_, Result<(), CoreError>> {
        async move {
            let url = format!("{}/notifications/recovery-email", self.base_url);
            let body = RecoveryEmailRequest {
                to: &payload.to,
                recovery_token: &payload.recovery_token,
            };

            let response = self
                .client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    tracing::error!("Notification service request failed: {}", e);
                    CoreError::Invariant(crate::core::error::InvariantError::inconsistent_state(
                        "Notification service unreachable",
                    ))
                })?;

            if !response.status().is_success() {
                tracing::error!(
                    "Notification service returned {}: {}",
                    response.status(),
                    response.text().await.unwrap_or_default()
                );
            }

            Ok(())
        }
        .boxed()
    }
}