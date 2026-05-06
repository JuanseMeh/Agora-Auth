use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::{
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
};
use dashmap::DashMap;

use crate::adapters::clients::notification::notification_http_client::NotificationHttpClient;
use crate::adapters::http::dto::public::credential_recovery::{
    ConfirmRecoveryDto, RecoverySuccessResponse, RequestRecoveryDto,
};
use crate::adapters::http::error::HttpError;
use crate::core::usecases::ports::notification_client::{
    NotificationClient, RecoveryNotificationPayload,
};
use crate::core::usecases::{
    confirm_credential_recovery::ConfirmCredentialRecovery,
    request_credential_recovery::RequestCredentialRecovery,
};

/// In-memory rate limiter — max N attempts per identifier per window.
/// Single-instance only; swap for Redis-backed counter when scaling horizontally.
#[derive(Clone)]
pub struct RecoveryRateLimiter {
    attempts: Arc<DashMap<String, (u32, Instant)>>,
    max_attempts: u32,
    window: Duration,
}

impl RecoveryRateLimiter {
    pub fn new(max_attempts: u32, window: Duration) -> Self {
        Self {
            attempts: Arc::new(DashMap::new()),
            max_attempts,
            window,
        }
    }

    /// Returns true if the request is within the allowed rate.
    pub fn check_and_record(&self, key: &str) -> bool {
        let mut entry = self
            .attempts
            .entry(key.to_string())
            .or_insert((0, Instant::now()));
        let (count, window_start) = entry.value_mut();

        if window_start.elapsed() > self.window {
            *count = 1;
            *window_start = Instant::now();
            return true;
        }

        if *count >= self.max_attempts {
            return false;
        }

        *count += 1;
        true
    }
}

#[tracing::instrument(skip(use_case, notification_client, limiter))]
pub async fn handle_request_recovery(
    State((use_case, notification_client, limiter)): State<(
        Arc<RequestCredentialRecovery>,
        Arc<NotificationHttpClient>,
        RecoveryRateLimiter,
    )>,
    Json(dto): Json<RequestRecoveryDto>,
) -> Result<impl IntoResponse, HttpError> {
    if !limiter.check_and_record(&dto.identifier) {
        return Err(HttpError::TooManyRequests(
            "Too many recovery requests. Please try again later.".into(),
        ));
    }

    // Use case returns the raw token — or None if identifier doesn't exist.
    let maybe_token = use_case
        .execute(&dto.identifier)
        .await
        .map_err(HttpError::from)?;

    // Fire notification best-effort — never surface errors to the client.
    if let Some(raw_token) = maybe_token {
        let _ = notification_client
            .send_recovery_email(RecoveryNotificationPayload {
                to: dto.identifier.clone(),
                recovery_token: raw_token.as_str().to_string(),
            })
            .await;
    }

    // Always return the same response — prevents identifier enumeration.
    Ok((
        StatusCode::OK,
        Json(RecoverySuccessResponse {
            message: "If that account exists, a recovery email has been sent.",
        }),
    ))
}

#[tracing::instrument(skip(use_case, dto))]
pub async fn handle_confirm_recovery(
    State(use_case): State<Arc<ConfirmCredentialRecovery>>,
    Json(dto): Json<ConfirmRecoveryDto>,
) -> Result<impl IntoResponse, HttpError> {
    use_case
        .execute(&dto.token, &dto.new_password)
        .await
        .map_err(HttpError::from)?;

    Ok((
        StatusCode::OK,
        Json(RecoverySuccessResponse {
            message: "Password updated successfully.",
        }),
    ))
}
