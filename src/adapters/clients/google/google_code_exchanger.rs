//! Google OAuth authorization code exchanger.

use std::sync::Arc;
use std::time::Duration;
use futures::future::BoxFuture;
use reqwest::Client;
use serde_json::Value;
use tracing::{debug, info, warn, instrument};

use crate::core::identity::ExternalIdentity;
use crate::core::error::{CoreError, AuthenticationError};
use crate::core::usecases::ports::{ExchangeAuthorizationCode, ExternalTokenValidator};

/// Configuration for GoogleCodeExchanger.
#[derive(Debug, Clone)]
pub struct GoogleCodeExchangerConfig {
    pub client_id: String,
    pub client_secret: String,
    pub token_url: String,
    pub redirect_uri: String,
    pub timeout: Duration,
    pub max_retries: u32,
}

/// Google OAuth authorization code exchanger.
pub struct GoogleCodeExchanger {
    config: GoogleCodeExchangerConfig,
    http_client: Client,
    token_validator: Arc<dyn ExternalTokenValidator + Send + Sync>,
}

impl GoogleCodeExchanger {
    pub fn new(
        config: GoogleCodeExchangerConfig,
        http_client: Client,
        token_validator: Arc<dyn ExternalTokenValidator + Send + Sync>,
    ) -> Self {
        Self { config, http_client, token_validator }
    }
}

impl ExchangeAuthorizationCode for GoogleCodeExchanger {
    #[instrument(skip(self, code, _state), fields(provider = "google"))]
    fn exchange(&self, code: &str, _state: Option<&str>) -> BoxFuture<'static, Result<ExternalIdentity, CoreError>> {
        let config = self.config.clone();
        let http_client = self.http_client.clone();
        let token_validator = Arc::clone(&self.token_validator);
        let code = code.to_string();

        Box::pin(async move {
            info!("[GOOGLE_CODE_EXCHANGER] Starting token exchange");
            debug!(
                token_url = %config.token_url,
                redirect_uri = %config.redirect_uri,
                client_id = %config.client_id,
                "[GOOGLE_CODE_EXCHANGER] Exchange parameters"
            );

            let mut last_err: Option<CoreError> = None;

            for attempt in 0..=config.max_retries {
                if attempt > 0 {
                    // Exponential backoff: 200ms, 400ms, 800ms…
                    let backoff = Duration::from_millis(200 * (1 << (attempt - 1)));
                    warn!(attempt, ?backoff, "[GOOGLE_CODE_EXCHANGER] Retrying token exchange");
                    tokio::time::sleep(backoff).await;
                }

                let form_params = [
                    ("client_id",     config.client_id.as_str()),
                    ("client_secret", config.client_secret.as_str()),
                    ("code",          code.as_str()),
                    ("grant_type",    "authorization_code"),
                    ("redirect_uri",  config.redirect_uri.as_str()),
                ];

                let result = http_client
                    .post(&config.token_url)
                    .timeout(config.timeout)
                    .form(&form_params)
                    .send()
                    .await;

                let response = match result {
                    Ok(r) => r,
                    Err(e) => {
                        // Network/timeout errors are retryable
                        info!("[GOOGLE_CODE_EXCHANGER] Request failed: {}", e);
                        last_err = Some(CoreError::Authentication(
                            AuthenticationError::InvalidExternalToken {
                                reason: format!("Request failed: {}", e),
                            }
                        ));
                        continue;
                    }
                };

                let status = response.status();

                // 4xx errors are not retryable — bad code, bad credentials, etc.
                if status.is_client_error() {
                    info!(status = %status, "[GOOGLE_CODE_EXCHANGER] Client error from Google");
                    return Err(CoreError::Authentication(
                        AuthenticationError::InvalidExternalToken {
                            reason: format!("HTTP {} from Google token endpoint", status),
                        }
                    ));
                }

                // 5xx errors are retryable
                if status.is_server_error() {
                    warn!(status = %status, "[GOOGLE_CODE_EXCHANGER] Server error from Google, will retry");
                    last_err = Some(CoreError::Authentication(
                        AuthenticationError::InvalidExternalToken {
                            reason: format!("HTTP {} from Google token endpoint", status),
                        }
                    ));
                    continue;
                }

                let json: Value = response
                    .json()
                    .await
                    .map_err(|e| CoreError::Authentication(
                        AuthenticationError::InvalidExternalToken {
                            reason: format!("Failed to parse JSON response: {}", e),
                        }
                    ))?;

                let id_token = json["id_token"]
                    .as_str()
                    .ok_or_else(|| CoreError::Authentication(
                        AuthenticationError::InvalidExternalToken {
                            reason: "No id_token field in token response".to_string(),
                        }
                    ))?
                    .to_string();

                info!("[GOOGLE_CODE_EXCHANGER] ID token received, delegating to validator");
                return token_validator.validate(&id_token).await;
            }

            // All retries exhausted
            warn!("[GOOGLE_CODE_EXCHANGER] All retries exhausted");
            Err(last_err.unwrap_or_else(|| CoreError::Authentication(
                AuthenticationError::InvalidExternalToken {
                    reason: "Token exchange failed after all retries".to_string(),
                }
            )))
        })
    }
}
