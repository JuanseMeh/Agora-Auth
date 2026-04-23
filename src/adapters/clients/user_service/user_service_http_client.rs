//! HTTP client adapter for user_service.
//!
//! Implements UserServiceClient port by calling
//! POST /internal/users/register/google on user_service.

use futures::future::BoxFuture;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::core::error::{AuthenticationError, CoreError};
use crate::core::usecases::ports::user_service_client::{
    RegisterGoogleUserRequest, UserServiceClient,
};

pub struct UserServiceHttpClientConfig {
    pub base_url: String,
}

pub struct UserServiceHttpClient {
    config: UserServiceHttpClientConfig,
    http_client: Client,
}

impl UserServiceHttpClient {
    pub fn new(config: UserServiceHttpClientConfig, http_client: Client) -> Self {
        Self { config, http_client }
    }
}

/// Request body sent to user_service
#[derive(Debug, Serialize)]
struct RegisterGoogleUserBody {
    email: Option<String>,
    name: Option<String>,
    family_name: Option<String>,
    picture: Option<String>,
}

/// Response body received from user_service
#[derive(Debug, Deserialize)]
struct RegisterGoogleUserResponse {
    user_id: Uuid,
}

impl UserServiceClient for UserServiceHttpClient {
    fn register_google_user(
        &self,
        request: RegisterGoogleUserRequest,
    ) -> BoxFuture<'_, Result<Uuid, CoreError>> {
        let url = format!("{}/internal/users/register/google", self.config.base_url);
        let body = RegisterGoogleUserBody {
            email: request.email,
            name: request.name,
            family_name: request.family_name,
            picture: request.picture,
        };

        Box::pin(async move {
            info!("[USER_SERVICE] Sending registration request to {}", url);

            let response = self
                .http_client
                .post(&url)
                .json(&body)
                .send()
                .await
                .map_err(|e| {
                    warn!("[USER_SERVICE] Request failed: {}", e);
                    CoreError::Authentication(AuthenticationError::IncompleteFlow {
                        stage: format!("user_service unreachable: {}", e),
                    })
                })?;

            let status = response.status();

            if status.is_client_error() || status.is_server_error() {
                warn!(
                    status = %status,
                    "[USER_SERVICE] Registration failed with error status"
                );
                return Err(CoreError::Authentication(
                    AuthenticationError::IncompleteFlow {
                        stage: format!(
                            "user_service registration failed with status: {}",
                            status
                        ),
                    },
                ));
            }

            let body: RegisterGoogleUserResponse =
                response.json().await.map_err(|e| {
                    warn!("[USER_SERVICE] Response parse failed: {}", e);
                    CoreError::Authentication(AuthenticationError::IncompleteFlow {
                        stage: format!("user_service response parse failed: {}", e),
                    })
                })?;

            info!(user_id = %body.user_id, "[USER_SERVICE] User registered successfully");
            Ok(body.user_id)
        })
    }
}

