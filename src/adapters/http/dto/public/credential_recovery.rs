use serde::{Deserialize, Serialize};

/// POST /auth/recovery/request
#[derive(Debug, Deserialize)]
pub struct RequestRecoveryDto {
    pub identifier: String,
}

/// POST /auth/recovery/confirm
#[derive(Debug, Deserialize)]
pub struct ConfirmRecoveryDto {
    pub token: String,
    pub new_password: String,
}

/// Uniform success envelope — identical whether identifier existed or not.
#[derive(Debug, Serialize)]
pub struct RecoverySuccessResponse {
    pub message: &'static str,
}