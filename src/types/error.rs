use axum::http::StatusCode;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthError {
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Insufficient payment channel balance")]
    InsufficientBalance,
    #[error("Payment channel expired")]
    Expired,
    #[error("Invalid payment channel")]
    InvalidChannel,
    #[error("Rate limit exceeded")]
    RateLimitExceeded,
    #[error("Contract interaction failed: {0}")]
    ContractError(String),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Channel already exists")]
    ChannelExists,
    #[error("Invalid network configuration")]
    InvalidConfig,
}

impl From<AuthError> for StatusCode {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::InvalidSignature => StatusCode::UNAUTHORIZED,
            AuthError::InsufficientBalance => StatusCode::PAYMENT_REQUIRED,
            AuthError::Expired => StatusCode::REQUEST_TIMEOUT,
            AuthError::InvalidChannel => StatusCode::BAD_REQUEST,
            AuthError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            AuthError::ContractError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::NetworkError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            AuthError::ChannelExists => StatusCode::CONFLICT,
            AuthError::InvalidConfig => StatusCode::BAD_REQUEST,
        }
    }
}
