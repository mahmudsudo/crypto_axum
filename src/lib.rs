use axum::{
    http::{StatusCode, Request},
    middleware::Next,
    response::Response,
    routing::post,
    body::Body,
    Router,
    Json,
};
use ethers::{
    types::{Address, Signature, U256, H256},
    utils::keccak256,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaymentChannel {
    pub sender: Address,
    pub recipient: Address,
    pub balance: U256,
    pub nonce: U256,
    pub expiration: U256,
    pub channel_id: H256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRequest {
    pub message: Vec<u8>,
    pub signature: Signature,
    pub payment_channel: PaymentChannel,
    pub payment_amount: U256,
}

#[derive(Clone)]
pub struct ChannelState {
    channels: Arc<RwLock<HashMap<H256, PaymentChannel>>>,
    rate_limiter: Arc<RwLock<HashMap<Address, (u64, SystemTime)>>>,
}

impl ChannelState {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn check_rate_limit(&self, sender: Address) -> Result<(), AuthError> {
        const RATE_LIMIT: u64 = 100;
        const WINDOW: u64 = 60;
        
        let mut rate_limits = self.rate_limiter.write().await;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let (count, last_reset) = rate_limits
            .entry(sender)
            .or_insert((0, SystemTime::now()));
        
        let last_reset_secs = last_reset
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if now - last_reset_secs >= WINDOW {
            *count = 1;
            *last_reset = SystemTime::now();
            Ok(())
        } else if *count >= RATE_LIMIT {
            Err(AuthError::RateLimitExceeded)
        } else {
            *count += 1;
            Ok(())
        }
    }
}

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
}

impl From<AuthError> for StatusCode {
    fn from(error: AuthError) -> Self {
        match error {
            AuthError::InvalidSignature => StatusCode::UNAUTHORIZED,
            AuthError::InsufficientBalance => StatusCode::PAYMENT_REQUIRED,
            AuthError::Expired => StatusCode::REQUEST_TIMEOUT,
            AuthError::InvalidChannel => StatusCode::BAD_REQUEST,
            AuthError::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
        }
    }
}

pub fn create_message(
    channel_id: H256,
    amount: U256,
    nonce: U256,
    request_data: &[u8],
) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(channel_id.as_bytes());
    message.extend_from_slice(&amount.to_be_bytes_vec());
    message.extend_from_slice(&nonce.to_be_bytes_vec());
    message.extend_from_slice(request_data);
    message
}

async fn verify_and_update_channel(
    state: &ChannelState,
    request: &SignedRequest,
) -> Result<(), AuthError> {
    let message_hash = keccak256(&request.message);
    let recovered_address = request.signature
        .recover(message_hash)
        .map_err(|_| AuthError::InvalidSignature)?;

    if recovered_address != request.payment_channel.sender {
        return Err(AuthError::InvalidSignature);
    }

    state.check_rate_limit(request.payment_channel.sender).await?;

    let mut channels = state.channels.write().await;
    let channel = channels
        .entry(request.payment_channel.channel_id)
        .or_insert_with(|| request.payment_channel.clone());

    if request.payment_channel.nonce <= channel.nonce {
        return Err(AuthError::InvalidChannel);
    }

    if request.payment_channel.balance < request.payment_amount {
        return Err(AuthError::InsufficientBalance);
    }

    channel.balance = request.payment_channel.balance;
    channel.nonce = request.payment_channel.nonce;

    Ok(())
}

pub async fn auth_middleware(
    state: ChannelState,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let timestamp = request
        .headers()
        .get("X-Timestamp")
        .and_then(|t| t.to_str().ok())
        .and_then(|t| t.parse::<u64>().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now - timestamp > 300 {
        return Err(StatusCode::REQUEST_TIMEOUT);
    }

    let signature = request
        .headers()
        .get("X-Signature")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let message = request
        .headers()
        .get("X-Message")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let payment_data = request
        .headers()
        .get("X-Payment")
        .ok_or(StatusCode::UNAUTHORIZED)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let signature = hex::decode(signature.trim_start_matches("0x"))
        .map_err(|_| StatusCode::BAD_REQUEST)
        .and_then(|bytes| Signature::try_from(bytes.as_slice()).map_err(|_| StatusCode::BAD_REQUEST))?;

    let message = hex::decode(message)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let payment_channel: PaymentChannel = serde_json::from_str(payment_data)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let signed_request = SignedRequest {
        message,
        signature,
        payment_channel: payment_channel.clone(),
        payment_amount: U256::one(),
    };

    match verify_and_update_channel(&state, &signed_request).await {
        Ok(_) => Ok(next.run(request).await),
        Err(e) => Err(StatusCode::from(e)),
    }
}

pub fn create_protected_router() -> Router {
    let state = ChannelState::new();
    
    Router::new()
        .route("/protected", post(protected_handler))
        .layer(axum::middleware::from_fn(move |req, next| {
            let state = state.clone();
            auth_middleware(state, req, next)
        }))
}

async fn protected_handler() -> Json<&'static str> {
    Json("Access granted!")
}

trait U256Ext {
    fn to_be_bytes_vec(&self) -> Vec<u8>;
}

impl U256Ext for U256 {
    fn to_be_bytes_vec(&self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes.to_vec()
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{self, HeaderMap, HeaderValue, Request},
    };
    use ethers::signers::{LocalWallet, Signer};
    use std::str::FromStr;
    use tower::util::ServiceExt;

    // Helper function to create a test wallet with a known private key
    fn create_test_wallet() -> LocalWallet {
        LocalWallet::from_str(
            "1234567890123456789012345678901234567890123456789012345678901234"
        ).unwrap()
    }

    // Helper function to create a test payment channel
    fn create_test_channel(wallet: &LocalWallet) -> PaymentChannel {
        PaymentChannel {
            sender: wallet.address(),
            recipient: Address::random(),
            balance: U256::from(1000),
            nonce: U256::from(1),
            expiration: U256::from(u64::MAX),
            channel_id: H256::random(),
        }
    }

    async fn create_signed_headers(
        wallet: &LocalWallet,
        channel: &PaymentChannel,
        request_data: &[u8],
    ) -> HeaderMap {
        let message = create_message(
            channel.channel_id,
            channel.balance,
            channel.nonce,
            request_data,
        );
        
        let signature = wallet.sign_message(&keccak256(&message)).await.unwrap();
        let payment_data = serde_json::to_string(&channel).unwrap();
        
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Signature",
            HeaderValue::from_str(&hex::encode(signature.to_vec())).unwrap(),
        );
        headers.insert(
            "X-Message",
            HeaderValue::from_str(&hex::encode(&message)).unwrap(),
        );
        headers.insert(
            "X-Payment",
            HeaderValue::from_str(&payment_data).unwrap(),
        );
        headers.insert(
            "X-Timestamp",
            HeaderValue::from_str(&SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .to_string()).unwrap(),
        );
        
        headers
    }

    async fn send_test_request(
        app: Router,
        headers: HeaderMap,
        request_data: &[u8],
    ) -> axum::response::Response {
        let request = Request::builder()
            .method(http::Method::POST)
            .uri("/protected")
            .body(Body::from(request_data.to_vec()))
            .unwrap();
        
        let request = {
            let (mut parts, body) = request.into_parts();
            parts.headers = headers;
            Request::from_parts(parts, body)
        };
        
        app.oneshot(request).await.unwrap()
    }

    #[tokio::test]
    async fn test_valid_request() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let channel = create_test_channel(&wallet);
        let request_data = b"test data";
        
        let headers = create_signed_headers(&wallet, &channel, request_data).await;
        let response = send_test_request(app, headers, request_data).await;
        
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_invalid_signature() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let mut channel = create_test_channel(&wallet);
        let request_data = b"test data";
        
        // Create headers with valid signature
        let mut headers = create_signed_headers(&wallet, &channel, request_data).await;
        
        // Modify channel data to invalidate signature
        channel.balance += U256::from(1);
        let payment_data = serde_json::to_string(&channel).unwrap();
        headers.insert(
            "X-Payment",
            HeaderValue::from_str(&payment_data).unwrap(),
        );
        
        let response = send_test_request(app, headers, request_data).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_headers() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let channel = create_test_channel(&wallet);
        let request_data = b"test data";
        
        for header_name in &["X-Signature", "X-Message", "X-Payment", "X-Timestamp"] {
            let mut headers = create_signed_headers(&wallet, &channel, request_data).await;
            headers.remove(*header_name);
            
            let response = send_test_request(app.clone(), headers, request_data).await;
            assert_eq!(
                response.status(), 
                StatusCode::UNAUTHORIZED,
                "Request missing {} should be unauthorized",
                header_name
            );
        }
    }

    #[tokio::test]
    async fn test_insufficient_balance() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let mut channel = create_test_channel(&wallet);
        let request_data = b"test data";
        
        // Set very low balance
        channel.balance = U256::zero();
        
        let headers = create_signed_headers(&wallet, &channel, request_data).await;
        let response = send_test_request(app, headers, request_data).await;
        
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let request_data = b"test data";
        
        let mut last_response = StatusCode::OK;
        
        for i in 0..120 {
            let mut channel = create_test_channel(&wallet);
            channel.nonce = U256::from(i + 1);
            
            let headers = create_signed_headers(&wallet, &channel, request_data).await;
            let response = send_test_request(app.clone(), headers, request_data).await;
            
            if i < 100 {
                assert_eq!(
                    response.status(),
                    StatusCode::OK,
                    "Request {} should succeed",
                    i
                );
            } else {
                assert_eq!(
                    response.status(),
                    StatusCode::TOO_MANY_REQUESTS,
                    "Request {} should be rate limited",
                    i
                );
            }
            
            last_response = response.status();
        }
    }

    #[tokio::test]
    async fn test_nonce_validation() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let channel = create_test_channel(&wallet);
        let request_data = b"test data";
        
        // First request should succeed
        let headers = create_signed_headers(&wallet, &channel, request_data).await;
        let response = send_test_request(app.clone(), headers, request_data).await;
        
        assert_eq!(response.status(), StatusCode::OK, "First request should succeed");
        
        // Same nonce should fail
        let headers = create_signed_headers(&wallet, &channel, request_data).await;
        let response = send_test_request(app.clone(), headers, request_data).await;
        
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Duplicate nonce should fail"
        );
        
        // Increasing nonce should succeed
        let mut new_channel = channel.clone();
        new_channel.nonce += U256::one();
        
        let headers = create_signed_headers(&wallet, &new_channel, request_data).await;
        let response = send_test_request(app, headers, request_data).await;
        
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Increased nonce should succeed"
        );
    }
}