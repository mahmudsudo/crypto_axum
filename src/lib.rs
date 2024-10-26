use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    routing::post,
    Json, Router,
};
use ethers::types::{Address, RecoveryMessage, Signature, H256, U256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;

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

        let (count, last_reset) = rate_limits.entry(sender).or_insert((0, SystemTime::now()));

        let last_reset_secs = last_reset.duration_since(UNIX_EPOCH).unwrap().as_secs();

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

pub fn create_message(channel_id: H256, amount: U256, nonce: U256, request_data: &[u8]) -> Vec<u8> {
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
    println!("\n=== verify_and_update_channel ===");
    println!("Payment amount: {}", request.payment_amount);
    println!("Channel balance: {}", request.payment_channel.balance);

    if request.payment_channel.balance < request.payment_amount {
        println!("Failed: Insufficient balance");
        return Err(AuthError::InsufficientBalance);
    }

    println!("Message length: {}", request.message.len());
    println!("Original message: 0x{}", hex::encode(&request.message));

    // Create a recovery message
    let recoverable = RecoveryMessage::Data(request.message.clone());

    let recovered_address = match request.signature.recover(recoverable) {
        Ok(addr) => addr,
        Err(e) => {
            println!("Signature recovery failed: {:?}", e);
            return Err(AuthError::InvalidSignature);
        }
    };

    println!("Recovered address: {:?}", recovered_address);
    println!("Expected sender: {:?}", request.payment_channel.sender);

    if recovered_address != request.payment_channel.sender {
        println!("Failed: Address mismatch");
        return Err(AuthError::InvalidSignature);
    }

    state
        .check_rate_limit(request.payment_channel.sender)
        .await?;

    let mut channels = state.channels.write().await;

    // Check if channel exists and validate nonce
    if let Some(existing_channel) = channels.get(&request.payment_channel.channel_id) {
        // Ensure new nonce is greater than existing nonce
        if request.payment_channel.nonce <= existing_channel.nonce {
            println!(
                "Failed: Invalid nonce - current: {}, received: {}",
                existing_channel.nonce, request.payment_channel.nonce
            );
            return Err(AuthError::InvalidChannel);
        }
    }

    // Update or insert the channel
    channels.insert(
        request.payment_channel.channel_id,
        request.payment_channel.clone(),
    );

    Ok(())
}

pub async fn auth_middleware(
    state: ChannelState,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check timestamp first
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

    // Get and validate all required headers
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

    // Parse signature
    let signature = hex::decode(signature.trim_start_matches("0x"))
        .map_err(|_| StatusCode::BAD_REQUEST)
        .and_then(|bytes| {
            Signature::try_from(bytes.as_slice()).map_err(|_| StatusCode::BAD_REQUEST)
        })?;

    // Parse message
    let message = hex::decode(message).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Parse payment channel data
    let payment_channel: PaymentChannel =
        serde_json::from_str(payment_data).map_err(|_| StatusCode::BAD_REQUEST)?;

    // Get request body
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, usize::MAX).await {
        Ok(bytes) => bytes,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };

    // Verify that the message matches what we expect
    let reconstructed_message = create_message(
        payment_channel.channel_id,
        payment_channel.balance,
        payment_channel.nonce,
        &body_bytes,
    );

    if message != reconstructed_message {
        return Err(StatusCode::BAD_REQUEST);
    }

    let payment_amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH in wei

    let signed_request = SignedRequest {
        message: message.clone(),
        signature,
        payment_channel: payment_channel.clone(),
        payment_amount,
    };

    match verify_and_update_channel(&state, &signed_request).await {
        Ok(_) => {
            let request = Request::from_parts(parts, Body::from(body_bytes));
            Ok(next.run(request).await)
        }
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
        LocalWallet::from_str("1234567890123456789012345678901234567890123456789012345678901234")
            .unwrap()
    }

    // Helper function to create a test payment channel
    fn create_test_channel(wallet: &LocalWallet) -> PaymentChannel {
        PaymentChannel {
            sender: wallet.address(),
            recipient: Address::random(),
            balance: U256::from(2_000_000_000_000_000_000u64), // 2 ETH in wei
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
        // Create the message
        let message = create_message(
            channel.channel_id,
            channel.balance,
            channel.nonce,
            request_data,
        );

        // Sign the message directly - wallet.sign_message already handles the Ethereum prefix
        let signature = wallet.sign_message(&message).await.unwrap();
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
        headers.insert("X-Payment", HeaderValue::from_str(&payment_data).unwrap());
        headers.insert(
            "X-Timestamp",
            HeaderValue::from_str(
                &SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string(),
            )
            .unwrap(),
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
        let channel = create_test_channel(&wallet);
        let request_data = b"test data";

        // Create the message and headers normally
        let mut headers = create_signed_headers(&wallet, &channel, request_data).await;

        // Replace the signature with an invalid one
        let invalid_sig = hex::encode([1u8; 65]); // Create an obviously invalid signature
        headers.insert("X-Signature", HeaderValue::from_str(&invalid_sig).unwrap());

        let response = send_test_request(app, headers, request_data).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_missing_headers() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let channel = create_test_channel(&wallet);
        let request_data = b"test data";

        // Test required auth headers
        let required_auth_headers = ["X-Signature", "X-Message", "X-Payment"];
        for header_name in &required_auth_headers {
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

        // Test timestamp header separately as it has different error behavior
        let mut headers = create_signed_headers(&wallet, &channel, request_data).await;
        headers.remove("X-Timestamp");

        let response = send_test_request(app.clone(), headers, request_data).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Request missing X-Timestamp should be bad request"
        );

        // Test malformed headers
        let mut headers = create_signed_headers(&wallet, &channel, request_data).await;
        headers.insert("X-Signature", HeaderValue::from_static("invalid-signature"));

        let response = send_test_request(app.clone(), headers, request_data).await;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Request with malformed signature should be bad request"
        );
    }

    #[tokio::test]
    async fn test_insufficient_balance() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let mut channel = create_test_channel(&wallet);
        let request_data = b"test data";

        // Set balance to 0.5 ETH in wei (5e17 wei)
        channel.balance = U256::from(500_000_000_000_000_000u64); // 0.5 ETH in wei

        // Create and sign the message with this balance
        let headers = create_signed_headers(&wallet, &channel, request_data).await;
        let response = send_test_request(app, headers, request_data).await;

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let request_data = b"test data";

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

            // Small delay to ensure stable rate limiting
            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn test_nonce_validation() {
        let app = create_protected_router();
        let wallet = create_test_wallet();
        let channel = create_test_channel(&wallet);
        let request_data = b"test data";

        println!("\n=== Starting first request (should succeed) ===");
        println!("Channel state: {:?}", channel);

        // First request should succeed
        let headers = create_signed_headers(&wallet, &channel, request_data).await;
        println!("Created headers:");
        for (name, value) in headers.iter() {
            println!("  {}: {:?}", name, value);
        }

        let response = send_test_request(app.clone(), headers, request_data).await;
        println!("First request response status: {}", response.status());
        println!("First request response headers: {:?}", response.headers());

        // Get status before moving the response
        let status = response.status();

        // Try to read response body for more info
        let body_bytes = match axum::body::to_bytes(response.into_body(), usize::MAX).await {
            Ok(bytes) => bytes,
            Err(e) => panic!("Failed to read response body: {}", e),
        };
        if !body_bytes.is_empty() {
            println!("Response body: {}", String::from_utf8_lossy(&body_bytes));
        }

        assert_eq!(status, StatusCode::OK, "First request should succeed");

        println!("\n=== Starting second request (should fail with duplicate nonce) ===");
        // Same nonce should fail
        let headers = create_signed_headers(&wallet, &channel, request_data).await;
        let response = send_test_request(app.clone(), headers, request_data).await;
        println!("Second request response status: {}", response.status());

        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "Duplicate nonce should fail"
        );

        println!("\n=== Starting third request (should succeed with increased nonce) ===");
        // Increasing nonce should succeed
        let mut new_channel = channel.clone();
        new_channel.nonce += U256::one();
        println!("New channel state: {:?}", new_channel);

        let headers = create_signed_headers(&wallet, &new_channel, request_data).await;
        let response = send_test_request(app, headers, request_data).await;
        println!("Third request response status: {}", response.status());

        assert_eq!(
            response.status(),
            StatusCode::OK,
            "Increased nonce should succeed"
        );
    }
}
