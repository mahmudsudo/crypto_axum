use crate::handlers::protected::protected_handler;
use crate::middleware::auth::auth_middleware;
use crate::state::channel::ChannelState;
use axum::{routing::post, Router};

pub mod handlers;
pub mod middleware;
pub mod state;
pub mod types;
pub mod utils;

pub fn create_protected_router() -> Router {
    let state = ChannelState::new();

    Router::new()
        .route("/protected", post(protected_handler))
        .layer(axum::middleware::from_fn(move |req, next| {
            let state = state.clone();
            auth_middleware(state, req, next)
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PaymentChannel;
    use crate::utils::crypto::create_message;
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
