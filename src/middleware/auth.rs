use crate::{
    state::channel::ChannelState,
    types::{AuthError, PaymentChannel, SignedRequest},
    utils::crypto::create_message,
};
use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use ethers::{
    prelude::Signature,
    types::{RecoveryMessage, U256},
};
use std::time::{SystemTime, UNIX_EPOCH};

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
