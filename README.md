# Axum Payment Channel Authentication

A Rust middleware for Axum that implements cryptographic authentication using payment channels. This library provides secure, efficient request authentication with built-in rate limiting and payment verification.

## Features

- 🔒 Cryptographic request authentication using ECDSA signatures
- 💸 Payment channel integration for per-request micropayments
- ⚡ Built-in rate limiting
- 🔄 Automatic nonce validation
- ⏰ Timestamp-based replay protection
- 🔋 Thread-safe state management

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
axum_signature = "0.1.0"
```

## Quick Start

```rust
use axum_signature::{create_protected_router, ChannelState};

#[tokio::main]
async fn main() {
    // Create a protected router with payment channel authentication
    let app = create_protected_router();
    
    // Start the server
    axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
```

## Making Authenticated Requests

Requests must include the following headers:

- `X-Signature`: ECDSA signature of the request message
- `X-Message`: Hex-encoded message bytes
- `X-Payment`: Payment channel state JSON
- `X-Timestamp`: Current Unix timestamp

Example request:

```rust
let headers = {
    "X-Signature": "0x...", // ECDSA signature
    "X-Message": "0x...",   // Hex-encoded message
    "X-Payment": {          // Payment channel state
        "sender": "0x...",
        "recipient": "0x...",
        "balance": "1000",
        "nonce": "1",
        "expiration": "...",
        "channel_id": "0x..."
    },
    "X-Timestamp": "1635329..." // Current Unix timestamp
}
```

## Payment Channel Structure

```rust
pub struct PaymentChannel {
    pub sender: Address,      // Ethereum address of the sender
    pub recipient: Address,   // Ethereum address of the recipient
    pub balance: U256,        // Current channel balance
    pub nonce: U256,         // Current nonce (increments with each payment)
    pub expiration: U256,     // Channel expiration timestamp
    pub channel_id: H256,     // Unique channel identifier
}
```

## Configuration

The middleware can be configured with custom rate limits and timeouts:

```rust
const RATE_LIMIT: u64 = 100;           // Requests per window
const RATE_LIMIT_WINDOW: u64 = 60;     // Window size in seconds
const TIMESTAMP_EXPIRY: u64 = 300;     // Request timestamp validity in seconds
```

## Security Considerations

- All signatures must be valid ECDSA signatures from the payment channel sender
- Nonces must strictly increase to prevent replay attacks
- Timestamps must be within 5 minutes of current time
- Rate limiting is applied per sender address
- Channel balance must be sufficient for the payment amount

## Running Tests

```bash
cargo test
```

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Examples

See the `/examples` directory for complete usage examples:

- Basic authentication setup
- Custom rate limiting
- Payment channel management
- Error handling
- Testing patterns

## API Documentation

For detailed API documentation, run:

```bash
cargo doc --open
```