use crate::types::{AuthError, PaymentChannel, network::Network};
use ethers::types::{Address, Signature, H256, U256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct ChannelState {
    pub(crate) channels: Arc<RwLock<HashMap<H256, PaymentChannel>>>,
    rate_limiter: Arc<RwLock<HashMap<Address, (u64, SystemTime)>>>,
    network: Arc<dyn Network>,
}

impl ChannelState {
    pub fn new(network: impl Network) -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
            network: Arc::new(network),
        }
    }

    pub(crate) async fn check_rate_limit(&self, sender: Address) -> Result<(), AuthError> {
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

    pub async fn verify_signature(&self, signature: &Signature, message: &[u8]) -> Result<Address, AuthError> {
        self.network.verify_signature(signature, message).await
    }

    pub async fn validate_channel(&self, channel_id: H256, balance: U256) -> Result<(), AuthError> {
        self.network.validate_channel(channel_id, balance).await
    }
}
