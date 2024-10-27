use crate::types::{AuthError, PaymentChannel};
use ethers::addressbook::Address;
use ethers::prelude::H256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct ChannelState {
    pub(crate) channels: Arc<RwLock<HashMap<H256, PaymentChannel>>>,
    rate_limiter: Arc<RwLock<HashMap<Address, (u64, SystemTime)>>>,
}

impl ChannelState {
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
            rate_limiter: Arc::new(RwLock::new(HashMap::new())),
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
}
