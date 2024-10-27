use ethers::types::{Address, Signature, H256, U256};
use serde::{Deserialize, Serialize};

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
