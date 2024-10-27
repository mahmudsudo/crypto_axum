use ethers::types::{H256, U256};

pub trait U256Ext {
    fn to_be_bytes_vec(&self) -> Vec<u8>;
}

impl U256Ext for U256 {
    fn to_be_bytes_vec(&self) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        self.to_big_endian(&mut bytes);
        bytes.to_vec()
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
