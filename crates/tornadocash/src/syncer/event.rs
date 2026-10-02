use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use crate::field::Field;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncEvent {
    Deposit(Deposit),
    Withdrawal(Withdrawal),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deposit {
    pub commitment: Field,
    pub leaf_index: u32,
    pub block_number: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Withdrawal {
    pub to: Address,
    pub nullifier_hash: Field,
    pub relayer: Address,
    pub fee: U256,
    pub block_number: u64,
}
