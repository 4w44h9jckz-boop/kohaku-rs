use std::ops::Range;

use alloy::primitives::{Address, U256};
use serde::{Deserialize, Serialize};

use crate::field::Field;

/// A set of events emitted by a pool within a given block range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The half-open block range these events cover.
    pub range: Range<u64>,
    /// The events the pool emitted within `range`.
    ///
    /// Deposits must be contiguous and in ascending order by leaf index.
    pub events: Vec<SyncEvent>,
}

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
