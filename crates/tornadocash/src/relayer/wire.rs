use alloy::primitives::{Address, B256, Bytes, TxHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobId(pub String);

/// A `v1/tornadoWithdraw` request to the relayer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub contract: Address,
    pub proof: Bytes,
    /// (`root`, `nullifier_hash`, `recipient`, `relayer`, `fee`, `refund`).
    ///
    /// Uses B256 for `fee` and `refund` so they are serialized as 32-byte hex strings.
    pub args: (B256, B256, Address, Address, B256, B256),
}

/// The relayer's response to a `v1/tornadoWithdraw` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawResponse {
    pub id: JobId,
}

/// The relayer's response to a `v1/jobs/{id}` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobResponse {
    pub status: JobStatus,
    pub tx_hash: Option<TxHash>,
    pub confirmations: Option<u32>,
    pub failed_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobStatus {
    Queued,
    Accepted,
    Sent,
    Mined,
    Resubmitted,
    Confirmed,
    Failed,
}
