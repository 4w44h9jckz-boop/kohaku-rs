//! Submitting and observing frame transactions over JSON-RPC.
//!
//! alloy's typed transaction and receipt models do not know type 0x06, so these go through
//! `raw_request` and the shapes in [`crate::json`].

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    providers::Provider,
    transports::TransportError,
};

use crate::{
    constants::NONCE_MANAGER,
    json::{FrameTxJson, FrameTxReceiptJson, SimulateResult},
    tx::{Fees, FrameTx},
};

pub const HEGOTA_RPC_URL: &str = "https://rpc1.privacy.ethrex.xyz";
pub const HEGOTA_CHAIN_ID: u64 = 8141;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error("node returned hash {got}, expected keccak256(raw) = {expected}")]
    HashMismatch { got: B256, expected: B256 },
    #[error("nonce keys sit at different sequences: {0:?}")]
    SplitSequence(Vec<U256>),
    #[error("sequence {0} does not fit in u64")]
    SequenceRange(U256),
    #[error("no receipt for {0} after {1:?}")]
    Timeout(B256, Duration),
}

/// `NONCE_MANAGER` storage slot for a non-zero key: `keccak256(pad32(sender) || uint256(key))`.
#[must_use]
pub fn keyed_nonce_slot(sender: Address, key: U256) -> B256 {
    let mut buf = [0u8; 64];
    buf[12..32].copy_from_slice(sender.as_slice());
    buf[32..].copy_from_slice(&key.to_be_bytes::<32>());
    keccak256(buf)
}

/// The current `nonce_seq` for a key set. Every key must sit at the same sequence; key 0 is the
/// account nonce.
pub async fn nonce_seq<P: Provider>(
    provider: &P,
    sender: Address,
    nonce_keys: &[U256],
) -> Result<u64, RpcError> {
    let mut seqs = Vec::with_capacity(nonce_keys.len());
    for key in nonce_keys {
        let seq = if key.is_zero() {
            U256::from(provider.get_transaction_count(sender).await?)
        } else {
            provider
                .get_storage_at(NONCE_MANAGER, keyed_nonce_slot(sender, *key).into())
                .await?
        };
        seqs.push(seq);
    }
    let first = seqs.first().copied().unwrap_or_default();
    if seqs.iter().any(|s| *s != first) {
        return Err(RpcError::SplitSequence(seqs));
    }
    u64::try_from(first).map_err(|_| RpcError::SequenceRange(first))
}

/// Twice the base fee plus `tip`, as the ethrex reference submitters do.
pub async fn suggest_fees<P: Provider>(provider: &P, tip: u128) -> Result<Fees, RpcError> {
    let base = u128::from(
        provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?
            .and_then(|b| b.header.base_fee_per_gas)
            .unwrap_or_default(),
    );
    Ok(Fees {
        max_priority_fee_per_gas: tip,
        max_fee_per_gas: base * 2 + tip,
        max_fee_per_blob_gas: 0,
    })
}

/// `ethrex_simulateFrameTransaction`: the mempool's frame-specific gates, then execution.
pub async fn simulate<P: Provider>(
    provider: &P,
    tx: &FrameTx,
    block: &str,
) -> Result<SimulateResult, RpcError> {
    Ok(provider
        .raw_request(
            "ethrex_simulateFrameTransaction".into(),
            (tx.encode(), block.to_owned()),
        )
        .await?)
}

/// `eth_sendRawTransaction`, checking that the node hashed what was sent.
pub async fn send<P: Provider>(provider: &P, tx: &FrameTx) -> Result<B256, RpcError> {
    let got: B256 = provider
        .raw_request("eth_sendRawTransaction".into(), (tx.encode(),))
        .await?;
    let expected = tx.hash();
    if got != expected {
        return Err(RpcError::HashMismatch { got, expected });
    }
    Ok(got)
}

pub async fn transaction<P: Provider>(
    provider: &P,
    hash: B256,
) -> Result<Option<FrameTxJson>, RpcError> {
    Ok(provider
        .raw_request("eth_getTransactionByHash".into(), (hash,))
        .await?)
}

pub async fn receipt<P: Provider>(
    provider: &P,
    hash: B256,
) -> Result<Option<FrameTxReceiptJson>, RpcError> {
    Ok(provider
        .raw_request("eth_getTransactionReceipt".into(), (hash,))
        .await?)
}

/// Poll for the receipt every `poll` until `timeout`.
pub async fn wait_for_receipt<P: Provider>(
    provider: &P,
    hash: B256,
    timeout: Duration,
    poll: Duration,
) -> Result<FrameTxReceiptJson, RpcError> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(r) = receipt(provider, hash).await? {
            return Ok(r);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(RpcError::Timeout(hash, timeout));
        }
        tokio::time::sleep(poll).await;
    }
}

/// What [`execute`] saw: the node's simulation, then the mined receipt.
#[derive(Debug, Clone)]
pub struct Executed {
    pub simulation: SimulateResult,
    pub hash: B256,
    pub receipt: FrameTxReceiptJson,
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error("the node would not admit it: {0}")]
    Invalid(String),
    #[error("a frame reverts in simulation: {0}")]
    Reverts(String),
}

/// Simulate, refuse what the node would not admit, send, and wait for the receipt.
///
/// A valid transaction can still revert a frame. With `require_success`, one that reverts in
/// simulation is not sent; without it, it is sent anyway, which is what an experiment about
/// reverting frames wants.
pub async fn execute<P: Provider>(
    provider: &P,
    tx: &FrameTx,
    require_success: bool,
) -> Result<Executed, ExecuteError> {
    let simulation = simulate(provider, tx, "latest").await?;
    if !simulation.valid {
        return Err(ExecuteError::Invalid(
            simulation.violation.clone().unwrap_or_default(),
        ));
    }
    if require_success && simulation.execution_status.as_deref() != Some("success") {
        return Err(ExecuteError::Reverts(
            simulation.execution_error.clone().unwrap_or_default(),
        ));
    }
    let hash = send(provider, tx).await?;
    let receipt = wait_for_receipt(
        provider,
        hash,
        Duration::from_mins(2),
        Duration::from_secs(2),
    )
    .await?;
    Ok(Executed {
        simulation,
        hash,
        receipt,
    })
}
