//! Gas accounting: the "Gas Accounting" section of EIP-8141 plus the EIP-8250 nonce calldata,
//! as ethrex implements it in `FrameTransaction::{mandatory_gas, data_cost, max_gas, max_cost}`.

use alloy::primitives::U256;

use crate::{
    constants::{
        FRAME_TX_INTRINSIC_COST, FRAME_TX_PER_FRAME_COST, GAS_PER_BLOB, STANDARD_TOKEN_COST,
        TOTAL_COST_FLOOR_PER_TOKEN, TX_MAX_GAS_LIMIT, TX_VALUE_COST, signature_gas,
    },
    tx::FrameTx,
};

#[derive(Debug, thiserror::Error)]
#[error("unknown signature scheme {0}")]
pub struct UnknownScheme(pub u8);

/// 4 gas per zero byte, 16 per non-zero byte.
#[must_use]
pub fn calldata_cost(data: &[u8]) -> u64 {
    data.iter()
        .map(|&b| {
            if b == 0 {
                STANDARD_TOKEN_COST
            } else {
                4 * STANDARD_TOKEN_COST
            }
        })
        .sum()
}

/// The byte strings the data cost is charged over: every frame's data, every signature's signer,
/// message and signature, and the nonce bytes.
fn data_fields(tx: &FrameTx) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = tx.frames.iter().map(|f| f.data.to_vec()).collect();
    for s in &tx.signatures {
        out.push(s.signer.map(|a| a.to_vec()).unwrap_or_default());
        out.push(s.msg.to_vec());
        out.push(s.signature.to_vec());
    }
    out.push(tx.nonce_calldata());
    out
}

pub fn signature_verification_gas(tx: &FrameTx) -> Result<u64, UnknownScheme> {
    tx.signatures
        .iter()
        .map(|s| signature_gas(s.scheme).ok_or(UnknownScheme(s.scheme)))
        .sum()
}

/// `TX_VALUE_COST` per frame moving value to an explicit target other than the sender.
#[must_use]
pub fn value_transfer_gas(tx: &FrameTx) -> u64 {
    let moving = tx
        .frames
        .iter()
        .filter(|f| !f.value.is_zero() && f.target.is_some_and(|t| t != tx.sender))
        .count() as u64;
    moving * TX_VALUE_COST
}

/// Costs charged in full on both sides of the calldata-floor comparison.
pub fn mandatory_gas(tx: &FrameTx) -> Result<u64, UnknownScheme> {
    Ok(FRAME_TX_INTRINSIC_COST
        + tx.frames.len() as u64 * FRAME_TX_PER_FRAME_COST
        + signature_verification_gas(tx)?
        + value_transfer_gas(tx))
}

#[must_use]
pub fn data_cost(tx: &FrameTx) -> u64 {
    data_fields(tx).iter().map(|d| calldata_cost(d)).sum()
}

/// `frame_tx_intrinsic_gas`: charged before any frame runs, outside the frames' budgets.
pub fn intrinsic_gas(tx: &FrameTx) -> Result<u64, UnknownScheme> {
    Ok(mandatory_gas(tx)? + data_cost(tx))
}

/// `calldata_floor_gas`: the mandatory costs plus 16 gas per token, 4 tokens per byte.
pub fn calldata_floor_gas(tx: &FrameTx) -> Result<u64, UnknownScheme> {
    let bytes: u64 = data_fields(tx).iter().map(|d| d.len() as u64).sum();
    Ok(mandatory_gas(tx)? + bytes * STANDARD_TOKEN_COST * TOTAL_COST_FLOOR_PER_TOKEN)
}

#[must_use]
pub fn total_execution_limit(tx: &FrameTx) -> u64 {
    tx.frames.iter().map(|f| f.limits.execution).sum()
}

#[must_use]
pub fn total_state_limit(tx: &FrameTx) -> u64 {
    tx.frames.iter().map(|f| f.limits.state).sum()
}

/// `max_gas`: what `max_cost` is charged over.
pub fn max_gas(tx: &FrameTx) -> Result<u64, UnknownScheme> {
    let standard = intrinsic_gas(tx)? + total_execution_limit(tx) + total_state_limit(tx);
    let floor = calldata_floor_gas(tx)? + total_state_limit(tx);
    Ok(standard.max(floor))
}

/// `TXPARAM(0x06)`: what `APPROVE(PAYMENT)` escrows from the payer.
pub fn max_cost(tx: &FrameTx, blob_base_fee: u128) -> Result<U256, UnknownScheme> {
    let blobs = U256::from(tx.blob_versioned_hashes.len() as u64 * GAS_PER_BLOB);
    Ok(
        U256::from(max_gas(tx)?) * U256::from(tx.fees.max_fee_per_gas)
            + blobs * U256::from(blob_base_fee),
    )
}

/// What EIP-7825's cap applies to: intrinsic and execution budgets, state gas excluded.
pub fn execution_reservation(tx: &FrameTx) -> Result<u64, UnknownScheme> {
    Ok((intrinsic_gas(tx)? + total_execution_limit(tx)).max(calldata_floor_gas(tx)?))
}

pub fn fits_tx_gas_cap(tx: &FrameTx) -> Result<bool, UnknownScheme> {
    Ok(execution_reservation(tx)? <= TX_MAX_GAS_LIMIT)
}

/// One frame's gas, as its receipt reports it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameGasUsed {
    pub execution: u64,
    pub state: u64,
}

/// Transaction `gas_used` from the per-frame receipts, per "Transaction settlement". `refund` is
/// the EIP-3529 refund counter, which the RPC does not expose: zero unless storage is cleared.
pub fn settled_gas_used(
    tx: &FrameTx,
    frames: &[FrameGasUsed],
    refund: u64,
) -> Result<u64, UnknownScheme> {
    let execution: u64 = frames.iter().map(|f| f.execution).sum();
    let state: u64 = frames.iter().map(|f| f.state).sum();
    let before_refund = intrinsic_gas(tx)? + execution + state;
    let applied = refund.min(before_refund / 5);
    let execution_part = before_refund - applied - state;
    Ok(execution_part.max(calldata_floor_gas(tx)?) + state)
}
