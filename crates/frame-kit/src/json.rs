//! The JSON shapes the ethrex Hegota testnet serves for frame transactions.

use alloy::primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Serialize};

use crate::tx::{Fees, Frame, FrameLimits, FrameSignature, FrameTx};

/// `eth_getTransactionByHash` for a type-0x06 transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameTxJson {
    pub hash: B256,
    pub chain_id: U256,
    pub nonce_keys: Vec<U256>,
    pub nonce_seq: U256,
    pub sender: Address,
    pub frames: Vec<FrameJson>,
    pub signatures: Vec<FrameSignatureJson>,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_fee_per_blob_gas: U256,
    pub blob_versioned_hashes: Vec<B256>,
    #[serde(default)]
    pub block_number: Option<U256>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameJson {
    pub mode: U256,
    pub flags: U256,
    pub to: Option<Address>,
    pub gas_limit: U256,
    pub state_gas_limit: U256,
    pub value: U256,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameSignatureJson {
    pub scheme: U256,
    pub signer: Option<Address>,
    pub msg: Bytes,
    pub signature: Bytes,
}

/// A log as a frame receipt carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogJson {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameReceiptJson {
    pub status: U256,
    pub gas_used: U256,
    pub state_gas_used: U256,
    pub logs: Vec<LogJson>,
}

/// `eth_getTransactionReceipt` for a type-0x06 transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameTxReceiptJson {
    pub transaction_hash: B256,
    pub block_hash: B256,
    pub block_number: U256,
    pub transaction_index: U256,
    pub status: U256,
    pub from: Address,
    /// Who `APPROVE(PAYMENT)` charged.
    pub payer: Address,
    pub gas_used: U256,
    pub cumulative_gas_used: U256,
    pub effective_gas_price: U256,
    pub frame_receipts: Vec<FrameReceiptJson>,
    pub logs: Vec<LogJson>,
}

/// `ethrex_simulateFrameTransaction`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulateResult {
    /// Every frame-specific admission gate passed: necessary, not sufficient, for the mempool.
    pub valid: bool,
    pub prefix_shape: Option<String>,
    pub payer: Option<Address>,
    pub max_cost: U256,
    pub violation: Option<String>,
    pub gas_used: Option<U256>,
    pub frames: Option<Vec<SimulatedFrame>>,
    /// `"success"` or `"reverted"`: a valid transaction can still revert a frame.
    pub execution_status: Option<String>,
    pub execution_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedFrame {
    pub gas_used: U256,
    pub succeeded: bool,
}

#[derive(Debug, thiserror::Error)]
#[error("{0} does not fit its field")]
pub struct OutOfRange(&'static str);

fn narrow<T: TryFrom<U256>>(v: U256, what: &'static str) -> Result<T, OutOfRange> {
    T::try_from(v).map_err(|_| OutOfRange(what))
}

impl TryFrom<&FrameTxJson> for FrameTx {
    type Error = OutOfRange;

    /// Rebuild the transaction from the node's JSON. Check `tx.hash() == json.hash` before
    /// trusting it: the JSON is the node's rendering, the hash is the commitment.
    fn try_from(j: &FrameTxJson) -> Result<Self, OutOfRange> {
        Ok(Self {
            chain_id: narrow(j.chain_id, "chainId")?,
            nonce_keys: j.nonce_keys.clone(),
            nonce_seq: narrow(j.nonce_seq, "nonceSeq")?,
            sender: j.sender,
            frames: j
                .frames
                .iter()
                .map(|f| {
                    Ok(Frame {
                        mode: narrow(f.mode, "mode")?,
                        flags: narrow(f.flags, "flags")?,
                        target: f.to,
                        limits: FrameLimits {
                            execution: narrow(f.gas_limit, "gasLimit")?,
                            state: narrow(f.state_gas_limit, "stateGasLimit")?,
                        },
                        value: f.value,
                        data: f.data.clone(),
                    })
                })
                .collect::<Result<_, OutOfRange>>()?,
            signatures: j
                .signatures
                .iter()
                .map(|s| {
                    Ok(FrameSignature {
                        scheme: narrow(s.scheme, "scheme")?,
                        signer: s.signer,
                        msg: s.msg.clone(),
                        signature: s.signature.clone(),
                    })
                })
                .collect::<Result<_, OutOfRange>>()?,
            fees: Fees {
                max_priority_fee_per_gas: narrow(
                    j.max_priority_fee_per_gas,
                    "maxPriorityFeePerGas",
                )?,
                max_fee_per_gas: narrow(j.max_fee_per_gas, "maxFeePerGas")?,
                max_fee_per_blob_gas: narrow(j.max_fee_per_blob_gas, "maxFeePerBlobGas")?,
            },
            blob_versioned_hashes: j.blob_versioned_hashes.clone(),
        })
    }
}
