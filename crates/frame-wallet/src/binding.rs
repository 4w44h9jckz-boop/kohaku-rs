//! ERC-7677's paymaster web service, bound to frame transactions, as `exp-frames` experiment 28
//! binds it (`binding.ts`, `paymaster.ts`).
//!
//! | ERC-7677 | Frames binding |
//! |---|---|
//! | `entryPoint` parameter | `0x00...aa`, the frames entry point, which says "frames" |
//! | user-operation parameter | the unsigned frame transaction, as [`RpcFrameTx`] |
//! | `paymaster` | the pay frame's target |
//! | `paymasterData` | the pay frame's data |
//! | `paymasterVerificationGasLimit` | the pay frame's execution budget |
//! | `paymasterPostOpGasLimit` | a `DEFAULT` frame after the calls, aimed at the paymaster; 0 means none |
//! | `sponsor`, `isFinal` | as in ERC-7677 |
//! | *(none)* | `paymasterStateGasLimit`: the pay frame's EIP-8037 state budget |
//! | *(none)* | `paymasterSignatures`: the payer's signature entries, after the sender's |
//!
//! There is no agreed JSON for a frame transaction (`exp-frames` experiment 22 found four
//! clients serving four), so [`RpcFrameTx`] is this binding's own, the same on both sides.

use alloy::primitives::{Address, Bytes, U64, U256};
use kohaku_frame_accounts::sponsor::Sponsor;
use kohaku_frame_kit::{
    Fees, Frame, FrameLimits, FrameSignature, FrameTx,
    constants::{approve, mode},
};
use serde::{Deserialize, Serialize};

/// One frame, as the binding carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcFrame {
    pub mode: U64,
    pub flags: U64,
    pub target: Option<Address>,
    pub execution_gas_limit: U64,
    pub state_gas_limit: U64,
    pub value: U256,
    pub data: Bytes,
}

/// One signature entry, as the binding carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcSignature {
    pub scheme: U64,
    pub signer: Option<Address>,
    pub msg: Bytes,
    pub signature: Bytes,
}

/// An unsigned frame transaction on its way to a paymaster service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcFrameTx {
    pub chain_id: U64,
    pub nonce_keys: Vec<U256>,
    pub nonce_seq: U64,
    pub sender: Address,
    pub frames: Vec<RpcFrame>,
    pub signatures: Vec<RpcSignature>,
    pub max_priority_fee_per_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_fee_per_blob_gas: U256,
}

impl From<&FrameTx> for RpcFrameTx {
    fn from(tx: &FrameTx) -> Self {
        Self {
            chain_id: U64::from(tx.chain_id),
            nonce_keys: tx.nonce_keys.clone(),
            nonce_seq: U64::from(tx.nonce_seq),
            sender: tx.sender,
            frames: tx
                .frames
                .iter()
                .map(|f| RpcFrame {
                    mode: U64::from(f.mode),
                    flags: U64::from(f.flags),
                    target: f.target,
                    execution_gas_limit: U64::from(f.limits.execution),
                    state_gas_limit: U64::from(f.limits.state),
                    value: f.value,
                    data: f.data.clone(),
                })
                .collect(),
            signatures: tx.signatures.iter().map(RpcSignature::from).collect(),
            max_priority_fee_per_gas: U256::from(tx.fees.max_priority_fee_per_gas),
            max_fee_per_gas: U256::from(tx.fees.max_fee_per_gas),
            max_fee_per_blob_gas: U256::from(tx.fees.max_fee_per_blob_gas),
        }
    }
}

impl From<&FrameSignature> for RpcSignature {
    fn from(s: &FrameSignature) -> Self {
        Self {
            scheme: U64::from(s.scheme),
            signer: s.signer,
            msg: s.msg.clone(),
            signature: s.signature.clone(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{0} does not fit its field")]
pub struct OutOfRange(&'static str);

impl TryFrom<&RpcSignature> for FrameSignature {
    type Error = OutOfRange;

    fn try_from(s: &RpcSignature) -> Result<Self, OutOfRange> {
        Ok(Self {
            scheme: u8::try_from(s.scheme).map_err(|_| OutOfRange("scheme"))?,
            signer: s.signer,
            msg: s.msg.clone(),
            signature: s.signature.clone(),
        })
    }
}

impl TryFrom<&RpcFrameTx> for FrameTx {
    type Error = OutOfRange;

    fn try_from(j: &RpcFrameTx) -> Result<Self, OutOfRange> {
        let fee = |v: U256, what| u128::try_from(v).map_err(|_| OutOfRange(what));
        Ok(Self {
            chain_id: j.chain_id.to(),
            nonce_keys: j.nonce_keys.clone(),
            nonce_seq: j.nonce_seq.to(),
            sender: j.sender,
            frames: j
                .frames
                .iter()
                .map(|f| {
                    Ok(Frame {
                        mode: u8::try_from(f.mode).map_err(|_| OutOfRange("mode"))?,
                        flags: u8::try_from(f.flags).map_err(|_| OutOfRange("flags"))?,
                        target: f.target,
                        limits: FrameLimits {
                            execution: f.execution_gas_limit.to(),
                            state: f.state_gas_limit.to(),
                        },
                        value: f.value,
                        data: f.data.clone(),
                    })
                })
                .collect::<Result<_, OutOfRange>>()?,
            signatures: j
                .signatures
                .iter()
                .map(FrameSignature::try_from)
                .collect::<Result<_, _>>()?,
            fees: Fees {
                max_priority_fee_per_gas: fee(j.max_priority_fee_per_gas, "maxPriorityFeePerGas")?,
                max_fee_per_gas: fee(j.max_fee_per_gas, "maxFeePerGas")?,
                max_fee_per_blob_gas: fee(j.max_fee_per_blob_gas, "maxFeePerBlobGas")?,
            },
            blob_versioned_hashes: Vec::new(),
        })
    }
}

/// ERC-7677's result, its v0.7 fields read as frame fields, plus the binding's two.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymasterResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sponsor: Option<serde_json::Value>,
    pub paymaster: Address,
    pub paymaster_data: Bytes,
    pub paymaster_verification_gas_limit: U64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paymaster_post_op_gas_limit: Option<U64>,
    /// Not in ERC-7677: the pay frame's EIP-8037 state budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paymaster_state_gas_limit: Option<U64>,
    /// Not in ERC-7677: the payer's signature entries, which follow the sender's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paymaster_signatures: Option<Vec<RpcSignature>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_final: Option<bool>,
}

/// A sponsor whose frames a paymaster service quoted. Before the first quote it has no frames,
/// which still makes the account approve execution only.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QuotedSponsor {
    payment: Vec<Frame>,
    post: Vec<Frame>,
    signatures: Vec<FrameSignature>,
}

impl QuotedSponsor {
    /// The pay frame, the post-op and the payer's entries from the service's answer.
    pub fn from_result(p: &PaymasterResult) -> Result<Self, OutOfRange> {
        let pay = Frame::verify(approve::PAYMENT, Some(p.paymaster))
            .with_execution(p.paymaster_verification_gas_limit.to())
            .with_state(p.paymaster_state_gas_limit.map_or(0, |g| g.to()))
            .with_data(p.paymaster_data.clone());
        let post_op: u64 = p.paymaster_post_op_gas_limit.map_or(0, |g| g.to());
        let post = if post_op > 0 {
            vec![Frame::entry_point(Some(p.paymaster)).with_execution(post_op)]
        } else {
            Vec::new()
        };
        let signatures = p
            .paymaster_signatures
            .iter()
            .flatten()
            .map(FrameSignature::try_from)
            .collect::<Result<_, _>>()?;
        Ok(Self {
            payment: vec![pay],
            post,
            signatures,
        })
    }

    /// The sponsor a mined transaction's payer frames describe: the `VERIFY(PAYMENT)` frame to
    /// another account, a `DEFAULT` frame to the same account after the calls, and every
    /// signature entry after the first.
    #[must_use]
    pub fn from_mined(tx: &FrameTx) -> Option<Self> {
        let pay = tx.frames.iter().find(|f| {
            f.mode == mode::VERIFY && f.flags & approve::PAYMENT != 0 && f.target.is_some()
        })?;
        let post = tx
            .frames
            .iter()
            .filter(|f| f.mode == mode::DEFAULT && f.target == pay.target)
            .cloned()
            .collect();
        Some(Self {
            payment: vec![pay.clone()],
            post,
            signatures: tx.signatures.iter().skip(1).cloned().collect(),
        })
    }
}

impl Sponsor for QuotedSponsor {
    fn payment_frames(&self) -> Vec<Frame> {
        self.payment.clone()
    }

    fn post_frames(&self) -> Vec<Frame> {
        self.post.clone()
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        self.signatures.clone()
    }
}
