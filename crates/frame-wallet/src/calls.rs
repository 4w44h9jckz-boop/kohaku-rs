//! EIP-5792's batch as one frame transaction, as `exp-frames` experiment 28's wallet lays it out:
//!
//! ```text
//! self-paid   [VERIFY sender, scope 3] [SENDER call 0] ... [SENDER call n-1]
//! sponsored   [VERIFY sender, scope 2] [VERIFY payer, scope 1] [SENDER call 0] ... [post-op]
//! ```
//!
//! With `atomicRequired`, every call frame but the last carries the atomic-batch flag, so the
//! calls commit or roll back together. Without it the calls are independent frames of one
//! transaction, and some may persist while others fail.

use std::collections::BTreeMap;

use alloy::primitives::{Address, Bytes, U64, U256};
use kohaku_frame_accounts::{
    account::FrameAccount,
    builder::{BuildError, Envelope, TxPlan},
    sponsor::Sponsor,
};
use kohaku_frame_kit::{
    Frame, FrameTx,
    constants::{NEW_ACCOUNT_STATE_GAS, STORAGE_SET_STATE_GAS, frame_status, mode},
};
use serde::{Deserialize, Serialize};

use crate::error::ProviderError;

/// Execution budget a call frame gets for the estimation run.
pub const DRAFT_EXECUTION: u64 = 400_000;
/// State budget a call frame gets, in the estimation run and after it: two fresh slots and one
/// new account.
///
/// ethrex's simulation reports execution gas per frame but not state gas, and its total is net
/// of refunds, so a wallet cannot attribute state gas to a frame (experiment 28, observation 6).
/// A call that needs more than this fails and burns its whole execution budget.
pub const STATE_PER_CALL: u64 = 2 * STORAGE_SET_STATE_GAS + NEW_ACCOUNT_STATE_GAS;
/// The capabilities this wallet understands in `wallet_sendCalls`.
pub const KNOWN_CAPABILITIES: &[&str] = &["paymasterService"];

/// A capability as a request names it: only whether it may be ignored matters here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFlag {
    #[serde(default)]
    pub optional: bool,
}

/// One call of a `wallet_sendCalls` batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Call {
    #[serde(default)]
    pub to: Option<Address>,
    #[serde(default)]
    pub data: Option<Bytes>,
    #[serde(default)]
    pub value: Option<U256>,
    #[serde(default)]
    pub capabilities: BTreeMap<String, CapabilityFlag>,
}

/// ERC-7677's `paymasterService` capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymasterService {
    pub url: String,
    #[serde(default)]
    pub context: Option<serde_json::Value>,
    #[serde(default)]
    pub optional: bool,
}

/// `wallet_sendCalls`'s parameter, EIP-5792 version 2.0.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendCallsParams {
    pub version: String,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub from: Option<Address>,
    pub chain_id: U64,
    pub atomic_required: bool,
    pub calls: Vec<Call>,
    #[serde(default)]
    pub capabilities: BTreeMap<String, serde_json::Value>,
}

impl SendCallsParams {
    /// Refuse what this wallet cannot honour, before anything is built, with EIP-5792's codes.
    pub fn check(&self, chain_id: u64, account: Address) -> Result<(), ProviderError> {
        if self.version != "2.0.0" {
            return Err(ProviderError::invalid_params(format!(
                "unsupported version {}",
                self.version
            )));
        }
        if self.chain_id.to::<u64>() != chain_id {
            return Err(ProviderError::new(
                5710,
                format!("unsupported chain id {}", self.chain_id),
            ));
        }
        if self.from.is_some_and(|f| f != account) {
            return Err(ProviderError::new(
                4100,
                format!(
                    "{} is not this wallet's account",
                    self.from.unwrap_or_default()
                ),
            ));
        }
        for (name, cap) in &self.capabilities {
            let optional = cap
                .get("optional")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            if !KNOWN_CAPABILITIES.contains(&name.as_str()) && !optional {
                return Err(ProviderError::new(
                    5700,
                    format!("unsupported non-optional capability {name}"),
                ));
            }
        }
        for call in &self.calls {
            // A SENDER frame calls a target; no target means the sender, not a creation.
            if call.to.is_none() {
                return Err(ProviderError::invalid_params(
                    "a call without `to` (a deployment) has no frame equivalent; send it through a deployer",
                ));
            }
            if let Some((name, _)) = call.capabilities.iter().find(|(_, c)| !c.optional) {
                return Err(ProviderError::new(
                    5700,
                    format!("unsupported non-optional call capability {name}"),
                ));
            }
        }
        Ok(())
    }

    /// The `paymasterService` capability, if the batch asks for sponsorship.
    pub fn paymaster_service(&self) -> Result<Option<PaymasterService>, ProviderError> {
        self.capabilities
            .get("paymasterService")
            .map(|v| serde_json::from_value(v.clone()))
            .transpose()
            .map_err(|e| ProviderError::invalid_params(format!("paymasterService: {e}")))
    }
}

/// The call frames, each with its own execution budget, the atomic flag on all but the last.
#[must_use]
pub fn call_frames(calls: &[Call], atomic: bool, execution: &[u64]) -> Vec<Frame> {
    let n = calls.len();
    calls
        .iter()
        .zip(execution)
        .enumerate()
        .map(|(i, (c, &gas))| {
            let frame = Frame::sender(c.to)
                .with_value(c.value.unwrap_or_default())
                .with_data(c.data.clone().unwrap_or_default())
                .with_execution(gas)
                .with_state(STATE_PER_CALL);
            if atomic && i + 1 < n {
                frame.atomic()
            } else {
                frame
            }
        })
        .collect()
}

/// The batch's transaction, unsigned.
pub fn batch_tx(
    account: &dyn FrameAccount,
    sponsor: Option<&mut dyn Sponsor>,
    calls: Vec<Frame>,
    envelope: &Envelope,
) -> Result<FrameTx, BuildError> {
    let plan = TxPlan::new(account).calls(calls);
    match sponsor {
        Some(s) => plan.sponsored_by(s).build(envelope),
        None => plan.build(envelope),
    }
}

/// A call frame's execution budget from its use in the draft: a quarter over, plus 5,000.
#[must_use]
pub fn tightened(used: u64) -> u64 {
    used * 5 / 4 + 5_000
}

/// The indexes of the call frames in a batch's transaction.
#[must_use]
pub fn call_frame_indexes(tx: &FrameTx) -> Vec<usize> {
    tx.frames
        .iter()
        .enumerate()
        .filter(|(_, f)| f.mode == mode::SENDER)
        .map(|(i, _)| i)
        .collect()
}

/// EIP-5792's status for a mined batch, from its call frames' statuses.
///
/// An atomic batch either commits or rolls back. The frames before the failing one report
/// `SUCCESS` although their effects were undone, since no frame status says "rolled back"
/// (experiment 28, observation 4), so a failure anywhere in an atomic batch means 500.
#[must_use]
pub fn status_code(atomic: bool, call_statuses: &[u64]) -> u16 {
    let ok: Vec<bool> = call_statuses
        .iter()
        .map(|&s| s == u64::from(frame_status::SUCCESS))
        .collect();
    if ok.iter().all(|&o| o) {
        200
    } else if atomic || !ok.iter().any(|&o| o) {
        500
    } else {
        600
    }
}
