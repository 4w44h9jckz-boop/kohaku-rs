//! The execution digest E as `eth_signTypedData_v4` carries it, and back: the second thing a
//! device may be asked to show, when the wallet sends the typed data rather than the transaction.

use alloy::{
    dyn_abi::TypedData,
    primitives::{Address, B256, Bytes, U256},
};
use kohaku_frame_kit::{
    FrameTx,
    digest::{is_pay_frame, nonce_keys_hash},
    tx::{Frame, FrameLimits},
};
use serde_json::{Value, json};

#[derive(Debug, thiserror::Error)]
pub enum TypedError {
    #[error("typed data: {0}")]
    Parse(String),
    #[error("not a FrameExecution message: {0}")]
    Shape(&'static str),
}

/// `encodeType(FrameExecution)`.
pub const ENCODED_TYPE: &str = "FrameExecution(bytes32 nonceKeysHash,uint64 nonceSeq,Frame[] frames,bytes32[] blobVersionedHashes)Frame(uint8 mode,uint8 flags,address target,uint64 executionLimit,uint64 stateLimit,uint256 value,bytes data)";

/// The typed data a wallet sends to `eth_signTypedData_v4` for `tx`'s E.
#[must_use]
pub fn execution_typed_data(tx: &FrameTx) -> Value {
    let frames: Vec<Value> = tx
        .frames
        .iter()
        .map(|f| {
            let pay = is_pay_frame(f);
            json!({
                "mode": f.mode,
                "flags": f.flags,
                "target": if pay { Address::ZERO } else { f.target.unwrap_or(tx.sender) },
                "executionLimit": if pay { 0 } else { f.limits.execution }.to_string(),
                "stateLimit": if pay { 0 } else { f.limits.state }.to_string(),
                "value": f.value.to_string(),
                "data": if pay { Bytes::new() } else { f.data.clone() },
            })
        })
        .collect();
    json!({
        "types": {
            "EIP712Domain": [
                { "name": "name", "type": "string" },
                { "name": "version", "type": "string" },
                { "name": "chainId", "type": "uint256" },
                { "name": "verifyingContract", "type": "address" },
            ],
            "FrameExecution": [
                { "name": "nonceKeysHash", "type": "bytes32" },
                { "name": "nonceSeq", "type": "uint64" },
                { "name": "frames", "type": "Frame[]" },
                { "name": "blobVersionedHashes", "type": "bytes32[]" },
            ],
            "Frame": [
                { "name": "mode", "type": "uint8" },
                { "name": "flags", "type": "uint8" },
                { "name": "target", "type": "address" },
                { "name": "executionLimit", "type": "uint64" },
                { "name": "stateLimit", "type": "uint64" },
                { "name": "value", "type": "uint256" },
                { "name": "data", "type": "bytes" },
            ],
        },
        "primaryType": "FrameExecution",
        "domain": {
            "name": "FrameExecution",
            "version": "1",
            "chainId": tx.chain_id,
            "verifyingContract": tx.sender,
        },
        "message": {
            "nonceKeysHash": nonce_keys_hash(&tx.nonce_keys),
            "nonceSeq": tx.nonce_seq.to_string(),
            "frames": frames,
            "blobVersionedHashes": tx.blob_versioned_hashes,
        },
    })
}

/// A `FrameExecution` message, read back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionMessage {
    pub chain_id: u64,
    /// The domain's `verifyingContract`: the account.
    pub sender: Address,
    pub nonce_keys_hash: B256,
    pub nonce_seq: u64,
    /// The frames as E has them: every target explicit, pay frames zeroed.
    pub frames: Vec<Frame>,
    pub blob_versioned_hashes: Vec<B256>,
    /// The EIP-712 signing hash, from alloy's encoder over the JSON as given.
    pub digest: B256,
}

fn field<'a>(v: &'a Value, name: &'static str) -> Result<&'a Value, TypedError> {
    v.get(name).ok_or(TypedError::Shape(name))
}

fn number<T: TryFrom<U256>>(v: &Value, name: &'static str) -> Result<T, TypedError> {
    let u = match v {
        Value::Number(n) => n.as_u64().map(U256::from),
        Value::String(s) => s.parse::<U256>().ok(),
        _ => None,
    };
    u.and_then(|u| T::try_from(u).ok())
        .ok_or(TypedError::Shape(name))
}

fn parsed<T: std::str::FromStr>(v: &Value, name: &'static str) -> Result<T, TypedError> {
    v.as_str()
        .and_then(|s| s.parse().ok())
        .ok_or(TypedError::Shape(name))
}

/// Read `json` as a `FrameExecution` message, checking its domain and types.
pub fn parse_execution(json: &Value) -> Result<ExecutionMessage, TypedError> {
    let typed: TypedData =
        serde_json::from_value(json.clone()).map_err(|e| TypedError::Parse(e.to_string()))?;
    if typed.primary_type != "FrameExecution" {
        return Err(TypedError::Shape("primaryType"));
    }
    let d = &typed.domain;
    if d.name.as_deref() != Some("FrameExecution") || d.version.as_deref() != Some("1") {
        return Err(TypedError::Shape("domain name and version"));
    }
    let chain_id = d
        .chain_id
        .and_then(|c| u64::try_from(c).ok())
        .ok_or(TypedError::Shape("domain chainId"))?;
    let sender = d
        .verifying_contract
        .ok_or(TypedError::Shape("domain verifyingContract"))?;
    let digest = typed
        .eip712_signing_hash()
        .map_err(|e| TypedError::Parse(e.to_string()))?;
    // The types must be E's, or the digest is of another message that names itself the same.
    if typed.encode_type().ok().as_deref() != Some(ENCODED_TYPE) {
        return Err(TypedError::Shape("types"));
    }

    let m = &typed.message;
    let frames = field(m, "frames")?
        .as_array()
        .ok_or(TypedError::Shape("frames"))?
        .iter()
        .map(|f| {
            Ok(Frame {
                mode: number(field(f, "mode")?, "mode")?,
                flags: number(field(f, "flags")?, "flags")?,
                target: Some(parsed(field(f, "target")?, "target")?),
                limits: FrameLimits {
                    execution: number(field(f, "executionLimit")?, "executionLimit")?,
                    state: number(field(f, "stateLimit")?, "stateLimit")?,
                },
                value: number(field(f, "value")?, "value")?,
                data: parsed(field(f, "data")?, "data")?,
            })
        })
        .collect::<Result<_, TypedError>>()?;
    let blob_versioned_hashes = field(m, "blobVersionedHashes")?
        .as_array()
        .ok_or(TypedError::Shape("blobVersionedHashes"))?
        .iter()
        .map(|h| parsed(h, "blobVersionedHashes"))
        .collect::<Result<_, TypedError>>()?;
    Ok(ExecutionMessage {
        chain_id,
        sender,
        nonce_keys_hash: parsed(field(m, "nonceKeysHash")?, "nonceKeysHash")?,
        nonce_seq: number(field(m, "nonceSeq")?, "nonceSeq")?,
        frames,
        blob_versioned_hashes,
        digest,
    })
}
