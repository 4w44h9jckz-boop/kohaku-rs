//! The execution-scope digest $E$: an EIP-712 hash of everything an execution-only approval
//! authorizes, and nothing the payer chooses.
//!
//! Written from the draft ERC in exp-frames experiment 27
//! (`experiments/27-execution-digest/erc-draft.md`), with alloy's EIP-712 derive standing in for
//! the encoder, so it shares no code with the TypeScript reference it is checked against.
//!
//! ```text
//! domain  = EIP712Domain("FrameExecution", "1", chain_id, verifyingContract = sender)
//! message = FrameExecution(nonce_keys_hash, nonce_seq, frames, blob_versioned_hashes)
//! frame   = Frame(mode, flags, resolved target, execution limit, state limit, value, data),
//!           with target, both limits and data zeroed in a pay frame
//! ```
//!
//! A pay frame is a `VERIFY` frame whose allowed scope is `PAYMENT` alone. An account that verifies
//! $E$ may approve `EXECUTION` on it and nothing else: $E$ leaves out the fees.

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::{Eip712Domain, SolStruct, eip712_domain},
};

use crate::{
    constants::{approve, mode},
    tx::{Frame, FrameTx},
};

mod typed {
    alloy::sol! {
        struct Frame {
            uint8 mode;
            uint8 flags;
            address target;
            uint64 executionLimit;
            uint64 stateLimit;
            uint256 value;
            bytes data;
        }

        struct FrameExecution {
            bytes32 nonceKeysHash;
            uint64 nonceSeq;
            Frame[] frames;
            bytes32[] blobVersionedHashes;
        }
    }
}

/// A `VERIFY` frame whose allowed scope is `PAYMENT` alone. Decided by mode and flags only.
#[must_use]
pub fn is_pay_frame(frame: &Frame) -> bool {
    frame.mode == mode::VERIFY && frame.flags & approve::SCOPE_MASK == approve::PAYMENT
}

/// EIP-8250's `nonce_keys_hash`: keccak256 of the key count and the keys, as 32-byte words.
#[must_use]
pub fn nonce_keys_hash(keys: &[U256]) -> B256 {
    let mut words = Vec::with_capacity(32 * (keys.len() + 1));
    words.extend_from_slice(&U256::from(keys.len()).to_be_bytes::<32>());
    for key in keys {
        words.extend_from_slice(&key.to_be_bytes::<32>());
    }
    keccak256(words)
}

/// The EIP-712 domain: the chain and the account.
#[must_use]
pub fn execution_domain(tx: &FrameTx) -> Eip712Domain {
    eip712_domain! {
        name: "FrameExecution",
        version: "1",
        chain_id: tx.chain_id,
        verifying_contract: tx.sender,
    }
}

fn typed_frame(tx: &FrameTx, frame: &Frame) -> typed::Frame {
    if is_pay_frame(frame) {
        return typed::Frame {
            mode: frame.mode,
            flags: frame.flags,
            target: Address::ZERO,
            executionLimit: 0,
            stateLimit: 0,
            value: frame.value,
            data: Bytes::new(),
        };
    }
    typed::Frame {
        mode: frame.mode,
        flags: frame.flags,
        target: frame.target.unwrap_or(tx.sender),
        executionLimit: frame.limits.execution,
        stateLimit: frame.limits.state,
        value: frame.value,
        data: frame.data.clone(),
    }
}

fn typed_message(tx: &FrameTx) -> typed::FrameExecution {
    typed::FrameExecution {
        nonceKeysHash: nonce_keys_hash(&tx.nonce_keys),
        nonceSeq: tx.nonce_seq,
        frames: tx.frames.iter().map(|f| typed_frame(tx, f)).collect(),
        blobVersionedHashes: tx.blob_versioned_hashes.clone(),
    }
}

/// `hashStruct(FrameExecution)`.
#[must_use]
pub fn execution_struct_hash(tx: &FrameTx) -> B256 {
    typed_message(tx).eip712_hash_struct()
}

/// $E$ = keccak256(0x1901 ‖ domain separator ‖ struct hash): the `msg` an execution-only
/// signature entry carries.
#[must_use]
pub fn execution_digest(tx: &FrameTx) -> B256 {
    typed_message(tx).eip712_signing_hash(&execution_domain(tx))
}
