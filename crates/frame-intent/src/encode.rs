//! Q in experiment 54's two forms, from a passing verdict.
//!
//! - `assert_writes`: the data of a final mode-3 frame (EIP-7906; `POST_TX` on the Hegota devnet)
//!   for experiment 54's `PostTxAccount`: every allowed storage write and the nonce manager's record,
//!   exactly; every allowed ether balance, exactly; and the payer, whose balance moves by the fee.
//!   The fee recipient is paid after a mode-3 frame, so it is not in that diff.
//! - `assert_named`: the data of the final `SENDER` frame of experiment 54's batch form, for
//!   `OutcomeAccount` and experiment 58's `ControlAccount`: a named read of every allowed write
//!   that has a getter, against its simulated value after.

use alloy::primitives::{Address, Bytes, U256};
use kohaku_frame_kit::{
    FrameTx,
    constants::{ATOMIC_BATCH_FLAG, mode},
    sign::{FrameSigner, SignError, sign_all},
};

use crate::check::{Status, Verdict};
use crate::template::Intent;
use crate::writes::Field;

pub const ASSERT_WRITES: [u8; 4] = [0x25, 0xc8, 0x70, 0x1e];
pub const ASSERT_NAMED: [u8; 4] = [0x68, 0x2c, 0x9c, 0x89];

fn word(v: U256) -> [u8; 32] {
    v.to_be_bytes::<32>()
}

/// `assertWrites` data: `sel || n || (address, slot, after)* || m || (address, after)* || payer`.
#[must_use]
pub fn assert_writes(v: &Verdict, payer: Address) -> Option<Bytes> {
    if v.status != Status::Pass {
        return None;
    }
    let mut slots = Vec::new();
    let mut balances = Vec::new();
    let changes = v.matched.iter().map(|m| m.change).chain(
        v.exempt
            .iter()
            .filter(|e| e.kind.starts_with("nonce: the nonce manager"))
            .map(|e| e.change),
    );
    for c in changes {
        match c.field {
            Field::Storage(s) => slots.push((c.address, s, c.after)),
            Field::Balance if c.address != payer => balances.push((c.address, c.after)),
            _ => {}
        }
    }
    let mut out = ASSERT_WRITES.to_vec();
    out.extend(word(U256::from(slots.len())));
    for (a, s, after) in slots {
        out.extend(a.into_word().as_slice());
        out.extend(s.as_slice());
        out.extend(word(after));
    }
    out.extend(word(U256::from(balances.len())));
    for (a, after) in balances {
        out.extend(a.into_word().as_slice());
        out.extend(word(after));
    }
    out.extend(payer.into_word().as_slice());
    Some(out.into())
}

/// `assert(Q)` data: `sel || (target, expected, len, call padded)*`, one entry per allowed write
/// with a getter. Ether balances have no getter and are left to the comparison at signing.
#[must_use]
pub fn assert_named(v: &Verdict, intent: &Intent) -> Option<Bytes> {
    if v.status != Status::Pass {
        return None;
    }
    let mut out = ASSERT_NAMED.to_vec();
    for m in &v.matched {
        let Some(a) = intent
            .allowed
            .iter()
            .find(|a| a.address == m.change.address && a.field == m.change.field)
        else {
            continue;
        };
        let Some((target, call)) = &a.getter else {
            continue;
        };
        out.extend(target.into_word().as_slice());
        out.extend(word(m.change.after));
        out.extend(word(U256::from(call.len())));
        let mut padded = call.to_vec();
        padded.resize(call.len().div_ceil(32) * 32, 0);
        out.extend(padded);
    }
    Some(out.into())
}

/// The number of entries in `assert(Q)` data.
#[must_use]
pub fn named_entries(data: &[u8]) -> usize {
    let mut p = 4;
    let mut n = 0;
    while p + 96 <= data.len() {
        let len = U256::from_be_slice(&data[p + 64..p + 96]).to::<usize>();
        p += 96 + len.div_ceil(32) * 32;
        n += 1;
    }
    n
}

#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    #[error(
        "the last frame is not the account's own assert(Q) frame (a SENDER frame to the sender, selector 0x682c9c89)"
    )]
    NoCheckFrame,
    #[error(transparent)]
    Sign(#[from] SignError),
}

/// The transaction with its check frame's data replaced by `q`, the body made one atomic batch
/// ending in the check, and every entry signed again by `key`.
pub fn sign_batch(tx: &FrameTx, q: &Bytes, key: &FrameSigner) -> Result<FrameTx, BatchError> {
    let mut out = tx.clone();
    let last = out
        .frames
        .len()
        .checked_sub(1)
        .ok_or(BatchError::NoCheckFrame)?;
    let check = &out.frames[last];
    let to_sender = check.target.is_none_or(|t| t == tx.sender);
    if check.mode != mode::SENDER || !to_sender || check.data.get(..4) != Some(&ASSERT_NAMED[..]) {
        return Err(BatchError::NoCheckFrame);
    }
    let entries = named_entries(q) as u64;
    out.frames[last].data = q.clone();
    out.frames[last].limits.execution = out.frames[last]
        .limits
        .execution
        .max(30_000 + 8_000 * entries);
    for f in &mut out.frames[..last] {
        if f.mode != mode::VERIFY {
            f.flags |= ATOMIC_BATCH_FLAG;
        }
    }
    for s in &mut out.signatures {
        s.signature = Bytes::new();
    }
    sign_all(&mut out, std::slice::from_ref(key))?;
    Ok(out)
}
