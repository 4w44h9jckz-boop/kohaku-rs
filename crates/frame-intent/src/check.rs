//! The exact comparison: every change is allowed by the intent with exactly its value after, or
//! exempt by kind; and every write the intent expects is present.
//!
//! Exempt by kind, computed from the transaction, never from the template:
//! - the fee: the payer's balance falls by at most the maximum cost (plus the intent's ether out,
//!   when the payer is the sender); the fee recipient's balance rises by at most the maximum cost;
//! - the nonce: for each EIP-8250 key, the nonce manager's slot for the sender rises by exactly one;
//!   for the legacy nonce, the sender's account nonce rises by exactly one.
//!
//! Nothing else is exempt: no other write by the nonce manager or to the fee recipient, and never a
//! code change.

use alloy::primitives::{Address, I256, U256};
use kohaku_frame_kit::{Eip8250, FrameTx, constants::NONCE_MANAGER, rpc::keyed_nonce_slot};
use serde::Serialize;

use crate::template::{Allowed, Expect, Intent};
use crate::writes::{Change, Field, Simulation, changes};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    Pass,
    Fail,
    NotSimulated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Matched {
    pub what: String,
    pub change: Change,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Mismatch {
    pub what: String,
    pub change: Change,
    pub expected: Expect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Exempt {
    pub kind: &'static str,
    pub change: Change,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Verdict {
    pub status: Status,
    pub reason: Option<String>,
    pub matched: Vec<Matched>,
    pub exempt: Vec<Exempt>,
    pub unlisted: Vec<Change>,
    pub missing: Vec<Allowed>,
    pub mismatched: Vec<Mismatch>,
}

impl Verdict {
    fn not_simulated(reason: String) -> Self {
        Self {
            status: Status::NotSimulated,
            reason: Some(reason),
            matched: vec![],
            exempt: vec![],
            unlisted: vec![],
            missing: vec![],
            mismatched: vec![],
        }
    }
}

fn delta(c: &Change) -> I256 {
    I256::from_raw(c.after).wrapping_sub(I256::from_raw(c.before))
}

/// Compare a simulation's writes with an intent. `fee_recipient` is the coinbase of the block the
/// simulation ran on; `rules` is the chain's EIP-8250 revision, which decides whether nonce key 0
/// is the legacy nonce (`f3079a0`, keys `[0]`) or an ordinary key (master, where `[]` is legacy).
#[must_use]
pub fn check(
    tx: &FrameTx,
    sim: &Simulation,
    intent: &Intent,
    fee_recipient: Address,
    rules: Eip8250,
) -> Verdict {
    if !sim.valid {
        return Verdict::not_simulated(format!(
            "invalid: {}",
            sim.violation.clone().unwrap_or_default()
        ));
    }
    let Some(writes) = sim.writes.as_deref() else {
        return Verdict::not_simulated(
            "the simulation lists no writes: its full execution did not run".into(),
        );
    };
    let max_cost = sim.max_cost.unwrap_or_default();
    let payer = sim.payer.unwrap_or(tx.sender);
    let legacy = match rules {
        Eip8250::F3079a0 => tx.nonce_keys.iter().all(U256::is_zero),
        Eip8250::Master => tx.nonce_keys.is_empty(),
    };
    let nonce_slots: Vec<_> = if legacy {
        vec![]
    } else {
        tx.nonce_keys
            .iter()
            .map(|k| keyed_nonce_slot(tx.sender, *k))
            .collect()
    };

    let mut v = Verdict {
        status: Status::Pass,
        reason: None,
        matched: vec![],
        exempt: vec![],
        unlisted: vec![],
        missing: vec![],
        mismatched: vec![],
    };
    let mut seen = vec![false; intent.allowed.len()];
    let mut swap_out: Option<U256> = None;

    for c in changes(writes) {
        // An allowed write first: the intent decides about its own resources.
        if let Some(i) = intent
            .allowed
            .iter()
            .position(|a| a.address == c.address && a.field == c.field)
        {
            seen[i] = true;
            let a = &intent.allowed[i];
            let ok = match a.expect {
                // The payer's own balance also pays the fee, up to the maximum cost.
                Expect::Delta(d) if c.field == Field::Balance && c.address == payer => {
                    let got = delta(&c);
                    got <= d && got >= d - I256::from_raw(max_cost)
                }
                Expect::Delta(d) => delta(&c) == d,
                Expect::Exact(x) | Expect::ExactIfChanged(x) => c.after == x,
                Expect::SwapOut { sign, min } => {
                    let d = delta(&c);
                    let amount = if sign > 0 { d } else { -d };
                    let ok = amount > I256::ZERO
                        && amount.into_raw() >= min
                        && swap_out.is_none_or(|s| s == amount.into_raw());
                    swap_out = Some(amount.into_raw());
                    ok
                }
            };
            if ok {
                v.matched.push(Matched {
                    what: a.what.clone(),
                    change: c,
                });
            } else {
                v.mismatched.push(Mismatch {
                    what: a.what.clone(),
                    change: c,
                    expected: a.expect,
                });
            }
            continue;
        }
        let exempt = match c.field {
            Field::Balance if c.address == payer => {
                let fell = I256::from_raw(c.before).wrapping_sub(I256::from_raw(c.after));
                let out = if payer == tx.sender {
                    intent.value_out
                } else {
                    U256::ZERO
                };
                (fell >= I256::from_raw(out)
                    && fell <= I256::from_raw(out.saturating_add(max_cost)))
                .then_some("fee: the payer")
            }
            Field::Balance if c.address == fee_recipient => {
                let rose = delta(&c);
                (rose >= I256::ZERO && rose <= I256::from_raw(max_cost))
                    .then_some("fee: the fee recipient")
            }
            Field::Nonce if legacy && c.address == tx.sender => {
                (c.after == c.before + U256::from(1)).then_some("nonce: the sender's account nonce")
            }
            Field::Storage(s) if c.address == NONCE_MANAGER && nonce_slots.contains(&s) => {
                (c.after == c.before + U256::from(1)).then_some("nonce: the nonce manager's record")
            }
            _ => None,
        };
        match exempt {
            Some(kind) => v.exempt.push(Exempt { kind, change: c }),
            None => v.unlisted.push(c),
        }
    }
    // The sender's ether when someone else pays: it moves by exactly the intent's value out.
    if payer != tx.sender && !intent.value_out.is_zero() {
        let moved = v
            .unlisted
            .iter()
            .position(|c| c.address == tx.sender && c.field == Field::Balance);
        match moved {
            Some(i) if delta(&v.unlisted[i]) == -I256::from_raw(intent.value_out) => {
                let c = v.unlisted.remove(i);
                v.matched.push(Matched {
                    what: format!("the sender sends {}", intent.value_out),
                    change: c,
                });
            }
            _ => {}
        }
    }
    for (i, a) in intent.allowed.iter().enumerate() {
        if !seen[i] && !matches!(a.expect, Expect::ExactIfChanged(_)) {
            v.missing.push(a.clone());
        }
    }
    if !(v.unlisted.is_empty() && v.missing.is_empty() && v.mismatched.is_empty()) {
        v.status = Status::Fail;
    }
    v
}
