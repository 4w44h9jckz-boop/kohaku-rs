//! The vault on chain, from the owner's side: its published openings, the owner's latest note,
//! and the redemption, the vault being its sender and payer.
//!
//! The interface is the one the committee's builders described for X9. It is provisional until
//! their ABI file lands with the contract, before the first transaction:
//!
//! ```text
//! deposit(bytes32 commitment) payable    the refund pool's, with its Deposit and RecentRoot events
//! enqueue(bytes sealed)                  event Intent(uint256 index, bytes sealed)
//! update (a frame transaction)           event Opening(uint256 updateNumber, bytes openings)
//! withdraw(...)                          the refund pool's, in its frames
//! mode(), since(), committeeKey()
//! ```
//!
//! A redemption is the refund pool's withdrawal byte for byte (`kohaku-frame-pool`), priced
//! uniformly, with the nullifier hash as its only nonce key. Its `VERIFY` cannot read the time, so
//! the vault's `withdraw` frame does: before `T` blocks of a stalled queue it reverts and pays
//! nothing, and the note's nonce sequence has moved on. The vault accepts sequences 0 to 2, so an
//! owner may try again ([`Outcome::PaidNothing`]).

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, U256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use anyhow::{Context as _, ensure};
use kohaku_frame_kit::{FrameTx, rpc};
use kohaku_frame_pool::{
    FramePoolProof,
    chain::{self, uniform_withdrawal},
    withdrawal::{FramePool, WithdrawalOpts, abi::RecentRoot},
};
use kohaku_tornadocash::{Field, Note, Secret};
use rand::CryptoRng;

use crate::{
    Context, OpeningKey,
    note::{Garbage, Opening, assemble, check},
};

/// The highest nonce sequence the vault accepts for a redemption: two retries after a try that
/// came too early.
pub const MAX_SEQUENCE: u64 = 2;

pub mod abi {
    alloy::sol! {
        event Opening(uint256 updateNumber, bytes openings);
        event Intent(uint256 index, bytes sealed);
        function enqueue(bytes sealed);
        function mode() view returns (uint8);
        function since() view returns (uint256);
        function committeeKey() view returns (bytes);
    }
}

/// Every update's published openings, oldest first.
pub async fn published<P: Provider>(
    provider: &P,
    vault: Address,
) -> anyhow::Result<Vec<(u64, Vec<u8>)>> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(vault)
                .event_signature(abi::Opening::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?;
    let mut out = Vec::with_capacity(logs.len());
    for l in logs {
        let e = abi::Opening::decode_log_data(l.data()).context("an Opening event")?;
        out.push((e.updateNumber.to::<u64>(), e.openings.to_vec()));
    }
    out.sort_by_key(|(u, _)| *u);
    Ok(out)
}

/// What the owner finds for one opening key, newest update first: the note it may redeem, and
/// every garbage opening on the way.
pub struct Found {
    pub note: Option<(Note, Opening)>,
    pub garbage: Vec<(u64, Garbage)>,
}

/// The owner's latest note in `vault`: the newest update whose openings are for `key`, assembled
/// and checked against the commitment the vault holds at its leaf, with `secret`.
pub async fn latest_note<P: Provider>(
    provider: &P,
    vault: Address,
    key: &OpeningKey,
    secret: &Secret,
) -> anyhow::Result<Found> {
    let mut garbage = vec![];
    for (update, openings) in published(provider, vault).await?.into_iter().rev() {
        let context = Context { vault, update };
        let opening = match assemble(key, &context, &openings) {
            None => continue,
            Some(Err(g)) => {
                garbage.push((update, g));
                continue;
            }
            Some(Ok(o)) => o,
        };
        let leaves = chain::leaves(provider, vault, opening.leaf as usize).await?;
        let at = leaves
            .get(opening.leaf as usize)
            .copied()
            .context("no commitment at the opening's leaf")?;
        match check(&opening, secret, at) {
            Ok(note) => {
                return Ok(Found {
                    note: Some((note, opening)),
                    garbage,
                });
            }
            Err(g) => garbage.push((update, g)),
        }
    }
    Ok(Found {
        note: None,
        garbage,
    })
}

/// The slot EIP-8272 filed `root` at, most recently, from the vault's `RecentRoot` events.
pub async fn root_slot<P: Provider>(
    provider: &P,
    vault: Address,
    root: B256,
) -> anyhow::Result<u64> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(vault)
                .event_signature(RecentRoot::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?;
    logs.iter()
        .rev()
        .find(|l| B256::from_slice(&l.data().data[..32]) == root)
        .map(|l| U256::from_be_slice(&l.data().data[32..64]).to::<u64>())
        .context("the root was never filed")
}

/// The redemption of `note`, among the vault's `leaves`, to `recipient`: the refund pool's
/// withdrawal at uniform pricing, proved on this device, at nonce sequence `sequence`.
pub fn redemption(
    vault: &FramePool,
    note: &Note,
    leaves: &[Field],
    recipient: Address,
    opts: &WithdrawalOpts,
    sequence: u64,
    rng: &mut impl CryptoRng,
) -> anyhow::Result<(FrameTx, FramePoolProof)> {
    ensure!(
        sequence <= MAX_SEQUENCE,
        "the vault accepts sequences 0 to {MAX_SEQUENCE}"
    );
    let (mut tx, proof) = uniform_withdrawal(vault, note, leaves, recipient, opts, rng)?;
    tx.nonce_seq = sequence;
    Ok((tx, proof))
}

/// What became of a redemption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Mined, and its `withdraw` paid out.
    Paid { hash: B256, block: u64 },
    /// Mined, but its `withdraw` reverted: before escape mode, it pays nothing. The note's next
    /// sequence may try again.
    PaidNothing { hash: B256, block: u64 },
    /// Not admitted: the node's answer, word for word.
    Refused(String),
}

/// Hands `tx` to the node at `node` alone and awaits it on `chain`. The withdraw frame is the
/// third, as in the refund pool's layout.
pub async fn redeem<N: Provider, C: Provider>(
    node: &N,
    chain: &C,
    tx: &FrameTx,
) -> anyhow::Result<Outcome> {
    let hash = match rpc::send(node, tx).await {
        Ok(h) => h,
        Err(e) => return Ok(Outcome::Refused(e.to_string())),
    };
    let r = rpc::wait_for_confirmed_receipt(
        chain,
        hash,
        Duration::from_mins(5),
        Duration::from_secs(2),
    )
    .await?;
    let block = r.block_number.to::<u64>();
    let withdrew = r
        .frame_receipts
        .get(2)
        .is_some_and(|f| f.status == U256::from(1));
    Ok(if withdrew {
        Outcome::Paid { hash, block }
    } else {
        Outcome::PaidNothing { hash, block }
    })
}
