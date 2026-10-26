//! The vault on chain, from the owner's side: its published openings, the owner's latest note,
//! and the redemption, the vault being its sender and payer.
//!
//! The interface is the committee's `ExitVault` (`exp-e2e-frames` experiment 14,
//! `contracts/ExitVault.abi.json`), in the part the owner and a holder use:
//!
//! ```text
//! deposit(bytes32 commitment) payable    the refund pool's, with its Deposit and RecentRoot events
//! enqueue(bytes sealed)                  event Intent(uint256 index, bytes sealed); index = tail()
//! update (a frame transaction)           event Opening(uint256 updateNumber, bytes openings)
//! withdraw(...)                          the refund pool's, in its frames
//! mode(), since(), tail(), nextIndex(), getLastRoot(), sourceId(), committeeKey()
//! ```
//!
//! A redemption is the refund pool's withdrawal byte for byte (`kohaku-frame-pool`), priced
//! uniformly, with the nullifier hash as its only nonce key, and one change: the withdraw frame's
//! state budget is [`WITHDRAW_STATE`], since the vault writes more than the refund pool. Its `VERIFY` cannot read the time, so
//! the vault's `withdraw` frame does: before `T` blocks of a stalled queue it reverts and pays
//! nothing, and the note's nonce sequence has moved on. The vault accepts sequences 0 to 2, so an
//! owner may try again ([`Outcome::PaidNothing`]).

use std::time::Duration;

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use anyhow::{Context as _, ensure};
use kohaku_frame_kit::{FrameTx, rpc};
use kohaku_frame_pool::{
    FramePoolProof, PublicInputs, chain, prove,
    withdrawal::{
        FramePool, PoolMode, Pricing, WithdrawalOpts, abi::RecentRoot, withdrawal_tx,
        worst_case_max_cost,
    },
};
use kohaku_tornadocash::{Field, Note, Payer, Secret};
use rand::CryptoRng;

use crate::{
    Context, OpeningKey,
    note::{Garbage, Opening, assemble, check},
};

/// The withdraw frame's state budget: the recipient's new account (183,600), the note's spent slot
/// (97,920) and, on the vault's first redemption, its packed mode slot (97,920). The committee's
/// builders measured 379,440 for a first redemption and 281,520 for a second on a local ethrex.
pub const WITHDRAW_STATE: u64 = 183_600 + 2 * 97_920;

/// The highest nonce sequence the vault accepts for a redemption: two retries after a try that
/// came too early.
pub const MAX_SEQUENCE: u64 = 2;

pub mod abi {
    alloy::sol! {
        event Opening(uint256 updateNumber, bytes openings);
        event Intent(uint256 index, bytes sealed);
        function enqueue(bytes sealed);
        function mode() view returns (uint256);
        function since() view returns (uint256);
        function tail() view returns (uint256);
        function nextIndex() view returns (uint256);
        function spent(bytes32 nullifierHash) view returns (uint256);
        /// The compressed key, 33 bytes: the first 32, then byte 33 at the start of the second word.
        function committeeKey() view returns (bytes32, bytes32);
        function getLastRoot() view returns (bytes32);
        function sourceId() view returns (bytes32);
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
    // Uniform pricing (the pool's default limits, the worst-case fee of that shape), with the
    // vault's state budget in the shape the fee is priced from.
    let opts = WithdrawalOpts {
        sponsor: None,
        execution_limits: None,
        pricing: Pricing::Uniform,
        ..opts.clone()
    };
    let shaped = |inputs: &PublicInputs, proof: &Bytes| -> anyhow::Result<FrameTx> {
        let mut tx = withdrawal_tx(vault, inputs, proof, &opts)?;
        tx.frames[2].limits.state = WITHDRAW_STATE;
        tx.nonce_seq = sequence;
        Ok(tx)
    };
    let shape = PublicInputs {
        root: B256::ZERO,
        nullifier_hash: B256::ZERO,
        recipient,
        relayer: vault.address,
        fee: U256::MAX,
        refund: U256::ZERO,
    };
    let fee = worst_case_max_cost(&shaped(&shape, &Bytes::from(vec![0; 256]))?)?;
    let payer = Payer {
        address: vault.address,
        fee,
        refund: U256::ZERO,
    };
    let proof = prove(note.clone(), leaves, recipient, payer, rng)?;
    let tx = shaped(&proof.inputs, &proof.proof)?;
    Ok((tx, proof))
}

async fn call<P: Provider, C: alloy::sol_types::SolCall>(
    provider: &P,
    vault: Address,
    call: &C,
) -> anyhow::Result<Bytes> {
    Ok(provider
        .call(
            alloy::rpc::types::TransactionRequest::default()
                .to(vault)
                .input(call.abi_encode().into()),
        )
        .await?)
}

async fn word<P: Provider, C: alloy::sol_types::SolCall>(
    provider: &P,
    vault: Address,
    c: &C,
) -> anyhow::Result<B256> {
    let out = call(provider, vault, c).await?;
    ensure!(out.len() == 32, "a view returned {} bytes", out.len());
    Ok(B256::from_slice(&out))
}

/// The vault as the refund pool's withdrawal sees it, with the EIP-8272 salt its roots are filed
/// under, checked against its `sourceId()`.
pub async fn pool<P: Provider>(
    provider: &P,
    vault: Address,
    salt: B256,
) -> anyhow::Result<FramePool> {
    let pool = FramePool {
        address: vault,
        mode: PoolMode::Refund,
        salt,
    };
    ensure!(
        word(provider, vault, &abi::sourceIdCall {}).await? == pool.source_id(),
        "the salt does not make the vault's sourceId()"
    );
    Ok(pool)
}

/// The vault's latest root, `getLastRoot()`.
pub async fn last_root<P: Provider>(provider: &P, vault: Address) -> anyhow::Result<B256> {
    word(provider, vault, &abi::getLastRootCall {}).await
}

/// The index the next intent takes, `tail()`.
pub async fn tail<P: Provider>(provider: &P, vault: Address) -> anyhow::Result<u64> {
    Ok(U256::from_be_bytes(word(provider, vault, &abi::tailCall {}).await?.0).to::<u64>())
}

/// The vault's mode, `mode()`: 0 normal, 1 escape.
pub async fn mode<P: Provider>(provider: &P, vault: Address) -> anyhow::Result<u64> {
    Ok(U256::from_be_bytes(word(provider, vault, &abi::modeCall {}).await?.0).to::<u64>())
}

/// The vault's leaves, all of them: a redemption proves against the latest root, since every
/// update files a new one.
pub async fn all_leaves<P: Provider>(provider: &P, vault: Address) -> anyhow::Result<Vec<Field>> {
    let next =
        U256::from_be_bytes(word(provider, vault, &abi::nextIndexCall {}).await?.0).to::<usize>();
    ensure!(next > 0, "the vault holds no notes");
    Ok(chain::leaves(provider, vault, next - 1).await?)
}

/// The committee's sealing key, from `committeeKey()`.
pub async fn committee_key<P: Provider>(provider: &P, vault: Address) -> anyhow::Result<[u8; 33]> {
    let out = call(provider, vault, &abi::committeeKeyCall {}).await?;
    ensure!(
        out.len() == 64,
        "committeeKey() returned {} bytes",
        out.len()
    );
    let mut key = [0u8; 33];
    key.copy_from_slice(&out[..33]);
    Ok(key)
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
