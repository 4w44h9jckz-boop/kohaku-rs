//! The pool on a node: a deposit, the tree read back from `Deposit` events, and a withdrawal
//! priced from a simulation the way a wallet prices one.

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::{SolCall, SolEvent},
};
use kohaku_frame_kit::{
    Fees, Frame, FrameSigner, FrameTx,
    constants::approve,
    gas::UnknownScheme,
    json::FrameTxReceiptJson,
    rpc::{self, ExecuteError, RpcError},
    sign_all,
};
use kohaku_tornadocash::{Field, Note, Payer};
use rand::CryptoRng;

use crate::{
    FramePoolError, FramePoolProof, PublicInputs, prove,
    withdrawal::{
        DENOMINATION, FramePool, POOL_FEES, Pricing, WithdrawalOpts, WithdrawalTxError,
        abi::{Deposit, RecentRoot, depositCall},
        tightened_limits, withdrawal_tx, worst_case_max_cost,
    },
};

#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error(transparent)]
    Rpc(#[from] RpcError),
    #[error(transparent)]
    Execute(#[from] ExecuteError),
    #[error(transparent)]
    Transport(#[from] alloy::transports::TransportError),
    #[error(transparent)]
    Sign(#[from] kohaku_frame_kit::sign::SignError),
    #[error(transparent)]
    Withdrawal(#[from] WithdrawalTxError),
    #[error(transparent)]
    Prove(#[from] FramePoolError),
    #[error(transparent)]
    Gas(#[from] UnknownScheme),
    #[error("{0}")]
    Missing(&'static str),
    #[error("the draft withdrawal was refused in simulation: {0}")]
    Draft(String),
}

/// A mined deposit: where the note landed, and the root the pool published to EIP-8272 for it.
#[derive(Debug, Clone)]
pub struct Deposited {
    pub receipt: FrameTxReceiptJson,
    pub leaf_index: usize,
    pub root: B256,
    pub slot: u64,
}

/// Deposit `note` from an ordinary account signing an ordinary frame transaction.
pub async fn deposit<P: Provider>(
    provider: &P,
    pool: &FramePool,
    depositor: &FrameSigner,
    note: &Note,
) -> Result<Deposited, ChainError> {
    let from = depositor.address();
    let mut tx = FrameTx {
        chain_id: provider.get_chain_id().await?,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: rpc::nonce_seq(provider, from, &[U256::ZERO]).await?,
        sender: from,
        frames: vec![
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None).with_execution(20_000),
            Frame::sender(Some(pool.address))
                .with_value(U256::from(DENOMINATION))
                .with_data(
                    depositCall {
                        commitment: B256::from(note.commitment()),
                    }
                    .abi_encode(),
                )
                .with_execution(1_500_000)
                .with_state(3_000_000),
        ],
        signatures: vec![depositor.placeholder(None)],
        fees: POOL_FEES,
        blob_versioned_hashes: vec![],
    };
    sign_all(&mut tx, std::slice::from_ref(depositor))?;
    let receipt = rpc::execute(provider, &tx, true).await?.receipt;

    // The pool published its new root to EIP-8272 in the same frame.
    let logs: Vec<_> = receipt
        .frame_receipts
        .iter()
        .flat_map(|f| &f.logs)
        .filter(|l| l.address == pool.address)
        .collect();
    let leaf_index = logs
        .iter()
        .find(|l| l.topics.first() == Some(&Deposit::SIGNATURE_HASH))
        .map(|l| U256::from_be_slice(&l.data[..32]).to::<usize>())
        .ok_or(ChainError::Missing("no Deposit event"))?;
    let (root, slot) = logs
        .iter()
        .find(|l| l.topics.first() == Some(&RecentRoot::SIGNATURE_HASH))
        .map(|l| {
            let root = B256::from_slice(&l.data[..32]);
            (root, U256::from_be_slice(&l.data[32..64]).to::<u64>())
        })
        .ok_or(ChainError::Missing("no RecentRoot event"))?;
    Ok(Deposited {
        receipt,
        leaf_index,
        root,
        slot,
    })
}

/// The pool's leaves `0..=through`, in insertion order, from its `Deposit` events.
pub async fn leaves<P: Provider>(
    provider: &P,
    pool: Address,
    through: usize,
) -> Result<Vec<Field>, ChainError> {
    let events = provider
        .get_logs(
            &Filter::new()
                .address(pool)
                .event_signature(Deposit::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?;
    let mut leaves = vec![None; through + 1];
    for e in &events {
        let index = U256::from_be_slice(&e.data().data[..32]).to::<usize>();
        if index <= through {
            leaves[index] = Field::try_from(e.topics()[1]).ok();
        }
    }
    leaves
        .into_iter()
        .collect::<Option<_>>()
        .ok_or(ChainError::Missing("gap in the Deposit events"))
}

/// The fee that covers a pool-paid withdrawal to `recipient` in the worst case, at the limits in
/// `opts` (the pool's defaults when they are `None`). The shape alone sets it: the fee and the
/// proof's bytes do not change a worst-case price, so it needs no proof.
///
/// At the default limits this is [`uniform_fee`]; at [`tightened_limits`] it is what
/// [`Pricing::Tightened`] binds.
///
/// # Errors
/// Returns an error if the shape cannot be built or priced.
pub fn worst_case_fee(
    pool: &FramePool,
    recipient: Address,
    opts: &WithdrawalOpts,
) -> Result<U256, ChainError> {
    let opts = WithdrawalOpts {
        sponsor: None,
        ..opts.clone()
    };
    let shape = withdrawal_tx(
        pool,
        &shape_inputs(pool, recipient),
        &Bytes::from(vec![0; 256]),
        &opts,
    )?;
    Ok(worst_case_max_cost(&shape)?)
}

/// The fee [`Pricing::Uniform`] binds into a withdrawal to `recipient`: the worst case at the
/// pool's default limits, whatever `opts.execution_limits` says. It needs no proof and no
/// simulation, so a wallet that hands its witness to a proving committee can fix it before
/// sharing.
///
/// # Errors
/// Returns an error if the shape cannot be built or priced.
pub fn uniform_fee(
    pool: &FramePool,
    recipient: Address,
    opts: &WithdrawalOpts,
) -> Result<U256, ChainError> {
    worst_case_fee(
        pool,
        recipient,
        &WithdrawalOpts {
            execution_limits: None,
            ..opts.clone()
        },
    )
}

/// A pool-paid withdrawal under [`Pricing::Uniform`]: the pool's default limits and
/// [`uniform_fee`], proved once. No chain is needed.
///
/// # Errors
/// Returns an error if the note is not among `leaves`, proving fails, or the shape cannot be
/// priced.
pub fn uniform_withdrawal(
    pool: &FramePool,
    note: &Note,
    leaves: &[Field],
    recipient: Address,
    opts: &WithdrawalOpts,
    rng: &mut impl CryptoRng,
) -> Result<(FrameTx, FramePoolProof), ChainError> {
    let opts = WithdrawalOpts {
        sponsor: None,
        execution_limits: None,
        pricing: Pricing::Uniform,
        ..opts.clone()
    };
    let fee = uniform_fee(pool, recipient, &opts)?;
    let proof = prove(note.clone(), leaves, recipient, pool_payer(pool, fee), rng)?;
    let tx = withdrawal_tx(pool, &proof.inputs, &proof.proof, &opts)?;
    Ok((tx, proof))
}

/// A pool-paid withdrawal under [`Pricing::Tightened`], given what each frame of the
/// default-limit shape used in a simulation: the limits [`tightened_limits`] makes of it, and the
/// worst-case fee of that shape, proved once.
///
/// # Errors
/// Returns an error if the note is not among `leaves`, proving fails, or the shape cannot be
/// priced.
pub fn tightened_withdrawal(
    pool: &FramePool,
    note: &Note,
    leaves: &[Field],
    recipient: Address,
    opts: &WithdrawalOpts,
    used: &[u64],
    rng: &mut impl CryptoRng,
) -> Result<(FrameTx, FramePoolProof), ChainError> {
    let defaults = WithdrawalOpts {
        sponsor: None,
        execution_limits: None,
        pricing: Pricing::Tightened,
        ..opts.clone()
    };
    let shape = withdrawal_tx(
        pool,
        &shape_inputs(pool, recipient),
        &Bytes::from(vec![0; 256]),
        &defaults,
    )?;
    let tightened = WithdrawalOpts {
        execution_limits: Some(tightened_limits(&shape, used)),
        ..defaults
    };
    let fee = worst_case_fee(pool, recipient, &tightened)?;
    let proof = prove(note.clone(), leaves, recipient, pool_payer(pool, fee), rng)?;
    let tx = withdrawal_tx(pool, &proof.inputs, &proof.proof, &tightened)?;
    Ok((tx, proof))
}

/// A pool-paid withdrawal of `note` to `recipient`, priced as `opts.pricing` says:
///
/// - [`Pricing::Uniform`], the default: [`uniform_withdrawal`], then one simulation to check it
///   would succeed;
/// - [`Pricing::Tightened`], `exp-frames` experiment 30's: a draft proved at the uniform fee and
///   simulated, then [`tightened_withdrawal`] from what its frames used.
///
/// The fee is the note's: with a refund pool the last frame returns what the gas did not use.
/// `opts.execution_limits` is ignored and replaced.
pub async fn priced_withdrawal<P: Provider>(
    provider: &P,
    pool: &FramePool,
    note: &Note,
    leaves: &[Field],
    recipient: Address,
    opts: &WithdrawalOpts,
    rng: &mut impl CryptoRng,
) -> Result<(FrameTx, FramePoolProof), ChainError> {
    let (draft_tx, draft) = uniform_withdrawal(pool, note, leaves, recipient, opts, rng)?;
    let sim = rpc::simulate(provider, &draft_tx, "latest").await?;
    if !sim.valid || sim.execution_status.as_deref() != Some("success") {
        return Err(ChainError::Draft(
            sim.violation
                .or(sim.execution_error)
                .unwrap_or_else(|| "no reason given".to_owned()),
        ));
    }
    match opts.pricing {
        Pricing::Uniform => Ok((draft_tx, draft)),
        Pricing::Tightened => {
            let used: Vec<u64> = sim
                .frames
                .ok_or(ChainError::Missing("the simulation returned no frames"))?
                .iter()
                .map(|f| f.gas_used.to())
                .collect();
            tightened_withdrawal(pool, note, leaves, recipient, opts, &used, rng)
        }
    }
}

fn pool_payer(pool: &FramePool, fee: U256) -> Payer {
    Payer {
        address: pool.address,
        fee,
        refund: U256::ZERO,
    }
}

/// Public inputs for pricing a shape: only the recipient and the relayer change its bytes' cost.
fn shape_inputs(pool: &FramePool, recipient: Address) -> PublicInputs {
    PublicInputs {
        root: B256::ZERO,
        nullifier_hash: B256::ZERO,
        recipient,
        relayer: pool.address,
        fee: U256::MAX,
        refund: U256::ZERO,
    }
}

/// A batch of pool-paid withdrawals from one wallet, from a keyed pool, all against the same
/// root: one per `(note, recipient)`, each priced as [`priced_withdrawal`] prices one. Each has
/// its own nullifier hash as its only nonce key, so no two share a key, and none reads the
/// pool's storage in `VERIFY`. A node that admits disjoint keys from one sender (the mempool
/// specification's `disjoint-keys`) can hold them all at once, and the wallet sends them without
/// waiting for one to be mined before the next.
///
/// Refuses a storage pool, whose withdrawals share the pool's account nonce, and two spends of
/// one note, which share a key: the second could only replace the first.
pub async fn keyed_batch<P: Provider>(
    provider: &P,
    pool: &FramePool,
    spends: &[(Note, Address)],
    leaves: &[Field],
    opts: &WithdrawalOpts,
    rng: &mut impl CryptoRng,
) -> Result<Vec<(FrameTx, FramePoolProof)>, ChainError> {
    if !pool.mode.is_keyed() {
        return Err(ChainError::Missing("a batch needs a keyed pool"));
    }
    let mut out: Vec<(FrameTx, FramePoolProof)> = Vec::with_capacity(spends.len());
    for (note, recipient) in spends {
        let (tx, proof) =
            priced_withdrawal(provider, pool, note, leaves, *recipient, opts, rng).await?;
        if out.iter().any(|(t, _)| t.nonce_keys == tx.nonce_keys) {
            return Err(ChainError::Missing(
                "two spends of one note share a nonce key: the second could only replace the first",
            ));
        }
        out.push((tx, proof));
    }
    Ok(out)
}

/// The fees `exp-frames` experiment 30 priced both withdrawals at: a 0.1 gwei tip and a 0.2 gwei
/// max fee, room for the base fee to double from a wallet's point of view.
pub const WALLET_FEES: Fees = Fees {
    max_priority_fee_per_gas: 100_000_000,
    max_fee_per_gas: 200_000_000,
    max_fee_per_blob_gas: 0,
};
