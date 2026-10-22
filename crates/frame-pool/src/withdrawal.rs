//! The withdrawal transaction: `tx.sender` is the pool, and the proof is the authorisation.
//!
//! ```text
//!                 pool pays                     sponsor pays
//! storage pool    VERIFY(pool, 3)               VERIFY(pool, 2)
//!                 SENDER(pool, withdraw)        VERIFY(sponsor, 1)
//!                                               SENDER(pool, withdraw)
//! keyed pool      VERIFY(0x8272, root tuple)    VERIFY(0x8272, root tuple)
//!                 VERIFY(pool, 3)               VERIFY(pool, 2)
//!                 SENDER(pool, withdraw)        VERIFY(sponsor, 1)
//!                                               SENDER(pool, withdraw)
//! refund pool     VERIFY(0x8272, root tuple)    -
//!                 VERIFY(pool, 3)
//!                 SENDER(pool, withdraw)
//!                 DEFAULT(pool), the refund
//! ```
//!
//! The pool's `VERIFY` reads the proof and its six public inputs out of the `SENDER` frame's
//! calldata, checks the layout above, and approves. A storage pool looks its roots and
//! nullifiers up in its own storage and uses the account nonce; a keyed pool reads no storage:
//! the nullifier hash is the transaction's EIP-8250 nonce key, which the protocol consumes, and
//! the root is checked by the EIP-8272 frame in front of it.
//!
//! A refund pool is a keyed pool that always pays its own gas and adds a last `DEFAULT` frame.
//! The note's fee must cover the transaction's max cost, which is every limit at the max fee, and
//! the chain charges what was used at the price paid. The last frame sends the recipient the fee
//! less an upper bound on that charge, so the note pays about its gas and not its max cost
//! (`exp-frames` experiment 30, `RefundPool.yul`).

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_kit::{
    Fees, Frame, FrameTx,
    constants::{NEW_ACCOUNT_STATE_GAS, RECENT_ROOT, STORAGE_SET_STATE_GAS, approve, mode},
    gas::{UnknownScheme, max_cost},
};

use crate::PublicInputs;

/// The pool's interface, as `FramePool.yul` in `exp-frames` (experiment 06) implements it.
pub mod abi {
    alloy::sol! {
        function deposit(bytes32 commitment) payable;
        function withdraw(
            bytes proof,
            bytes32 root,
            bytes32 nullifierHash,
            address recipient,
            address relayer,
            uint256 fee,
            uint256 refund
        );
        event Deposit(bytes32 indexed commitment, uint32 leafIndex, uint256 timestamp);
        event Withdrawal(address to, bytes32 nullifierHash, address indexed relayer, uint256 fee);
        event RecentRoot(bytes32 root, uint64 slot);
        /// A refund pool's last frame: what it sent back, and its bound on the charge.
        event FeeRefund(address indexed recipient, uint256 refunded, uint256 chargedAtMost);
    }
}

/// The pool's deposit, in wei, on the testnet deployment.
pub const DENOMINATION: u128 = 1_000_000_000_000_000;

/// The testnet's base fee is 7 wei: a 1 wei tip under a 100 wei cap is plenty.
pub const POOL_FEES: Fees = Fees {
    max_priority_fee_per_gas: 1,
    max_fee_per_gas: 100,
    max_fee_per_blob_gas: 0,
};

/// Execution gas for the withdrawal frame, and the minimum the pool accepts.
pub const WITHDRAW_EXECUTION: u64 = 100_000;
/// Execution gas for the pool's `VERIFY`: a Groth16 check is about 245,000.
pub const VERIFY_EXECUTION: u64 = 400_000;
/// Execution gas for the EIP-8272 verifier frame.
pub const RECENT_ROOT_EXECUTION: u64 = 10_000;
/// Execution gas for a sponsor's `VERIFY`.
pub const SPONSOR_EXECUTION: u64 = 10_000;
/// Execution gas for a refund pool's last frame before it is tightened.
pub const REFUND_EXECUTION: u64 = 50_000;
/// The least execution gas a refund pool accepts for its last frame (`POST_OP_GAS`).
pub const REFUND_EXECUTION_FLOOR: u64 = 25_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolMode {
    /// Roots and nullifiers in the pool's storage; withdrawals serialise on the account nonce.
    Storage,
    /// The nullifier hash as an EIP-8250 nonce key and roots through EIP-8272: `VERIFY` reads no
    /// storage, so withdrawals from different notes do not conflict in the mempool.
    Keyed,
    /// A keyed pool that pays its own gas and refunds the fee's surplus in a last `DEFAULT`
    /// frame: `RefundPool.yul`, `exp-frames` experiment 30.
    Refund,
}

impl PoolMode {
    /// Whether the nullifier hash is the nonce key and the root goes through EIP-8272.
    #[must_use]
    pub fn is_keyed(self) -> bool {
        matches!(self, Self::Keyed | Self::Refund)
    }
}

/// A deployed frame-native pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramePool {
    pub address: Address,
    pub mode: PoolMode,
    /// The EIP-8272 salt a keyed pool files its roots under.
    pub salt: B256,
}

impl FramePool {
    /// The EIP-8272 source id of this pool's roots: `keccak256(pool || salt)`.
    #[must_use]
    pub fn source_id(&self) -> B256 {
        let mut buf = [0u8; 52];
        buf[..20].copy_from_slice(self.address.as_slice());
        buf[20..].copy_from_slice(self.salt.as_slice());
        keccak256(buf)
    }

    /// The state gas the pool requires the withdrawal frame to carry: the recipient's account,
    /// the nullifier slot in a storage pool, and the relayer's credit when the relayer is not
    /// the pool.
    #[must_use]
    pub fn withdraw_state_floor(&self, relayer_is_pool: bool) -> u64 {
        let nullifier = match self.mode {
            PoolMode::Storage => STORAGE_SET_STATE_GAS,
            PoolMode::Keyed | PoolMode::Refund => 0,
        };
        let credit = if relayer_is_pool {
            0
        } else {
            STORAGE_SET_STATE_GAS
        };
        NEW_ACCOUNT_STATE_GAS + nullifier + credit
    }
}

/// `withdraw(proof, root, nullifierHash, recipient, relayer, fee, refund)`.
#[must_use]
pub fn withdraw_calldata(inputs: &PublicInputs, proof: &Bytes) -> Bytes {
    abi::withdrawCall {
        proof: proof.clone(),
        root: inputs.root,
        nullifierHash: inputs.nullifier_hash,
        recipient: inputs.recipient,
        relayer: inputs.relayer,
        fee: inputs.fee,
        refund: inputs.refund,
    }
    .abi_encode()
    .into()
}

/// The EIP-8272 verifier frame for one `(source_id, slot, root)` tuple.
#[must_use]
pub fn recent_root_frame(source_id: B256, slot: u64, root: B256) -> Frame {
    let mut data = Vec::with_capacity(72);
    data.extend_from_slice(source_id.as_slice());
    data.extend_from_slice(&slot.to_be_bytes());
    data.extend_from_slice(root.as_slice());
    Frame::verify(approve::NONE, Some(RECENT_ROOT))
        .with_execution(RECENT_ROOT_EXECUTION)
        .with_data(data)
}

/// The least execution gas the pool accepts for `frame`: the withdrawal frame's floor, so that
/// nobody can starve it after approval, and a refund frame's.
#[must_use]
pub fn execution_floor(frame: &Frame) -> u64 {
    match frame.mode {
        mode::SENDER => WITHDRAW_EXECUTION,
        mode::DEFAULT => REFUND_EXECUTION_FLOOR,
        _ => 0,
    }
}

/// Execution limits from a simulation's per-frame use, as `exp-frames` experiment 28's wallet
/// sets them: a quarter over the use plus 5,000, never below the pool's floor for the frame.
#[must_use]
pub fn tightened_limits(tx: &FrameTx, used: &[u64]) -> Vec<u64> {
    tx.frames
        .iter()
        .zip(used)
        .map(|(f, &u)| (u * 5 / 4 + 5_000).max(execution_floor(f)))
        .collect()
}

/// The max cost of `tx` with every byte of every frame's data and of every nonce key non-zero.
///
/// A note's fee is fixed when the proof is made, and the proof's bytes are part of the calldata
/// the fee must cover. Pricing the worst case lets the fee be chosen before the proof exists.
pub fn worst_case_max_cost(tx: &FrameTx) -> Result<U256, UnknownScheme> {
    let mut worst = tx.clone();
    for f in &mut worst.frames {
        f.data = vec![0xff; f.data.len()].into();
    }
    for k in &mut worst.nonce_keys {
        *k = U256::MAX;
    }
    max_cost(&worst, 0)
}

/// How a pool-paid withdrawal's execution limits and fee are set ([`crate::chain::priced_withdrawal`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Pricing {
    /// The pool's default limits, unchanged, and the worst-case fee at them
    /// ([`crate::chain::uniform_fee`]). Nothing in it depends on this withdrawal, so it needs no
    /// draft proof: a wallet that proves for itself and one that hands its witness to a committee
    /// build the same limits and the same fee, and a node cannot tell the two apart by them. With
    /// a refund pool the last frame returns what the gas did not use; elsewhere the note pays the
    /// surplus.
    #[default]
    Uniform,
    /// `exp-frames` experiment 30's: prove a draft at the uniform fee, simulate it, tighten each
    /// frame's limit to a quarter over its use plus 5,000 ([`tightened_limits`]), and fix the fee
    /// at the worst case of that shape. The fee is lower, but the limits and the fee follow this
    /// withdrawal's simulation, and only a wallet that can prove a draft can set them.
    Tightened,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalOpts {
    pub chain_id: u64,
    /// `None`: the pool pays the gas out of the fee. `Some`: a `PoolSponsor` at this address
    /// pays, and is paid the fee.
    pub sponsor: Option<Address>,
    /// Keyed pools: the slot the root was published in.
    pub root_slot: Option<u64>,
    /// Storage pools: the pool's account nonce.
    pub nonce: Option<u64>,
    pub verify_execution: u64,
    /// Every frame's execution limit, in layout order, in place of the defaults; usually
    /// [`tightened_limits`] of a simulation. Each must meet [`execution_floor`].
    pub execution_limits: Option<Vec<u64>>,
    pub fees: Fees,
    /// How [`crate::chain::priced_withdrawal`] sets the limits and the fee; [`Pricing::Uniform`]
    /// unless chosen.
    pub pricing: Pricing,
}

impl WithdrawalOpts {
    #[must_use]
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            sponsor: None,
            root_slot: None,
            nonce: None,
            verify_execution: VERIFY_EXECUTION,
            execution_limits: None,
            fees: POOL_FEES,
            pricing: Pricing::Uniform,
        }
    }
}

/// What the pool's `VERIFY` would refuse, caught before a transaction is built.
#[derive(Debug, thiserror::Error)]
pub enum WithdrawalTxError {
    #[error("the proof names relayer {proof}, but {payer} is paying")]
    Relayer { proof: Address, payer: Address },
    #[error("the pool requires a zero refund")]
    Refund,
    #[error("a keyed withdrawal needs the slot its root was published in")]
    MissingSlot,
    #[error("a storage-pool withdrawal needs the pool's nonce")]
    MissingNonce,
    #[error("a refund pool pays its own gas and takes no sponsor")]
    SponsoredRefund,
    #[error("{limits} execution limits for {frames} frames")]
    Limits { frames: usize, limits: usize },
    #[error("frame {frame}: execution limit {limit} is below the pool's floor {floor}")]
    BelowFloor {
        frame: usize,
        limit: u64,
        floor: u64,
    },
    #[error("fee {fee} is below the transaction's max cost {max_cost}")]
    Fee { fee: U256, max_cost: U256 },
    #[error(transparent)]
    Gas(#[from] UnknownScheme),
}

/// The withdrawal laid out as the pool's `VERIFY` requires it. There are no signatures.
///
/// The proof binds the relayer and the fee, so they are decided before proving: the relayer is
/// the pool when the pool pays and the sponsor when a sponsor does, and the fee must cover the
/// transaction's `max_cost` either way.
pub fn withdrawal_tx(
    pool: &FramePool,
    inputs: &PublicInputs,
    proof: &Bytes,
    opts: &WithdrawalOpts,
) -> Result<FrameTx, WithdrawalTxError> {
    let payer = opts.sponsor.unwrap_or(pool.address);
    if inputs.relayer != payer {
        return Err(WithdrawalTxError::Relayer {
            proof: inputs.relayer,
            payer,
        });
    }
    if !inputs.refund.is_zero() {
        return Err(WithdrawalTxError::Refund);
    }
    let refunds = pool.mode == PoolMode::Refund;
    if refunds && opts.sponsor.is_some() {
        return Err(WithdrawalTxError::SponsoredRefund);
    }
    let keyed = pool.mode.is_keyed();
    // EIP-8250 charges the first use of a nonce key to whichever frame approves payment.
    let first_use = if keyed { STORAGE_SET_STATE_GAS } else { 0 };

    let mut frames = Vec::with_capacity(4);
    if keyed {
        let slot = opts.root_slot.ok_or(WithdrawalTxError::MissingSlot)?;
        frames.push(recent_root_frame(pool.source_id(), slot, inputs.root));
    }
    let (scope, verify_state) = match opts.sponsor {
        None => (approve::EXECUTION_AND_PAYMENT, first_use),
        Some(_) => (approve::EXECUTION, 0),
    };
    frames.push(
        Frame::verify(scope, None)
            .with_execution(opts.verify_execution)
            .with_state(verify_state),
    );
    if let Some(sponsor) = opts.sponsor {
        frames.push(
            Frame::verify(approve::PAYMENT, Some(sponsor))
                .with_execution(SPONSOR_EXECUTION)
                .with_state(first_use),
        );
    }
    frames.push(
        Frame::sender(Some(pool.address))
            .with_execution(WITHDRAW_EXECUTION)
            .with_state(pool.withdraw_state_floor(opts.sponsor.is_none()))
            .with_data(withdraw_calldata(inputs, proof)),
    );
    if refunds {
        frames.push(Frame::entry_point(Some(pool.address)).with_execution(REFUND_EXECUTION));
    }
    if let Some(limits) = &opts.execution_limits {
        if limits.len() != frames.len() {
            return Err(WithdrawalTxError::Limits {
                frames: frames.len(),
                limits: limits.len(),
            });
        }
        for (i, (f, &limit)) in frames.iter_mut().zip(limits).enumerate() {
            let floor = execution_floor(f);
            if limit < floor {
                return Err(WithdrawalTxError::BelowFloor {
                    frame: i,
                    limit,
                    floor,
                });
            }
            f.limits.execution = limit;
        }
    }

    let (nonce_keys, nonce_seq) = if keyed {
        (vec![U256::from_be_bytes(inputs.nullifier_hash.0)], 0)
    } else {
        (
            vec![U256::ZERO],
            opts.nonce.ok_or(WithdrawalTxError::MissingNonce)?,
        )
    };
    let tx = FrameTx {
        chain_id: opts.chain_id,
        nonce_keys,
        nonce_seq,
        sender: pool.address,
        frames,
        signatures: vec![],
        fees: opts.fees,
        blob_versioned_hashes: vec![],
    };
    let max_cost = max_cost(&tx, 0)?;
    if inputs.fee < max_cost {
        return Err(WithdrawalTxError::Fee {
            fee: inputs.fee,
            max_cost,
        });
    }
    Ok(tx)
}
