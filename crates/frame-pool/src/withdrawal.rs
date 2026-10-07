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
//! ```
//!
//! The pool's `VERIFY` reads the proof and its six public inputs out of the `SENDER` frame's
//! calldata, checks the layout above, and approves. A storage pool looks its roots and
//! nullifiers up in its own storage and uses the account nonce; a keyed pool reads no storage:
//! the nullifier hash is the transaction's EIP-8250 nonce key, which the protocol consumes, and
//! the root is checked by the EIP-8272 frame in front of it.

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_kit::{
    Fees, Frame, FrameTx,
    constants::{NEW_ACCOUNT_STATE_GAS, RECENT_ROOT, STORAGE_SET_STATE_GAS, approve},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolMode {
    /// Roots and nullifiers in the pool's storage; withdrawals serialise on the account nonce.
    Storage,
    /// The nullifier hash as an EIP-8250 nonce key and roots through EIP-8272: `VERIFY` reads no
    /// storage, so withdrawals from different notes do not conflict in the mempool.
    Keyed,
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
            PoolMode::Keyed => 0,
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
        .with_execution(10_000)
        .with_data(data)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    pub fees: Fees,
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
            fees: POOL_FEES,
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
    let keyed = pool.mode == PoolMode::Keyed;
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
                .with_execution(10_000)
                .with_state(first_use),
        );
    }
    frames.push(
        Frame::sender(Some(pool.address))
            .with_execution(WITHDRAW_EXECUTION)
            .with_state(pool.withdraw_state_floor(opts.sponsor.is_none()))
            .with_data(withdraw_calldata(inputs, proof)),
    );

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
