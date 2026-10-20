//! The registry's transactions: a deposit frame, the kernel's input for a spend, and the update.
//!
//! An update is a frame transaction with `tx.sender` = the registry and no signature, the
//! nullifiers as its EIP-8250 nonce keys in ascending order at sequence 0, and exactly
//!
//! ```text
//! (version 2 only) VERIFY  0x8141: the deadline every proof binds
//!                  VERIFY  0x8272: source_id || slot || root
//!                  VERIFY  the registry, scope 3: layout, root, keys, the app's rule, the proofs
//!                  SENDER  the registry: update(bytes32 root, uint256[15][] updates)
//! ```
//!
//! A pair of updates settles a swap: under version 2 each names the other's nullifier and change
//! note ([`pair_link`]), so neither proof is valid beside any other update.

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_kit::{
    Fees, Frame, FrameTx,
    constants::{NEW_ACCOUNT_STATE_GAS, STORAGE_SET_STATE_GAS, approve},
};
use kohaku_frame_pool::withdrawal::recent_root_frame;
use kohaku_tornadocash::{Field, merkle_tree::MerkleTree};

use crate::{
    contracts::{Registry, Version},
    note::{Note, field, tag},
};

/// The registry's interface, as `OwnedStateRegistry.yul` implements it.
pub mod abi {
    alloy::sol! {
        function deposit(address app, bytes32 inner) payable;
        function update(bytes32 root, uint256[15][] updates);
        function claim(address who);
        function republish();
        event Inserted(address indexed app, bytes32 leaf, uint32 index);
        event Updated(address indexed app, bytes32 nullifier, address recipient, uint256 withdrawn, uint256 fee);
        event RecentRoot(bytes32 root, uint64 slot);
    }
}

/// The registry's `VERIFY` budget per update: the layout, the rule and one Groth16 check
/// (229,326 at most on the testnet).
pub const VERIFY_EXECUTION: u64 = 260_000;
/// Frame 2's floors, as the registry's `VERIFY` requires them: per update, its payout and
/// event; per change note, its insertion and the root's publication.
pub const UPDATE_EXECUTION: u64 = 100_000;
pub const INSERT_EXECUTION: u64 = 1_200_000;
pub const INSERT_STATE: u64 = 2 * STORAGE_SET_STATE_GAS;
/// Version 2's prefix: the expiry frame, the recent-root frame and, for a pair, two Groth16
/// checks (454,891 on the testnet), within the testnet's 500,000.
pub const EXPIRY_EXECUTION: u64 = 5_000;
pub const RECENT_ROOT_EXECUTION_V2: u64 = 6_000;
pub const PAIR_VERIFY_EXECUTION: u64 = 480_000;

/// A deposit of `value` wei into `app`, as a `SENDER` frame of the depositor's transaction. The
/// registry's first insertion writes all 20 of the tree's slots; later ones write none.
#[must_use]
pub fn deposit_frame(
    registry: Address,
    app: Address,
    inner: Field,
    value: U256,
    first: bool,
) -> Frame {
    let data = abi::depositCall {
        app,
        inner: inner.into(),
    }
    .abi_encode();
    Frame::sender(Some(registry))
        .with_value(value)
        .with_data(data)
        .with_execution(1_200_000)
        .with_state(if first { 2_600_000 } else { 500_000 })
}

/// One update: 15 words of frame 2's data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Update {
    pub nullifier: U256,
    /// Zero when the spend leaves nothing.
    pub new_commitment: U256,
    pub tag: U256,
    pub withdrawn: U256,
    pub recipient: Address,
    /// Kept by the registry for the gas it pays.
    pub fee: U256,
    /// In a pair, what the other update is (version 1: its nullifier; version 2:
    /// [`pair_link`] of it), so that neither is valid alone; zero alone.
    pub link: U256,
    /// A.x A.y B.x1 B.x0 B.y1 B.y0 C.x C.y
    pub proof: [U256; 8],
}

impl Update {
    /// What the registry binds to the proof ([`binding`]); `deadline` under version 2.
    #[must_use]
    pub fn binding(&self, deadline: Option<u64>) -> U256 {
        binding(self.recipient, self.fee, self.link, deadline)
    }

    /// The kernel's public inputs: root, nullifier, newCommitment, tag, withdrawn, binding.
    #[must_use]
    pub fn public_inputs(&self, root: U256, deadline: Option<u64>) -> [U256; 6] {
        [
            root,
            self.nullifier,
            self.new_commitment,
            self.tag,
            self.withdrawn,
            self.binding(deadline),
        ]
    }

    #[must_use]
    pub fn words(&self) -> [U256; 15] {
        let mut w = [U256::ZERO; 15];
        w[..7].copy_from_slice(&[
            self.nullifier,
            self.new_commitment,
            self.tag,
            self.withdrawn,
            U256::from_be_slice(self.recipient.as_slice()),
            self.fee,
            self.link,
        ]);
        w[7..].copy_from_slice(&self.proof);
        w
    }

    #[must_use]
    pub fn from_words(w: &[U256; 15]) -> Self {
        let mut proof = [U256::ZERO; 8];
        proof.copy_from_slice(&w[7..]);
        Self {
            nullifier: w[0],
            new_commitment: w[1],
            tag: w[2],
            withdrawn: w[3],
            recipient: Address::from_word(w[4].into()),
            fee: w[5],
            link: w[6],
            proof,
        }
    }
}

/// `keccak256(recipient || fee || link) >> 8` (version 1), or
/// `keccak256(recipient || fee || link || deadline) >> 8` (version 2), the words as 32 bytes.
#[must_use]
pub fn binding(recipient: Address, fee: U256, link: U256, deadline: Option<u64>) -> U256 {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&[0u8; 12]);
    buf.extend_from_slice(recipient.as_slice());
    buf.extend_from_slice(&fee.to_be_bytes::<32>());
    buf.extend_from_slice(&link.to_be_bytes::<32>());
    if let Some(d) = deadline {
        buf.extend_from_slice(&U256::from(d).to_be_bytes::<32>());
    }
    U256::from_be_bytes(keccak256(buf).0) >> 8
}

/// Version 2's link to the other update of a pair: `keccak256(nullifier || newCommitment)`.
#[must_use]
pub fn pair_link(nullifier: U256, new_commitment: U256) -> U256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&nullifier.to_be_bytes::<32>());
    buf[32..].copy_from_slice(&new_commitment.to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(buf).0)
}

/// Frame 2's data.
#[must_use]
pub fn update_calldata(root: U256, updates: &[Update]) -> Bytes {
    abi::updateCall {
        root: root.into(),
        updates: updates.iter().map(Update::words).collect(),
    }
    .abi_encode()
    .into()
}

/// What frame 2 of an update carried.
pub fn decode_update(data: &[u8]) -> Result<(U256, Vec<Update>), UpdateError> {
    let call = abi::updateCall::abi_decode(data).map_err(|_| UpdateError::Calldata)?;
    Ok((
        call.root.into(),
        call.updates.iter().map(Update::from_words).collect(),
    ))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UpdateError {
    #[error("the registry takes one update or a pair, not {0}")]
    Count(usize),
    #[error("the nullifiers must be strictly ascending: they are the nonce keys")]
    Order,
    #[error("a pair's updates must link to each other, a single one to nothing")]
    Link,
    #[error("version 2 takes a deadline, version 1 none")]
    Deadline,
    #[error("an update's fee is above what it withdraws")]
    Fee,
    #[error("not an update(bytes32,uint256[15][]) call")]
    Calldata,
}

/// The update, as the registry's `VERIFY` requires it, with `deadline` for version 2. It
/// refuses what that `VERIFY` would refuse for its shape, including a pair that does not link;
/// the proofs and the rules are the registry's to check.
pub fn update_tx(
    registry: &Registry,
    chain_id: u64,
    root: U256,
    slot: u64,
    deadline: Option<u64>,
    updates: &[Update],
    fees: Fees,
) -> Result<FrameTx, UpdateError> {
    let k = updates.len();
    if !(1..=2).contains(&k) {
        return Err(UpdateError::Count(k));
    }
    if (registry.version == Version::V2) != deadline.is_some() {
        return Err(UpdateError::Deadline);
    }
    if updates.windows(2).any(|w| w[0].nullifier >= w[1].nullifier) {
        return Err(UpdateError::Order);
    }
    let names = |u: &Update, other: &Update| match registry.version {
        Version::V1 => u.link == other.nullifier,
        Version::V2 => u.link == pair_link(other.nullifier, other.new_commitment),
    };
    let linked = match updates {
        [one] => one.link.is_zero(),
        [a, b] => names(a, b) && names(b, a),
        _ => false,
    };
    if !linked {
        return Err(UpdateError::Link);
    }
    if updates.iter().any(|u| u.fee > u.withdrawn) {
        return Err(UpdateError::Fee);
    }
    let inserts = updates
        .iter()
        .filter(|u| !u.new_commitment.is_zero())
        .count() as u64;
    let payouts = updates.iter().filter(|u| u.withdrawn > u.fee).count() as u64;
    let k = k as u64;
    let source_id = registry.source_id();
    let (prefix, verify) = match deadline {
        None => (
            vec![recent_root_frame(source_id, slot, root.into())],
            VERIFY_EXECUTION * k,
        ),
        Some(d) => (
            vec![
                Frame::expiry(d).with_execution(EXPIRY_EXECUTION),
                recent_root_frame(source_id, slot, root.into())
                    .with_execution(RECENT_ROOT_EXECUTION_V2),
            ],
            if k == 1 {
                VERIFY_EXECUTION
            } else {
                PAIR_VERIFY_EXECUTION
            },
        ),
    };
    let mut frames = prefix;
    frames.extend([
        // The first use of each nonce key is paid by the frame that approves payment.
        Frame::verify(approve::EXECUTION_AND_PAYMENT, None)
            .with_execution(verify)
            .with_state(STORAGE_SET_STATE_GAS * k),
        Frame::sender(Some(registry.address()))
            .with_data(update_calldata(root, updates))
            .with_execution(UPDATE_EXECUTION * k + INSERT_EXECUTION * inserts)
            .with_state(NEW_ACCOUNT_STATE_GAS * payouts + INSERT_STATE * inserts),
    ]);
    Ok(FrameTx {
        chain_id,
        nonce_keys: updates.iter().map(|u| u.nullifier).collect(),
        nonce_seq: 0,
        sender: registry.address(),
        frames,
        signatures: vec![],
        fees,
        blob_versioned_hashes: vec![],
    })
}

/// A spend of a note, as its owner decides it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spend {
    pub note: Note,
    /// The note's leaf index in the registry's tree.
    pub index: usize,
    pub withdrawn: u64,
    /// The change note's owner's `inner`, or none when nothing is left.
    pub new_inner: Option<Field>,
    pub recipient: Address,
    pub fee: U256,
    pub link: U256,
    /// Version 2: the deadline the proof binds.
    pub deadline: Option<u64>,
}

/// The kernel circuit's input for a spend, the signals as `kernel.circom` names them: what a
/// circom prover takes to prove it. The first six are public.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelInput {
    pub root: Field,
    pub nullifier: Field,
    pub new_commitment: Field,
    pub tag: Field,
    pub withdrawn: u64,
    pub binding: U256,
    pub nullifier_secret: Field,
    pub secret: Field,
    pub state: u64,
    pub new_inner: Field,
    pub path_elements: [Field; 20],
    pub path_indices: [u8; 20],
}

#[derive(Debug, thiserror::Error)]
pub enum SpendError {
    #[error("the spend takes out more than the note holds")]
    Overdrawn,
    #[error("something is left, so the spend needs a change note")]
    NoChange,
    #[error("the note's leaf is not at that index of the tree")]
    NotInTree,
    #[error(transparent)]
    Tree(#[from] kohaku_merkle_tree::MerkleTreeError),
}

impl Spend {
    /// The kernel's input against `leaves`, the registry's tree in insertion order.
    pub fn kernel_input(&self, leaves: &[Field]) -> Result<KernelInput, SpendError> {
        let new_state = self
            .note
            .state
            .checked_sub(self.withdrawn)
            .ok_or(SpendError::Overdrawn)?;
        if new_state > 0 && self.new_inner.is_none() {
            return Err(SpendError::NoChange);
        }
        let tree = MerkleTree::from_leaves(leaves)?;
        let proof = tree.proof(self.index)?;
        if proof.leaf != self.note.leaf() {
            return Err(SpendError::NotInTree);
        }
        let new_commitment = self.new_inner.map_or(Field::default(), |inner| {
            crate::note::leaf(self.note.app, inner, new_state)
        });
        Ok(KernelInput {
            root: proof.root,
            nullifier: self.note.nullifier(),
            new_commitment,
            tag: tag(self.note.app),
            withdrawn: self.withdrawn,
            binding: binding(self.recipient, self.fee, self.link, self.deadline),
            nullifier_secret: self.note.secrets.nullifier_secret,
            secret: self.note.secrets.secret,
            state: self.note.state,
            new_inner: self.new_inner.unwrap_or_default(),
            path_elements: proof.sibling_paths(),
            path_indices: proof.path,
        })
    }

    /// The update this spend becomes once proven.
    #[must_use]
    pub fn update(&self, input: &KernelInput, proof: [U256; 8]) -> Update {
        Update {
            nullifier: input.nullifier.into(),
            new_commitment: input.new_commitment.into(),
            tag: input.tag.into(),
            withdrawn: U256::from(self.withdrawn),
            recipient: self.recipient,
            fee: self.fee,
            link: self.link,
            proof,
        }
    }
}

/// The registry's root after `leaves`, as the kernel proves against it.
pub fn root_of(leaves: &[Field]) -> Result<B256, kohaku_merkle_tree::MerkleTreeError> {
    Ok(MerkleTree::from_leaves(leaves)?.root()?.into())
}

/// A field element from a 32-byte word of the chain, reduced.
#[must_use]
pub fn word_field(w: B256) -> Field {
    field(U256::from_be_bytes(w.0))
}
