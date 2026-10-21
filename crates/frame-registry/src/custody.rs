//! The vaulted registry of `exp-frames` experiment 40: each application's value in a vault of
//! its own, the vault bound into what a withdrawal proves, and the withdrawal bound to whom it
//! pays and on what fee terms.
//!
//! ```text
//! params  = SHA-256(0x90 || kind || amount)                                 a vault's parameters
//! scope   = SHA-256(0x91 || params || uint64be(chain id) || vault) mod p   in the kernel's tag's place
//! leaf    = H(scope, inner, state)        nullifier = H(scope, nullifierSecret)
//! context = SHA-256(0x61 || recipient || fee || max_priority_fee_per_gas || max_fee_per_gas) >> 8
//! ```
//!
//! The kernel and its key are experiment 32's: the scope is its `tag` and the context its
//! `binding`. The registry computes the scope from the vault's address, so no two vaults share
//! one, and computes the context from the transaction's own fees in `VERIFY`, so a pending update
//! cannot be sent again with other fees. Frame 2 pays the recipient and the registry's fee from
//! the vault the scope was computed for.

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_accounts::contracts::{create2_address, deploy_frame, word};
use kohaku_frame_kit::{
    Fees, Frame, FrameTx,
    constants::{NEW_ACCOUNT_STATE_GAS, STORAGE_SET_STATE_GAS, approve},
};
use kohaku_frame_pool::withdrawal::recent_root_frame;
use kohaku_tornadocash::{Field, mimc_sponge};
use sha2::{Digest, Sha256};

use crate::note::{Secrets, field};

fn code(hex_code: &str) -> Vec<u8> {
    hex::decode(hex_code.trim()).expect("embedded creation code is hex")
}

/// `VaultedRegistry.yul`. Initcode: code `||` hasher `||` verifier `||` root salt.
#[must_use]
pub fn registry_code() -> Vec<u8> {
    code(include_str!("../contracts/VaultedRegistry.hex"))
}

/// `Vault.yul`. Initcode: code `||` registry `||` kind `||` amount.
#[must_use]
pub fn vault_code() -> Vec<u8> {
    code(include_str!("../contracts/Vault.hex"))
}

/// The registry's interface, as `VaultedRegistry.yul` implements it.
pub mod abi {
    alloy::sol! {
        function deposit(address vault, bytes32 inner) payable;
        function update(bytes32 root, uint256[15][] updates);
        function scopeOf(address vault) view returns (uint256);
        event Inserted(address indexed vault, bytes32 leaf, uint32 index);
        event Updated(address indexed vault, bytes32 nullifier, address recipient, uint256 withdrawn, uint256 fee);
    }
}

/// A `VaultedRegistry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultedRegistry {
    pub hasher: Address,
    pub verifier: Address,
    pub root_salt: B256,
    pub salt: B256,
}

impl VaultedRegistry {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut c = registry_code();
        c.extend_from_slice(&word(self.hasher));
        c.extend_from_slice(&word(self.verifier));
        c.extend_from_slice(self.root_salt.as_slice());
        c
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }

    /// `keccak256(registry || root_salt)`: the EIP-8272 source id of its roots.
    #[must_use]
    pub fn source_id(&self) -> B256 {
        let mut buf = [0u8; 52];
        buf[..20].copy_from_slice(self.address().as_slice());
        buf[20..].copy_from_slice(self.root_salt.as_slice());
        keccak256(buf)
    }
}

/// A vault's rule, `Vault.yul`'s `kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Experiment 32's `FixedPool`: a deposit of exactly `amount`, spent whole.
    Fixed,
    /// Experiment 32's `Balance`: any deposit below 2^64, at most `amount` out per withdrawal.
    Balance,
}

/// An application's vault: its custody, rule and parameters, for one registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vault {
    pub registry: Address,
    pub kind: Kind,
    pub amount: U256,
    pub salt: B256,
}

impl Vault {
    fn kind_word(&self) -> U256 {
        U256::from(match self.kind {
            Kind::Fixed => 0u8,
            Kind::Balance => 1u8,
        })
    }

    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut c = vault_code();
        c.extend_from_slice(&word(self.registry));
        c.extend_from_slice(&self.kind_word().to_be_bytes::<32>());
        c.extend_from_slice(&self.amount.to_be_bytes::<32>());
        c
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }

    /// `SHA-256(0x90 || kind || amount)`, as the vault's `params()` returns it.
    #[must_use]
    pub fn params(&self) -> B256 {
        let mut h = Sha256::new();
        h.update([0x90]);
        h.update(self.kind_word().to_be_bytes::<32>());
        h.update(self.amount.to_be_bytes::<32>());
        B256::from_slice(&h.finalize())
    }

    /// `SHA-256(0x91 || params || uint64be(chain id) || vault) mod p`.
    #[must_use]
    pub fn scope(&self, chain_id: u64) -> Field {
        let mut h = Sha256::new();
        h.update([0x91]);
        h.update(self.params());
        h.update(chain_id.to_be_bytes());
        h.update(self.address());
        field(U256::from_be_slice(&h.finalize()))
    }
}

/// A note's leaf under a scope.
#[must_use]
pub fn leaf(scope: Field, inner: Field, state: u64) -> Field {
    mimc_sponge(&[scope, inner, field(U256::from(state))])
}

/// A note's nullifier under a scope.
#[must_use]
pub fn nullifier(scope: Field, secrets: &Secrets) -> Field {
    mimc_sponge(&[scope, secrets.nullifier_secret])
}

/// `SHA-256(0x61 || recipient || fee || max_priority_fee_per_gas || max_fee_per_gas) >> 8`.
#[must_use]
pub fn context(recipient: Address, fee: U256, fees: &Fees) -> U256 {
    let mut h = Sha256::new();
    h.update([0x61]);
    h.update(word(recipient));
    h.update(fee.to_be_bytes::<32>());
    h.update(U256::from(fees.max_priority_fee_per_gas).to_be_bytes::<32>());
    h.update(U256::from(fees.max_fee_per_gas).to_be_bytes::<32>());
    U256::from_be_slice(&h.finalize()) >> 8
}

/// One update: 15 words of frame 2's data, the vault in experiment 32's tag's place and no link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyUpdate {
    pub nullifier: U256,
    /// Zero when the spend leaves nothing.
    pub new_commitment: U256,
    pub vault: Address,
    pub withdrawn: U256,
    pub recipient: Address,
    /// Paid to the registry from the vault, for the gas it pays.
    pub fee: U256,
    /// A.x A.y B.x1 B.x0 B.y1 B.y0 C.x C.y
    pub proof: [U256; 8],
}

impl CustodyUpdate {
    #[must_use]
    pub fn words(&self) -> [U256; 15] {
        let mut w = [U256::ZERO; 15];
        w[..6].copy_from_slice(&[
            self.nullifier,
            self.new_commitment,
            U256::from_be_slice(self.vault.as_slice()),
            self.withdrawn,
            U256::from_be_slice(self.recipient.as_slice()),
            self.fee,
        ]);
        w[7..].copy_from_slice(&self.proof);
        w
    }

    /// From frame 2's words, refusing a link: the vaulted registry takes no pairs.
    #[must_use]
    pub fn from_words(w: &[U256; 15]) -> Option<Self> {
        if !w[6].is_zero() {
            return None;
        }
        let mut proof = [U256::ZERO; 8];
        proof.copy_from_slice(&w[7..]);
        Some(Self {
            nullifier: w[0],
            new_commitment: w[1],
            vault: Address::from_word(w[2].into()),
            withdrawn: w[3],
            recipient: Address::from_word(w[4].into()),
            fee: w[5],
            proof,
        })
    }

    /// The kernel's public inputs: root, nullifier, newCommitment, the vault's scope, withdrawn,
    /// and the context for these fees.
    #[must_use]
    pub fn public_inputs(&self, root: U256, scope: Field, fees: &Fees) -> [U256; 6] {
        [
            root,
            self.nullifier,
            self.new_commitment,
            scope.into(),
            self.withdrawn,
            context(self.recipient, self.fee, fees),
        ]
    }
}

/// The registry's `VERIFY` budget: experiment 32's, the vault's rule and parameters, and two
/// SHA-256 calls (230,370 at most on the testnet).
pub const VERIFY_EXECUTION: u64 = 290_000;
/// Frame 2's floors, as the registry's `VERIFY` requires them.
pub const UPDATE_EXECUTION: u64 = 150_000;
pub const INSERT_EXECUTION: u64 = 1_200_000;
pub const INSERT_STATE: u64 = 2 * STORAGE_SET_STATE_GAS;

/// Frame 2's data.
#[must_use]
pub fn update_calldata(root: U256, update: &CustodyUpdate) -> Bytes {
    crate::update::abi::updateCall {
        root: root.into(),
        updates: vec![update.words()],
    }
    .abi_encode()
    .into()
}

/// What frame 2 of an update carried: its root and its one update.
#[must_use]
pub fn decode_update(data: &[u8]) -> Option<(U256, CustodyUpdate)> {
    let call = crate::update::abi::updateCall::abi_decode(data).ok()?;
    match call.updates.as_slice() {
        [one] => Some((call.root.into(), CustodyUpdate::from_words(one)?)),
        _ => None,
    }
}

/// A deposit of `value` wei into `vault`, as a `SENDER` frame of the depositor's transaction.
#[must_use]
pub fn deposit_frame(
    registry: Address,
    vault: Address,
    inner: Field,
    value: U256,
    first: bool,
) -> Frame {
    let data = abi::depositCall {
        vault,
        inner: inner.into(),
    }
    .abi_encode();
    Frame::sender(Some(registry))
        .with_value(value)
        .with_data(data)
        .with_execution(1_300_000)
        .with_state(if first { 2_600_000 } else { 500_000 })
}

/// The update, laid out as the registry's `VERIFY` requires: no signature, the nullifier as the
/// one nonce key at sequence 0, and `fees` the ones its proof's context was made for.
#[must_use]
pub fn update_tx(
    registry: &VaultedRegistry,
    chain_id: u64,
    root: U256,
    slot: u64,
    update: &CustodyUpdate,
    fees: Fees,
) -> FrameTx {
    let insert = u64::from(!update.new_commitment.is_zero());
    let payout = u64::from(update.withdrawn > update.fee);
    FrameTx {
        chain_id,
        nonce_keys: vec![update.nullifier],
        nonce_seq: 0,
        sender: registry.address(),
        frames: vec![
            recent_root_frame(registry.source_id(), slot, root.into()),
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None)
                .with_execution(VERIFY_EXECUTION)
                .with_state(STORAGE_SET_STATE_GAS),
            Frame::sender(Some(registry.address()))
                .with_data(update_calldata(root, update))
                .with_execution(UPDATE_EXECUTION + INSERT_EXECUTION * insert)
                .with_state(NEW_ACCOUNT_STATE_GAS * payout + INSERT_STATE * insert),
        ],
        signatures: vec![],
        fees,
        blob_versioned_hashes: vec![],
    }
}
