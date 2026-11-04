//! `SphincsAccount.yul` and `SphincsSender.yul`: accounts a leanSPHINCS key authorises through an
//! EIP-8288 dependency. The `.hex` files beside the sources are their creation code as solc
//! 0.8.37 compiles them (EVM version osaka, optimizer on, 200 runs).
//!
//! Where the triple travels is fixed at deployment ([`Carrier`]), so that an account on a chain
//! with EIP-8288 never accepts a triple that nothing proves.

use alloy::primitives::{Address, B256, U256};
use kohaku_frame_accounts::contracts::{create2_address, deploy_frame, self_deploy_frame};
use kohaku_frame_accounts::account::FrameAccount;
use kohaku_frame_kit::{
    Frame, FrameSignature, FrameTx,
    constants::{CPSB, approve},
};

use crate::{PqError, SphincsKey, TRIPLE_LEN, dependency_frame, verify as verify_signature};

/// Where an account looks for its key's triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Carrier {
    /// In a dependency frame (mode 4), which the block's proof covers.
    Dependency,
    /// In the account's own `VERIFY` data, for a chain without EIP-8288: nothing on chain checks
    /// the signature.
    Modelled,
}

impl Carrier {
    fn flag(self) -> u8 {
        u8::from(self == Carrier::Modelled)
    }
}

/// What a fresh slot costs in state gas.
pub const FRESH_SLOT_STATE_GAS: u64 = 64 * CPSB;

fn code(hex_code: &str) -> Vec<u8> {
    hex::decode(hex_code.trim()).expect("embedded creation code is hex")
}

/// `SphincsAccount.yul`'s creation code, without its arguments.
#[must_use]
pub fn sphincs_account_code() -> Vec<u8> {
    code(include_str!("../contracts/SphincsAccount.hex"))
}

/// `SphincsSender.yul`'s creation code, without its arguments.
#[must_use]
pub fn sphincs_sender_code() -> Vec<u8> {
    code(include_str!("../contracts/SphincsSender.hex"))
}

/// The recovery commitment: `keccak256(salt || m || n || keys)`, the keys ascending.
#[must_use]
pub fn commitment(salt: B256, m: u8, keys: &[B256]) -> B256 {
    alloy::primitives::keccak256(recovery_body(salt, m, keys))
}

fn recovery_body(salt: B256, m: u8, keys: &[B256]) -> Vec<u8> {
    let mut sorted = keys.to_vec();
    sorted.sort();
    let mut b = Vec::with_capacity(34 + 32 * keys.len());
    b.extend_from_slice(salt.as_slice());
    b.push(m);
    b.push(u8::try_from(keys.len()).expect("at most 255 keys"));
    for k in &sorted {
        b.extend_from_slice(k.as_slice());
    }
    b
}

/// A `SphincsAccount`: an owner key, a recovery commitment, a delay and the carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SphincsAccount {
    pub owner: B256,
    pub commitment: B256,
    pub delay: u64,
    pub lower_bound: bool,
    pub carrier: Carrier,
    pub salt: B256,
}

impl SphincsAccount {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut c = sphincs_account_code();
        c.extend_from_slice(self.owner.as_slice());
        c.extend_from_slice(self.commitment.as_slice());
        c.extend_from_slice(&U256::from(self.delay).to_be_bytes::<32>());
        c.extend_from_slice(&U256::from(u8::from(self.lower_bound)).to_be_bytes::<32>());
        c.extend_from_slice(&U256::from(self.carrier.flag()).to_be_bytes::<32>());
        c
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    /// Deployed from someone else's transaction: the constructor writes three fresh slots.
    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 3 * FRESH_SLOT_STATE_GAS)
    }

    /// The owner's `VERIFY`: kind 0, and the owner's triple when modelled.
    #[must_use]
    pub fn owner_verify(&self, key: &SphincsKey, scope: u8) -> Frame {
        self.verify(0, &[], &[key.triple()], scope)
    }

    /// The pending owner's `VERIFY`: kind 2.
    #[must_use]
    pub fn pending_verify(&self, key: &SphincsKey, scope: u8) -> Frame {
        self.verify(2, &[], &[key.triple()], scope)
    }

    /// Recovery keys' `VERIFY`: kind 1, the commitment's preimage, and their triples when
    /// modelled.
    #[must_use]
    pub fn recovery_verify(&self, salt: B256, m: u8, keys: &[B256], signers: &[&SphincsKey], scope: u8) -> Frame {
        let triples: Vec<_> = signers.iter().map(|k| k.triple()).collect();
        self.verify(1, &recovery_body(salt, m, keys), &triples, scope)
    }

    fn verify(&self, kind: u8, body: &[u8], triples: &[[u8; TRIPLE_LEN]], scope: u8) -> Frame {
        let mut data = vec![kind];
        data.extend_from_slice(body);
        if self.carrier == Carrier::Modelled {
            data.extend(triples.concat());
        }
        Frame::verify(scope, None).with_data(data).with_execution(60_000)
    }

    /// `SENDER -> self` with `op || arg`.
    #[must_use]
    pub fn operate(&self, op: u8, arg: Option<B256>) -> Frame {
        let mut data = vec![op];
        if let Some(a) = arg {
            data.extend_from_slice(a.as_slice());
        }
        Frame::sender(Some(self.address())).with_data(data).with_execution(40_000)
    }
}

/// A `SphincsSender`: one key, kept in the code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SphincsSender {
    pub key: B256,
    pub carrier: Carrier,
    pub salt: B256,
}

impl SphincsSender {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut c = sphincs_sender_code();
        c.push(self.carrier.flag());
        c.extend_from_slice(self.key.as_slice());
        c
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    /// The account deploying itself at `tx.sender`, ahead of its own `VERIFY`.
    #[must_use]
    pub fn self_deploy_frame(&self) -> Frame {
        self_deploy_frame(&self.initcode(), self.salt)
    }

    /// Its `VERIFY`, with its triple when modelled.
    #[must_use]
    pub fn verify(&self, key: &SphincsKey, scope: u8) -> Frame {
        let data = if self.carrier == Carrier::Modelled { key.triple().to_vec() } else { Vec::new() };
        Frame::verify(scope, None).with_data(data).with_execution(20_000)
    }
}

/// `APPROVE`'s scope for an account that pays for itself.
pub const PAYS_ITSELF: u8 = approve::EXECUTION_AND_PAYMENT;

/// Who acts for a [`SphincsAccount`] in a transaction.
#[derive(Debug, Clone, Copy)]
pub enum Role<'a> {
    Owner(&'a SphincsKey),
    Pending(&'a SphincsKey),
    /// The commitment's salt, `m`, every committed key, and the `m` that sign.
    Recovery { salt: B256, m: u8, keys: &'a [B256], signers: &'a [&'a SphincsKey] },
}

/// A [`SphincsAccount`] acting through one [`Role`], as [`FrameAccount`] for `TxPlan`.
#[derive(Debug, Clone, Copy)]
pub struct Acting<'a> {
    pub account: &'a SphincsAccount,
    pub role: Role<'a>,
}

impl Acting<'_> {
    /// The keys whose triples this role declares.
    #[must_use]
    pub fn keys(&self) -> Vec<&SphincsKey> {
        match self.role {
            Role::Owner(k) | Role::Pending(k) => vec![k],
            Role::Recovery { signers, .. } => signers.to_vec(),
        }
    }
}

impl FrameAccount for Acting<'_> {
    fn address(&self) -> Address {
        self.account.address()
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        match self.role {
            Role::Owner(k) => self.account.owner_verify(k, scope),
            Role::Pending(k) => self.account.pending_verify(k, scope),
            Role::Recovery { salt, m, keys, signers } => {
                self.account.recovery_verify(salt, m, keys, signers, scope)
            }
        }
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        Vec::new()
    }
}

/// A [`SphincsSender`] and its key, as [`FrameAccount`]; `deploy` while it has no code.
#[derive(Debug, Clone, Copy)]
pub struct Fresh<'a> {
    pub sender: &'a SphincsSender,
    pub key: &'a SphincsKey,
    pub deploy: bool,
}

impl FrameAccount for Fresh<'_> {
    fn address(&self) -> Address {
        self.sender.address()
    }

    fn deploy_frames(&self) -> Vec<Frame> {
        if self.deploy { vec![self.sender.self_deploy_frame()] } else { Vec::new() }
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        self.sender.verify(self.key, scope)
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        Vec::new()
    }
}

/// Put `keys`' triples in one dependency frame right after the sender's `VERIFY` (the first
/// `VERIFY` frame), for a [`Carrier::Dependency`] account. The signature hash changes, so sign
/// after this.
pub fn declare(tx: &mut FrameTx, keys: &[&SphincsKey]) {
    let triples: Vec<_> = keys.iter().map(|k| k.triple()).collect();
    let at = tx
        .frames
        .iter()
        .position(|f| f.mode == kohaku_frame_kit::constants::mode::VERIFY)
        .map_or(0, |i| i + 1);
    tx.frames.insert(at, dependency_frame(&triples));
}

/// One dependency's witness: the key, the message (the signature hash) and the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Witness {
    pub key: B256,
    pub message: B256,
    pub signature: Vec<u8>,
}

/// Sign `tx`'s signature hash with each key, and check each signature, as the block's proof or,
/// modelled, the experiment would.
pub fn witnesses(tx: &FrameTx, keys: &[&SphincsKey]) -> Result<Vec<Witness>, PqError> {
    let message = tx.sig_hash();
    keys.iter()
        .map(|k| {
            let signature = k.sign(message)?;
            debug_assert!(verify_signature(k.public_key(), message, &signature)?);
            Ok(Witness { key: k.public_key(), message, signature })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use kohaku_frame_kit::constants::{MAX_VERIFY_STATE_GAS, NEW_ACCOUNT_STATE_GAS};

    use super::*;

    /// `SphincsSender`'s constructor, as solc 0.8.37 compiles it: 21 bytes before the runtime.
    const SENDER_CONSTRUCTOR_LEN: usize = 21;

    #[test]
    fn a_sender_fits_the_validation_prefix_state_cap() {
        let n = (sphincs_sender_code().len() - SENDER_CONSTRUCTOR_LEN + 33) as u64;
        assert_eq!(n, 190);
        assert!(NEW_ACCOUNT_STATE_GAS + CPSB * n <= MAX_VERIFY_STATE_GAS, "{n} bytes of runtime");
    }

    #[test]
    fn the_carrier_changes_the_address() {
        let a = SphincsSender { key: B256::repeat_byte(1), carrier: Carrier::Dependency, salt: B256::ZERO };
        let b = SphincsSender { carrier: Carrier::Modelled, ..a.clone() };
        assert_ne!(a.address(), b.address());
    }

    #[test]
    fn the_commitment_sorts_its_keys() {
        let (x, y) = (B256::repeat_byte(2), B256::repeat_byte(1));
        assert_eq!(commitment(B256::ZERO, 1, &[x, y]), commitment(B256::ZERO, 1, &[y, x]));
    }
}
