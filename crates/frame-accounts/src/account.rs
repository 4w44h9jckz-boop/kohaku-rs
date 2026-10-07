//! Accounts: who `tx.sender` is, and how its `VERIFY` frame approves.
//!
//! An account here holds addresses only. Keys are applied afterwards with
//! [`kohaku_frame_kit::sign_all`], so the same layout works whether the keys are in memory, in a
//! hardware wallet, or with several co-signers on different machines.

use alloy::primitives::{Address, B256, U256};
use kohaku_frame_kit::{Frame, FrameSignature, FrameSigner, constants::scheme};

use crate::contracts::{
    create2_address, deploy_frame, multisig_code, self_deploy_frame, simple_account_code, word,
};

/// A transaction sender.
pub trait FrameAccount {
    /// `tx.sender`.
    fn address(&self) -> Address;

    /// Frames that must run before the account's `VERIFY`, such as deploying the account at
    /// `tx.sender`. Empty for an account that already exists.
    fn deploy_frames(&self) -> Vec<Frame> {
        Vec::new()
    }

    /// The `VERIFY` frame in which the account approves `scope`.
    fn verify_frame(&self, scope: u8) -> Frame;

    /// The signature entries that `VERIFY` frame relies on, unsigned.
    fn signature_entries(&self) -> Vec<FrameSignature>;
}

/// A signing key's identity: what a signature entry names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signer {
    pub address: Address,
    pub scheme: u8,
}

impl Signer {
    #[must_use]
    pub fn secp256k1(address: Address) -> Self {
        Self {
            address,
            scheme: scheme::SECP256K1,
        }
    }

    #[must_use]
    pub fn p256(address: Address) -> Self {
        Self {
            address,
            scheme: scheme::P256,
        }
    }

    fn entry(self, signer: Option<Address>) -> FrameSignature {
        FrameSignature {
            scheme: self.scheme,
            signer,
            ..FrameSignature::default()
        }
    }
}

impl From<&FrameSigner> for Signer {
    fn from(key: &FrameSigner) -> Self {
        Self {
            address: key.address(),
            scheme: key.scheme(),
        }
    }
}

/// An account with no code, validated by the protocol's default code: signature entry 0 must be
/// by `tx.sender` itself. A secp256k1 key's address is the usual one; a P256 key's is
/// `keccak256(qx || qy)[12..]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Eoa {
    pub key: Signer,
    pub verify_execution: u64,
}

impl Eoa {
    pub const VERIFY_EXECUTION: u64 = 20_000;

    #[must_use]
    pub fn new(key: Signer) -> Self {
        Self {
            key,
            verify_execution: Self::VERIFY_EXECUTION,
        }
    }

    #[must_use]
    pub fn with_verify_execution(mut self, gas: u64) -> Self {
        self.verify_execution = gas;
        self
    }
}

impl FrameAccount for Eoa {
    fn address(&self) -> Address {
        self.key.address
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        Frame::verify(scope, None).with_execution(self.verify_execution)
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        vec![self.key.entry(None)]
    }
}

/// `SimpleAccount.yul` (experiment 02): a counterfactual account with one secp256k1 owner.
/// Its `VERIFY` checks with `SIGPARAM` that entry 0 is the owner's signature over the signature
/// hash; the protocol has already checked the signature itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimpleAccount {
    pub owner: Address,
    pub salt: B256,
    /// `false` puts the deployment in front of `VERIFY` (Example 1b).
    pub deployed: bool,
    pub verify_execution: u64,
}

impl SimpleAccount {
    pub const VERIFY_EXECUTION: u64 = 10_000;

    #[must_use]
    pub fn new(owner: Address, salt: B256) -> Self {
        Self {
            owner,
            salt,
            deployed: false,
            verify_execution: Self::VERIFY_EXECUTION,
        }
    }

    #[must_use]
    pub fn deployed(mut self, deployed: bool) -> Self {
        self.deployed = deployed;
        self
    }

    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = simple_account_code();
        code.extend_from_slice(&word(self.owner));
        code
    }
}

impl FrameAccount for SimpleAccount {
    fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    fn deploy_frames(&self) -> Vec<Frame> {
        if self.deployed {
            Vec::new()
        } else {
            vec![self_deploy_frame(&self.initcode(), self.salt)]
        }
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        Frame::verify(scope, None).with_execution(self.verify_execution)
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        vec![Signer::secp256k1(self.owner).entry(Some(self.owner))]
    }
}

/// `Multisig.yul` (experiment 05): k of n owners, each a secp256k1 or P256 key. Its `VERIFY`
/// counts, with `SIGPARAM`, the distinct owners among the entries that sign the signature hash,
/// so it can share the signature list with a sponsor's entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Multisig {
    pub owners: Vec<Address>,
    pub threshold: usize,
    pub salt: B256,
    /// `false` puts the deployment in front of `VERIFY`, which only fits small owner sets: the
    /// prefix's state gas is capped at 500,000.
    pub deployed: bool,
    /// The owners signing this transaction.
    pub signers: Vec<Signer>,
    pub verify_execution: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum MultisigError {
    #[error("threshold {threshold} of {owners} owners")]
    Threshold { threshold: usize, owners: usize },
    #[error("{0} is not an owner")]
    NotOwner(Address),
}

impl Multisig {
    pub const VERIFY_EXECUTION: u64 = 30_000;

    /// The contract refuses `k = 0`, `k > n` and `n > 256`; so does this.
    pub fn new(owners: Vec<Address>, threshold: usize, salt: B256) -> Result<Self, MultisigError> {
        if threshold == 0 || threshold > owners.len() || owners.len() > 256 {
            return Err(MultisigError::Threshold {
                threshold,
                owners: owners.len(),
            });
        }
        Ok(Self {
            owners,
            threshold,
            salt,
            deployed: false,
            signers: Vec::new(),
            verify_execution: Self::VERIFY_EXECUTION,
        })
    }

    #[must_use]
    pub fn deployed(mut self, deployed: bool) -> Self {
        self.deployed = deployed;
        self
    }

    /// Choose who signs. The chain is not asked: fewer than `threshold` distinct owners makes
    /// `VERIFY` revert, and the node refuses the transaction.
    pub fn signed_by(mut self, signers: Vec<Signer>) -> Result<Self, MultisigError> {
        if let Some(s) = signers.iter().find(|s| !self.owners.contains(&s.address)) {
            return Err(MultisigError::NotOwner(s.address));
        }
        self.signers = signers;
        Ok(self)
    }

    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = multisig_code();
        for owner in &self.owners {
            code.extend_from_slice(&word(*owner));
        }
        code.extend_from_slice(&U256::from(self.owners.len()).to_be_bytes::<32>());
        code.extend_from_slice(&U256::from(self.threshold).to_be_bytes::<32>());
        code
    }

    /// A `SENDER` frame that deploys this account from someone else's transaction.
    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }
}

impl FrameAccount for Multisig {
    fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    fn deploy_frames(&self) -> Vec<Frame> {
        if self.deployed {
            Vec::new()
        } else {
            vec![self_deploy_frame(&self.initcode(), self.salt)]
        }
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        Frame::verify(scope, None).with_execution(self.verify_execution)
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        self.signers
            .iter()
            .map(|s| s.entry(Some(s.address)))
            .collect()
    }
}
