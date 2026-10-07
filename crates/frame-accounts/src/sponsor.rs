//! Sponsors: someone other than the sender approves payment.
//!
//! With no sponsor the account's own `VERIFY` approves execution and payment. With one, the
//! account approves execution only, and the sponsor's frames follow it. 4337 needs a paymaster
//! contract, a deposit and a bundler for this; here a sponsor is one more frame.

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    sol,
    sol_types::SolCall,
};
use kohaku_frame_kit::{
    Frame, FrameSignature, FrameTx,
    constants::{STORAGE_SET_STATE_GAS, approve, scheme},
    gas::{UnknownScheme, max_cost},
};

use crate::{
    account::{FrameAccount, Multisig, Signer},
    contracts::{
        canonical_paymaster_code, create2_address, deploy_frame, token_sponsor_code, word,
    },
};

sol! {
    function transfer(address to, uint256 amount) returns (bool);
}

/// Pays for someone else's transaction.
pub trait Sponsor {
    /// The frames that make this sponsor pay, placed right after the account's `VERIFY`.
    fn payment_frames(&self) -> Vec<Frame>;

    /// Frames after the sender's calls, such as a refund.
    fn post_frames(&self) -> Vec<Frame> {
        Vec::new()
    }

    /// Signature entries the payment frames rely on, unsigned. They follow the account's.
    fn signature_entries(&self) -> Vec<FrameSignature> {
        Vec::new()
    }

    /// Price the sponsorship against the transaction it pays for, which is laid out again until
    /// this returns `false`. A sponsor whose frames do not depend on the transaction keeps the
    /// default.
    fn reprice(&mut self, _tx: &FrameTx) -> Result<bool, UnknownScheme> {
        Ok(false)
    }

    /// The index this sponsor's first signature entry must have, for a sponsor whose code reads
    /// a fixed one. The builder refuses a layout that puts it elsewhere.
    fn entry_index(&self) -> Option<usize> {
        None
    }
}

/// Another account with default code pays: its `VERIFY(PAYMENT)` checks its own signature, which
/// covers the whole transaction. Experiment 04's warm-up: a user with no ETH, an owner who pays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EoaSponsor {
    pub key: Signer,
    pub verify_execution: u64,
    /// 183,600 when `APPROVE(PAYMENT)` creates the sender's account, which it does for a sender
    /// that does not exist yet; zero otherwise.
    pub state: u64,
}

impl EoaSponsor {
    pub const VERIFY_EXECUTION: u64 = 10_000;

    #[must_use]
    pub fn new(key: Signer) -> Self {
        Self {
            key,
            verify_execution: Self::VERIFY_EXECUTION,
            state: 0,
        }
    }

    #[must_use]
    pub fn with_state(mut self, state: u64) -> Self {
        self.state = state;
        self
    }
}

impl Sponsor for EoaSponsor {
    fn payment_frames(&self) -> Vec<Frame> {
        vec![
            Frame::verify(approve::PAYMENT, Some(self.key.address))
                .with_execution(self.verify_execution)
                .with_state(self.state),
        ]
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        vec![FrameSignature {
            scheme: self.key.scheme,
            signer: Some(self.key.address),
            ..FrameSignature::default()
        }]
    }
}

/// `TokenSponsor.yul` (experiment 04, the EIP's Example 3): pays the gas for anyone who pays it
/// `max_cost * rate` of one ERC-20 in the frame right after its `VERIFY`, and refunds the unused
/// part in a post-op frame at the end.
///
/// Its `VERIFY` reads only the transaction, never the token's storage, so it cannot know the
/// sender holds the tokens: a sender who spends them first still gets its gas paid. Experiment
/// 04 measured what that costs the sponsor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenSponsor {
    pub address: Address,
    pub token: Address,
    /// Token base units per wei.
    pub rate: U256,
    /// What the fee frame transfers. [`Sponsor::reprice`] raises it to what the sponsor accepts.
    pub fee: U256,
    /// Whether to append the refund frame.
    pub post_op: bool,
    /// State gas for the payment `VERIFY`: 183,600 if it creates the sender's account.
    pub pay_state: u64,
    /// State gas for the fee transfer: a fresh balance slot the first time the sponsor is paid.
    pub fee_state: u64,
}

impl TokenSponsor {
    pub const VERIFY_EXECUTION: u64 = 30_000;
    pub const FEE_EXECUTION: u64 = 50_000;
    pub const POST_OP_EXECUTION: u64 = 60_000;

    #[must_use]
    pub fn new(address: Address, token: Address, rate: U256) -> Self {
        Self {
            address,
            token,
            rate,
            fee: U256::ZERO,
            post_op: true,
            pay_state: 0,
            fee_state: STORAGE_SET_STATE_GAS,
        }
    }

    /// The initcode of a sponsor for `token` at `rate`, swept by `owner`.
    #[must_use]
    pub fn initcode(token: Address, rate: U256, owner: Address) -> Vec<u8> {
        let mut code = token_sponsor_code();
        code.extend_from_slice(&word(token));
        code.extend_from_slice(&rate.to_be_bytes::<32>());
        code.extend_from_slice(&word(owner));
        code
    }

    /// Where that sponsor is deployed under `salt`.
    #[must_use]
    pub fn address_of(token: Address, rate: U256, owner: Address, salt: B256) -> Address {
        create2_address(&Self::initcode(token, rate, owner), salt)
    }

    fn fee_calldata(&self) -> Bytes {
        transferCall {
            to: self.address,
            amount: self.fee,
        }
        .abi_encode()
        .into()
    }
}

/// The transaction as it will be once signed, for pricing: an empty signature is as long as its
/// scheme's, so the calldata it adds is paid for.
fn signed_worst_case(tx: &FrameTx) -> FrameTx {
    let mut tx = tx.clone();
    for s in &mut tx.signatures {
        if s.signature.is_empty() {
            let len = match s.scheme {
                scheme::P256 => 128,
                scheme::SECP256K1 => 65,
                _ => 0,
            };
            s.signature = vec![0xff; len].into();
        }
    }
    tx
}

impl Sponsor for TokenSponsor {
    fn payment_frames(&self) -> Vec<Frame> {
        vec![
            Frame::verify(approve::PAYMENT, Some(self.address))
                .with_execution(Self::VERIFY_EXECUTION)
                .with_state(self.pay_state),
            Frame::sender(Some(self.token))
                .with_data(self.fee_calldata())
                .with_execution(Self::FEE_EXECUTION)
                .with_state(self.fee_state),
        ]
    }

    fn post_frames(&self) -> Vec<Frame> {
        if self.post_op {
            vec![Frame::entry_point(Some(self.address)).with_execution(Self::POST_OP_EXECUTION)]
        } else {
            Vec::new()
        }
    }

    /// The fee is part of the calldata it pays for, so raise it to `max_cost * rate` and lay the
    /// transaction out again until it covers itself.
    fn reprice(&mut self, tx: &FrameTx) -> Result<bool, UnknownScheme> {
        let need = max_cost(&signed_worst_case(tx), 0)? * self.rate;
        if self.fee >= need {
            return Ok(false);
        }
        self.fee = need;
        Ok(true)
    }
}

/// An instance of the canonical paymaster (`exp-frames` experiment 09): it pays for any
/// transaction whose signature entry 1 is its signer's signature over the signature hash. The
/// signer only signs, and never needs ETH.
///
/// It is the payer that lets one sponsor serve many users at once. ethrex recognises it by its
/// code hash and admits as many pending transactions as its balance covers, less what pending
/// ones reserve. Every other payer is held to one pending transaction: a copy of the same code
/// one byte longer, a multisig treasury, and a code-less sponsor alike. In experiment 09 four
/// users with no ETH sent at once; the canonical instance had 4 of 4 admitted, the others 1.
///
/// Its runtime reads entry 1, so the sender's account must contribute exactly one entry. A
/// multisig sender cannot use it, and [`TxPlan::build`](crate::TxPlan::build) says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalPaymaster {
    pub address: Address,
    pub signer: Signer,
    pub verify_execution: u64,
    /// 183,600 when `APPROVE(PAYMENT)` creates the sender's account; zero otherwise.
    pub state: u64,
}

impl CanonicalPaymaster {
    /// Experiment 09 measured the pay frame at 5,210 gas. The PR lets a node refuse one that
    /// declares more than 15,000; ethrex accepted up to 50,000.
    pub const VERIFY_EXECUTION: u64 = 15_000;
    /// The signature entry the runtime reads.
    pub const ENTRY: usize = 1;

    #[must_use]
    pub fn new(address: Address, signer: Signer) -> Self {
        Self {
            address,
            signer,
            verify_execution: Self::VERIFY_EXECUTION,
            state: 0,
        }
    }

    #[must_use]
    pub fn with_state(mut self, state: u64) -> Self {
        self.state = state;
        self
    }

    /// The initcode of an instance whose payments `signer` approves.
    #[must_use]
    pub fn initcode(signer: Address) -> Vec<u8> {
        let mut code = canonical_paymaster_code();
        code.extend_from_slice(&word(signer));
        code
    }

    /// Where that instance is deployed under `salt`.
    #[must_use]
    pub fn address_of(signer: Address, salt: B256) -> Address {
        create2_address(&Self::initcode(signer), salt)
    }

    /// A `SENDER` frame deploying that instance; the constructor writes one fresh slot.
    #[must_use]
    pub fn deploy_frame(signer: Address, salt: B256) -> Frame {
        deploy_frame(&Self::initcode(signer), salt, STORAGE_SET_STATE_GAS)
    }
}

impl Sponsor for CanonicalPaymaster {
    fn payment_frames(&self) -> Vec<Frame> {
        vec![
            Frame::verify(approve::PAYMENT, Some(self.address))
                .with_execution(self.verify_execution)
                .with_state(self.state),
        ]
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        vec![FrameSignature {
            scheme: self.signer.scheme,
            signer: Some(self.signer.address),
            ..FrameSignature::default()
        }]
    }

    fn entry_index(&self) -> Option<usize> {
        Some(Self::ENTRY)
    }
}

/// A [`Multisig`] paying for someone else: experiment 09's treasury. Its `VERIFY(PAYMENT)`
/// counts its owners among the entries exactly as it does for its own transactions, and ignores
/// the sender's. It is not the canonical paymaster, so the mempool holds it to one pending
/// transaction: a treasury pays for one member at a time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultisigSponsor {
    /// Deployed, and `signed_by` the owners approving this payment.
    pub multisig: Multisig,
    /// 183,600 when `APPROVE(PAYMENT)` creates the sender's account; zero otherwise.
    pub state: u64,
}

impl MultisigSponsor {
    #[must_use]
    pub fn new(multisig: Multisig) -> Self {
        Self { multisig, state: 0 }
    }

    #[must_use]
    pub fn with_state(mut self, state: u64) -> Self {
        self.state = state;
        self
    }
}

impl Sponsor for MultisigSponsor {
    fn payment_frames(&self) -> Vec<Frame> {
        vec![
            Frame::verify(approve::PAYMENT, Some(self.multisig.address()))
                .with_execution(self.multisig.verify_execution)
                .with_state(self.state),
        ]
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        self.multisig.signature_entries()
    }
}
