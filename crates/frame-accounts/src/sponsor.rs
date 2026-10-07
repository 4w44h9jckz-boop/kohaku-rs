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
    account::Signer,
    contracts::{create2_address, token_sponsor_code, word},
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
