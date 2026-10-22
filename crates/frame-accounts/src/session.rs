//! `SessionAccount.yul` (`exp-frames` experiment 12): one owner key with full control, and
//! session keys the owner grants to an app, an agent or a device. A session may call one target
//! with one selector until a deadline, within a budget in wei that counts the value it sends and
//! each transaction's maximum fee.
//!
//! Under ERC-4337 a session validator decodes the `execute` calldata of a user operation to learn
//! what the key is asking for. Here the calls are the frames, and the account's `VERIFY` reads
//! every one of them before it approves. A session transaction has exactly this shape:
//!
//! ```text
//! 0   VERIFY  expiry verifier   deadline <= the session's validUntil
//! 1   VERIFY  the account       entry 0 signed by the session key over the signature hash
//! 2   SENDER  the account       0x03 || key || amount: records the spend; cannot fail
//! 3+  SENDER  the target        empty data if the selector is 0, else starting with it
//! ```
//!
//! `amount` must cover the maximum cost plus the value of frames 3 and up. `VERIFY` is static, so
//! it checks the budget and frame 2 writes it. `TIMESTAMP` is banned in `VERIFY`, so the deadline
//! comes from the expiry frame, which the account requires.
//!
//! Experiment 12 measured a session transaction at about 21,600 gas over the owner's own, and
//! found that the owner revokes a pending session transaction by replacing it: same nonce, fees
//! raised by [`kohaku_frame_kit::Fees::bumped`] or more.

use alloy::primitives::{Address, B256, U256};
use kohaku_frame_kit::{
    Frame, FrameSignature, FrameTx,
    constants::{STORAGE_SET_STATE_GAS, approve},
    gas::{UnknownScheme, max_cost},
};

use crate::{
    account::{FrameAccount, Signer},
    builder::{Envelope, charge_fresh_nonce_keys},
    contracts::{create2_address, deploy_frame, session_account_code, word},
    sponsor::signed_worst_case,
};

/// What a session key may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionPolicy {
    /// The only contract or account its calls may reach. Never the account itself.
    pub target: Address,
    /// The only function it may call; zero for plain transfers with no data.
    pub selector: [u8; 4],
    /// The latest deadline its transactions may carry, as a block timestamp.
    pub valid_until: u64,
    /// Wei it may spend in all, value and maximum fees together.
    pub budget: u128,
}

/// A `SessionAccount`, deployed by someone else (its code is 674 bytes, too large to deploy
/// itself in a validation prefix). As a [`FrameAccount`] it is the owner signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionAccount {
    pub owner: Address,
    pub salt: B256,
    pub verify_execution: u64,
}

impl SessionAccount {
    pub const VERIFY_EXECUTION: u64 = 20_000;
    /// The session path's `VERIFY` walks every frame; experiment 12 measured 7,468 for one call.
    pub const SESSION_VERIFY_EXECUTION: u64 = 60_000;
    /// The account refuses a spend frame with less, so that it cannot run out.
    pub const SPEND_EXECUTION: u64 = 30_000;

    #[must_use]
    pub fn new(owner: Address, salt: B256) -> Self {
        Self {
            owner,
            salt,
            verify_execution: Self::VERIFY_EXECUTION,
        }
    }

    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = session_account_code();
        code.extend_from_slice(&word(self.owner));
        code
    }

    /// A `SENDER` frame deploying this account from someone else's transaction.
    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }

    /// The owner's frame granting `key` a session: three fresh slots.
    #[must_use]
    pub fn add_session(&self, key: Address, policy: &SessionPolicy) -> Frame {
        let mut data = Vec::with_capacity(69);
        data.push(0x01);
        data.extend_from_slice(key.as_slice());
        data.extend_from_slice(policy.target.as_slice());
        data.extend_from_slice(&policy.selector);
        data.extend_from_slice(&policy.valid_until.to_be_bytes());
        data.extend_from_slice(&policy.budget.to_be_bytes());
        Frame::sender(Some(self.address()))
            .with_data(data)
            .with_execution(80_000)
            .with_state(3 * STORAGE_SET_STATE_GAS)
    }

    /// The owner's frame revoking `key`'s session.
    #[must_use]
    pub fn revoke_session(&self, key: Address) -> Frame {
        let mut data = Vec::with_capacity(21);
        data.push(0x02);
        data.extend_from_slice(key.as_slice());
        Frame::sender(Some(self.address()))
            .with_data(data)
            .with_execution(40_000)
    }

    fn spend_frame(&self, key: Address, amount: U256) -> Frame {
        let mut data = Vec::with_capacity(53);
        data.push(0x03);
        data.extend_from_slice(key.as_slice());
        data.extend_from_slice(&amount.to_be_bytes::<32>());
        Frame::sender(Some(self.address()))
            .with_data(data)
            .with_execution(Self::SPEND_EXECUTION)
    }

    /// A transaction signed by the session `key`, making `calls` (SENDER frames to the
    /// session's target) before `deadline`. The result is unsigned: sign it with the session key.
    ///
    /// The spend amount is priced on the transaction as it will be once signed and with the
    /// amount's own 32 bytes at their most expensive, which bounds the maximum cost from above;
    /// the account only requires the amount to be at least that plus the value sent.
    pub fn session_tx(
        &self,
        key: Signer,
        calls: &[Frame],
        deadline: u64,
        envelope: &Envelope,
    ) -> Result<FrameTx, UnknownScheme> {
        let value: U256 = calls.iter().map(|c| c.value).sum();
        let layout = |amount: U256| {
            let mut frames = vec![
                Frame::expiry(deadline),
                Frame::verify(approve::EXECUTION_AND_PAYMENT, None)
                    .with_execution(Self::SESSION_VERIFY_EXECUTION),
                self.spend_frame(key.address, amount),
            ];
            frames.extend_from_slice(calls);
            charge_fresh_nonce_keys(&mut frames, envelope.fresh_nonce_keys());
            FrameTx {
                chain_id: envelope.chain_id,
                nonce_keys: envelope.nonce_keys.clone(),
                nonce_seq: envelope.nonce_seq,
                sender: self.address(),
                frames,
                signatures: vec![FrameSignature {
                    scheme: key.scheme,
                    signer: Some(key.address),
                    ..FrameSignature::default()
                }],
                fees: envelope.fees,
                blob_versioned_hashes: Vec::new(),
            }
        };
        let amount = max_cost(&signed_worst_case(&layout(U256::MAX)), 0)? + value;
        Ok(layout(amount))
    }
}

impl FrameAccount for SessionAccount {
    fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        Frame::verify(scope, None).with_execution(self.verify_execution)
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        vec![FrameSignature {
            scheme: kohaku_frame_kit::constants::scheme::SECP256K1,
            signer: Some(self.owner),
            ..FrameSignature::default()
        }]
    }
}
