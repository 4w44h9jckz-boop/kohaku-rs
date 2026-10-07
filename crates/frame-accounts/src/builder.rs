//! Laying out a transaction: the account, then its sponsor, then the calls.
//!
//! ```text
//! [expiry]  the expiry verifier, if the transaction has a deadline: always the first frame
//! [deploy]  account deploys itself at tx.sender, if it is not there yet (Example 1b)
//! VERIFY    the account: EXECUTION_AND_PAYMENT, or EXECUTION when sponsored
//! [payment] the sponsor's VERIFY(PAYMENT), and whatever it needs next to it
//! calls     SENDER frames, as the account
//! [post]    the sponsor's post-op
//! ```
//!
//! The frame that approves payment, the account's `VERIFY` or the sponsor's, also carries the
//! state gas for any EIP-8250 nonce key the transaction uses for the first time.

use alloy::primitives::U256;
use kohaku_frame_kit::{
    Fees, Frame, FrameTx,
    constants::{STORAGE_SET_STATE_GAS, approve, mode},
    gas::UnknownScheme,
};

use crate::{account::FrameAccount, sponsor::Sponsor};

/// The envelope fields that are not frames or signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub chain_id: u64,
    /// `[0]` is the account nonce; anything else is a set of EIP-8250 keys.
    pub nonce_keys: Vec<U256>,
    pub nonce_seq: u64,
    pub fees: Fees,
}

impl Envelope {
    /// How many keys this envelope uses for the first time. Every key in a set sits at the same
    /// sequence, so at sequence 0 each non-zero key's `NONCE_MANAGER` slot is still empty, and
    /// the transaction creates it: 97,920 state gas a key on this chain. Key 0 is the account
    /// nonce and has no slot.
    #[must_use]
    pub fn fresh_nonce_keys(&self) -> usize {
        if self.nonce_seq == 0 {
            self.nonce_keys.iter().filter(|k| !k.is_zero()).count()
        } else {
            0
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error(transparent)]
    Gas(#[from] UnknownScheme),
    #[error("the sponsor's price did not settle after {0} rounds")]
    Unsettled(usize),
    #[error("the sponsor reads its signature at entry {needs}, but the account has {has} entries")]
    EntryIndex { needs: usize, has: usize },
}

/// A transaction from `account`, optionally sponsored, making `calls`.
pub struct TxPlan<'a> {
    account: &'a dyn FrameAccount,
    sponsor: Option<&'a mut dyn Sponsor>,
    calls: Vec<Frame>,
    deadline: Option<u64>,
}

impl<'a> TxPlan<'a> {
    #[must_use]
    pub fn new(account: &'a dyn FrameAccount) -> Self {
        Self {
            account,
            sponsor: None,
            calls: Vec::new(),
            deadline: None,
        }
    }

    /// Put an expiry verifier frame first: the transaction is invalid once
    /// `block.timestamp > deadline`, and the mempool drops it then.
    ///
    /// `exp-frames` experiment 10 measured the frame at 3,051 execution gas, nearly all of it
    /// the cold access to the verifier, so [`Frame::expiry`]'s 5,000 leaves a margin; 3,050 was
    /// refused. The node refuses the frame anywhere but first.
    #[must_use]
    pub fn expires_at(mut self, deadline: u64) -> Self {
        self.deadline = Some(deadline);
        self
    }

    #[must_use]
    pub fn sponsored_by(mut self, sponsor: &'a mut dyn Sponsor) -> Self {
        self.sponsor = Some(sponsor);
        self
    }

    /// Append one frame. A call is normally a `SENDER` frame; mark it `atomic()` to batch it
    /// with the next one.
    #[must_use]
    pub fn call(mut self, frame: Frame) -> Self {
        self.calls.push(frame);
        self
    }

    #[must_use]
    pub fn calls(mut self, frames: impl IntoIterator<Item = Frame>) -> Self {
        self.calls.extend(frames);
        self
    }

    fn layout(&self, envelope: &Envelope) -> FrameTx {
        let sponsor = self.sponsor.as_deref();
        let mut frames: Vec<Frame> = self.deadline.map(Frame::expiry).into_iter().collect();
        frames.extend(self.account.deploy_frames());
        let scope = if sponsor.is_some() {
            approve::EXECUTION
        } else {
            approve::EXECUTION_AND_PAYMENT
        };
        frames.push(self.account.verify_frame(scope));
        let mut signatures = self.account.signature_entries();
        if let Some(s) = sponsor {
            frames.extend(s.payment_frames());
            signatures.extend(s.signature_entries());
        }
        frames.extend(self.calls.iter().cloned());
        if let Some(s) = sponsor {
            frames.extend(s.post_frames());
        }
        charge_fresh_nonce_keys(&mut frames, envelope.fresh_nonce_keys());
        FrameTx {
            chain_id: envelope.chain_id,
            nonce_keys: envelope.nonce_keys.clone(),
            nonce_seq: envelope.nonce_seq,
            sender: self.account.address(),
            frames,
            signatures,
            fees: envelope.fees,
            blob_versioned_hashes: Vec::new(),
        }
    }

    /// Lay the transaction out, and lay it out again while the sponsor reprices it. The result
    /// is unsigned: fill it with [`kohaku_frame_kit::sign_all`].
    pub fn build(mut self, envelope: &Envelope) -> Result<FrameTx, BuildError> {
        const ROUNDS: usize = 8;
        if let Some(needs) = self.sponsor.as_deref().and_then(Sponsor::entry_index) {
            let has = self.account.signature_entries().len();
            if has != needs {
                return Err(BuildError::EntryIndex { needs, has });
            }
        }
        for _ in 0..ROUNDS {
            let tx = self.layout(envelope);
            let changed = match self.sponsor.as_deref_mut() {
                Some(s) => s.reprice(&tx)?,
                None => false,
            };
            if !changed {
                return Ok(tx);
            }
        }
        Err(BuildError::Unsettled(ROUNDS))
    }
}

/// The nonce is incremented where payment is approved, so a fresh key's slot is charged there:
/// to the account's `VERIFY` when it pays for itself (`exp-frames` experiments 01 and 08), to the
/// sponsor's `VERIFY(PAYMENT)` when someone else pays (experiment 16).
fn charge_fresh_nonce_keys(frames: &mut [Frame], fresh: usize) {
    let Some(payer) = frames
        .iter_mut()
        .find(|f| f.mode == mode::VERIFY && f.flags & approve::PAYMENT != 0)
    else {
        return;
    };
    let fresh = u64::try_from(fresh).expect("at most MAX_NONCE_KEYS keys");
    payer.limits.state += fresh * STORAGE_SET_STATE_GAS;
}

#[cfg(feature = "rpc")]
impl Envelope {
    /// Chain id, the sequence of `nonce_keys` for `sender`, and fees of twice the base fee plus
    /// `tip`, from the node.
    pub async fn fetch<P: alloy::providers::Provider>(
        provider: &P,
        sender: alloy::primitives::Address,
        nonce_keys: Vec<U256>,
        tip: u128,
    ) -> Result<Self, kohaku_frame_kit::rpc::RpcError> {
        use kohaku_frame_kit::rpc;
        Ok(Self {
            chain_id: provider.get_chain_id().await?,
            nonce_seq: rpc::nonce_seq(provider, sender, &nonce_keys).await?,
            nonce_keys,
            fees: rpc::suggest_fees(provider, tip).await?,
        })
    }
}
