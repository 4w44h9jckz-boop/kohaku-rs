//! Laying out a transaction: the account, then its sponsor, then the calls.
//!
//! ```text
//! [deploy]  account deploys itself at tx.sender, if it is not there yet (Example 1b)
//! VERIFY    the account: EXECUTION_AND_PAYMENT, or EXECUTION when sponsored
//! [payment] the sponsor's VERIFY(PAYMENT), and whatever it needs next to it
//! calls     SENDER frames, as the account
//! [post]    the sponsor's post-op
//! ```

use alloy::primitives::U256;
use kohaku_frame_kit::{Fees, Frame, FrameTx, constants::approve, gas::UnknownScheme};

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

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error(transparent)]
    Gas(#[from] UnknownScheme),
    #[error("the sponsor's price did not settle after {0} rounds")]
    Unsettled(usize),
}

/// A transaction from `account`, optionally sponsored, making `calls`.
pub struct TxPlan<'a> {
    account: &'a dyn FrameAccount,
    sponsor: Option<&'a mut dyn Sponsor>,
    calls: Vec<Frame>,
}

impl<'a> TxPlan<'a> {
    #[must_use]
    pub fn new(account: &'a dyn FrameAccount) -> Self {
        Self {
            account,
            sponsor: None,
            calls: Vec::new(),
        }
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
        let mut frames = self.account.deploy_frames();
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
