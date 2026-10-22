//! A ticket bound to the transaction it pays for (`exp-frames` experiment 48; the claim-gated
//! admission's CG-12).
//!
//! The message gains the address of a one-time secp256k1 key the buyer chose, the binder:
//!
//! ```text
//! message  = chain_id (32) || sender (20) || nonce_keys_hash (32) || nonce_seq (8)
//!            || epoch (8) || salt (32) || binder (20)                              152 bytes
//! pay data = epoch (8) || salt (32) || binder (20) || signature (128, EIP-2537's G1) 188 bytes
//! ```
//!
//! The issuers sign it blind, as [`crate::ticket::Claim`]'s, so they never see the binder. The
//! binder signs the transaction's signature hash as one more signature entry (scheme
//! `SECP256K1`, `msg` empty, `signer` the binder), which the protocol verifies before any frame
//! runs. `BoundTicketPaymaster.yul` pays only when such an entry is there. A transaction that
//! differs in any field the hash covers, its fees, its frames and its payer among them, is not
//! paid by the ticket.

use alloy::primitives::{Address, B256, U256};
use commonware_cryptography::bls12381::primitives::{
    Error,
    group::{G1, G2},
    sharing::Sharing,
    variant::MinSig,
};
use kohaku_frame_accounts::{
    contracts::{create2_address, deploy_frame},
    sponsor::Sponsor,
};
use kohaku_frame_kit::{Frame, FrameSignature, FrameTx, constants::approve};

use crate::{
    blind,
    ticket::{Claim, NAMESPACE, g1_eip2537, g1_from_eip2537, g2_eip2537},
};

/// The length of [`BoundClaim::message`].
pub const BOUND_MESSAGE_LEN: usize = 152;
/// The length of [`BoundTicket::pay_data`].
pub const BOUND_PAY_DATA_LEN: usize = 188;
/// `SECP256K1`, the scheme a binder's entry must have.
const SECP256K1: u8 = 1;

/// A claim, and the one-time key that must sign the transaction it pays for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundClaim {
    pub claim: Claim,
    pub binder: Address,
}

impl BoundClaim {
    /// The bytes the issuers sign, under [`NAMESPACE`]: the unbound message, then the binder.
    #[must_use]
    pub fn message(&self) -> [u8; BOUND_MESSAGE_LEN] {
        let mut m = [0u8; BOUND_MESSAGE_LEN];
        m[..132].copy_from_slice(&self.claim.message());
        m[132..].copy_from_slice(self.binder.as_slice());
        m
    }

    /// The message hashed to G1, which the buyer blinds.
    #[must_use]
    pub fn point(&self) -> G1 {
        blind::hash(NAMESPACE, &self.message())
    }
}

/// A bound claim and the issuers' signature on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundTicket {
    pub claim: BoundClaim,
    pub signature: G1,
}

impl BoundTicket {
    pub fn verify(&self, sharing: &Sharing<MinSig>) -> Result<(), Error> {
        blind::verify(sharing, NAMESPACE, &self.claim.message(), &self.signature)
    }

    /// The pay frame's data: `epoch || salt || binder || signature`.
    #[must_use]
    pub fn pay_data(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(BOUND_PAY_DATA_LEN);
        d.extend_from_slice(&self.claim.claim.epoch.to_be_bytes());
        d.extend_from_slice(self.claim.claim.salt.as_slice());
        d.extend_from_slice(self.claim.binder.as_slice());
        d.extend_from_slice(&g1_eip2537(&self.signature));
        d
    }

    /// Read a bound ticket back from a pay frame's data, for the slot of its transaction.
    #[must_use]
    pub fn from_pay_data(slot: crate::Slot, data: &[u8]) -> Option<Self> {
        if data.len() != BOUND_PAY_DATA_LEN {
            return None;
        }
        Some(Self {
            claim: BoundClaim {
                claim: Claim {
                    slot,
                    epoch: u64::from_be_bytes(data[..8].try_into().ok()?),
                    salt: B256::from_slice(&data[8..40]),
                },
                binder: Address::from_slice(&data[40..60]),
            },
            signature: g1_from_eip2537(&data[60..])?,
        })
    }
}

/// Whether `tx` carries the binding CG-12 asks of `binder`: an entry with scheme `SECP256K1`,
/// an empty `msg` and `binder` as its resolved signer. The protocol checks its signature.
#[must_use]
pub fn is_bound(tx: &FrameTx, binder: Address) -> bool {
    tx.signatures.iter().any(|s| {
        s.scheme == SECP256K1 && s.msg.is_empty() && s.signer.unwrap_or(tx.sender) == binder
    })
}

/// The binder's entry, unsigned: what [`kohaku_frame_kit::sign_all`] fills.
#[must_use]
pub fn binder_entry(binder: Address) -> FrameSignature {
    FrameSignature {
        scheme: SECP256K1,
        signer: Some(binder),
        ..FrameSignature::default()
    }
}

/// The bound paymaster's creation code, without its arguments.
///
/// # Panics
///
/// Never: the code is embedded hex.
#[must_use]
pub fn bound_paymaster_code() -> Vec<u8> {
    hex::decode(include_str!("../contracts/BoundTicketPaymaster.hex").trim())
        .expect("embedded creation code is hex")
}

/// A bound paymaster for one issuer key and one ticket price; buying is as
/// [`crate::TicketPaymaster`]'s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundTicketPaymaster {
    pub key: G2,
    pub denomination: U256,
    pub salt: B256,
}

impl BoundTicketPaymaster {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = bound_paymaster_code();
        code.extend_from_slice(&g2_eip2537(&self.key));
        code.extend_from_slice(&self.denomination.to_be_bytes::<32>());
        code
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }

    #[must_use]
    pub fn buy_frame(&self, count: u64) -> Frame {
        Frame::sender(Some(self.address()))
            .with_value(self.denomination * U256::from(count))
            .with_execution(10_000)
    }
}

/// Pays with a bound ticket: the pay frame, and the binder's signature entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundTicketSponsor {
    pub paymaster: Address,
    pub data: Vec<u8>,
    pub binder: Address,
    pub verify_execution: u64,
    pub state: u64,
}

impl BoundTicketSponsor {
    /// Experiment 36's room for the check, and room for the loop over the signatures.
    pub const VERIFY_EXECUTION: u64 = 140_000;

    /// The sponsor for a fresh sender's first transaction.
    #[must_use]
    pub fn new(paymaster: Address, ticket: &BoundTicket) -> Self {
        Self {
            paymaster,
            data: ticket.pay_data(),
            binder: ticket.claim.binder,
            verify_execution: Self::VERIFY_EXECUTION,
            state: crate::TicketSponsor::NEW_ACCOUNT_STATE,
        }
    }

    /// Its pay frame alone, for a layout built elsewhere (a pool's withdrawal).
    #[must_use]
    pub fn pay_frame(&self) -> Frame {
        Frame::verify(approve::PAYMENT, Some(self.paymaster))
            .with_data(self.data.clone())
            .with_execution(self.verify_execution)
            .with_state(self.state)
    }
}

impl Sponsor for BoundTicketSponsor {
    fn payment_frames(&self) -> Vec<Frame> {
        vec![self.pay_frame()]
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        vec![binder_entry(self.binder)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_bound_message_is_the_unbound_one_then_the_binder() {
        let claim = Claim {
            slot: crate::Slot {
                chain_id: 8141,
                sender: Address::repeat_byte(0x11),
                nonce_keys: vec![U256::ZERO],
                nonce_seq: 0,
            },
            epoch: 7,
            salt: B256::repeat_byte(0x22),
        };
        let bound = BoundClaim {
            claim: claim.clone(),
            binder: Address::repeat_byte(0x33),
        };
        let m = bound.message();
        assert_eq!(&m[..132], &claim.message()[..]);
        assert_eq!(&m[132..], &[0x33; 20]);
        assert_ne!(bound.point(), claim.point());
    }
}
