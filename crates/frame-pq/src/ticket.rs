//! A ticket bound to its transaction by a one-time leanSPHINCS key (`exp-frames` experiment 49):
//! experiment 48's bound ticket with the binder's 20-byte address replaced by its 32-byte
//! leanSPHINCS public key, and its protocol signature entry by an EIP-8288 dependency.
//!
//! ```text
//! message  = chain_id (32) || sender (20) || nonce_keys_hash (32) || nonce_seq (8)
//!            || epoch (8) || salt (32) || binder (32)                              164 bytes
//! pay data = epoch (8) || salt (32) || binder (32) || signature (128, EIP-2537's G1) 200 bytes
//! binding  = the triple 0x10 || 0 || binder: the binder's signature over the signature hash
//! ```
//!
//! The issuers sign the message blind, as experiment 36's, so they never see the binder's key.
//! The issuers' signature is still BLS: that half is not post-quantum here.

use alloy::primitives::{Address, B256, U256};
use commonware_cryptography::bls12381::primitives::{
    Error,
    group::{G1, G2},
    sharing::Sharing,
    variant::MinSig,
};
use kohaku_frame_accounts::contracts::{create2_address, deploy_frame};
use kohaku_frame_kit::{Frame, constants::approve};
use kohaku_frame_ticket::{
    Claim, blind,
    ticket::{NAMESPACE, g1_eip2537, g2_eip2537},
};

use crate::{SphincsKey, TRIPLE_LEN, account::Carrier};

/// The length of [`PqBoundClaim::message`].
pub const PQ_BOUND_MESSAGE_LEN: usize = 164;
/// The length of [`PqBoundTicket::pay_data`].
pub const PQ_BOUND_PAY_DATA_LEN: usize = 200;

/// A claim, and the leanSPHINCS key that must sign the transaction it pays for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqBoundClaim {
    pub claim: Claim,
    pub binder: B256,
}

impl PqBoundClaim {
    /// The bytes the issuers sign: the unbound message, then the binder's key.
    #[must_use]
    pub fn message(&self) -> [u8; PQ_BOUND_MESSAGE_LEN] {
        let mut m = [0u8; PQ_BOUND_MESSAGE_LEN];
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
pub struct PqBoundTicket {
    pub claim: PqBoundClaim,
    pub signature: G1,
}

impl PqBoundTicket {
    pub fn verify(&self, sharing: &Sharing<MinSig>) -> Result<(), Error> {
        blind::verify(sharing, NAMESPACE, &self.claim.message(), &self.signature)
    }

    /// `epoch || salt || binder || signature`.
    #[must_use]
    pub fn pay_data(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(PQ_BOUND_PAY_DATA_LEN + TRIPLE_LEN);
        d.extend_from_slice(&self.claim.claim.epoch.to_be_bytes());
        d.extend_from_slice(self.claim.claim.salt.as_slice());
        d.extend_from_slice(self.claim.binder.as_slice());
        d.extend_from_slice(&g1_eip2537(&self.signature));
        d
    }
}

/// `PqBoundTicketPaymaster.yul`'s creation code, without its arguments.
///
/// # Panics
///
/// Never: the code is embedded hex.
#[must_use]
pub fn pq_bound_paymaster_code() -> Vec<u8> {
    hex::decode(include_str!("../contracts/PqBoundTicketPaymaster.hex").trim())
        .expect("embedded creation code is hex")
}

/// A bound paymaster for one issuer key, one price, and one carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqBoundTicketPaymaster {
    pub key: G2,
    pub denomination: U256,
    pub carrier: Carrier,
    pub salt: B256,
}

impl PqBoundTicketPaymaster {
    /// Room for experiment 36's check and the triple.
    pub const VERIFY_EXECUTION: u64 = 140_000;

    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = pq_bound_paymaster_code();
        code.extend_from_slice(&g2_eip2537(&self.key));
        code.extend_from_slice(&self.denomination.to_be_bytes::<32>());
        code.extend_from_slice(&U256::from(u8::from(self.carrier == Carrier::Modelled)).to_be_bytes::<32>());
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

    /// The pay frame: the ticket, and the binder's triple when modelled. `state` covers what the
    /// transaction creates that the payer pays for (a fresh sender: a new account).
    #[must_use]
    pub fn pay_frame(&self, ticket: &PqBoundTicket, binder: &SphincsKey, state: u64) -> Frame {
        let mut data = ticket.pay_data();
        if self.carrier == Carrier::Modelled {
            data.extend_from_slice(&binder.triple());
        }
        Frame::verify(approve::PAYMENT, Some(self.address()))
            .with_data(data)
            .with_execution(Self::VERIFY_EXECUTION)
            .with_state(state)
    }
}

#[cfg(test)]
mod tests {
    use kohaku_frame_ticket::Slot;

    use super::*;

    #[test]
    fn the_message_is_the_unbound_one_then_the_key() {
        let claim = Claim {
            slot: Slot { chain_id: 8141, sender: Address::repeat_byte(0x11), nonce_keys: vec![U256::ZERO], nonce_seq: 0 },
            epoch: 7,
            salt: B256::repeat_byte(0x22),
        };
        let bound = PqBoundClaim { claim: claim.clone(), binder: B256::repeat_byte(0x33) };
        let m = bound.message();
        assert_eq!(&m[..132], &claim.message()[..]);
        assert_eq!(&m[132..], &[0x33; 32]);
        assert_ne!(bound.point(), claim.point());
    }
}
