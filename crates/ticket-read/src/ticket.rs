//! A read ticket: the issuers' signature on a serial for one server.
//!
//! It is issued exactly as a gas ticket is (`kohaku_frame_ticket::blind`), by the same committee
//! under the same key, and the issuers cannot tell the two apart: they see a blinded point
//! either way. A different namespace keeps a read ticket from paying for gas, and gas tickets
//! from paying for reads.
//!
//! ```text
//! message = server (32) || serial (32)
//! ```
//!
//! The server keeps its own set of spent serials, so a ticket binds the server it was bought
//! for: another server would not know it was spent.

use alloy::primitives::B256;
use commonware_cryptography::bls12381::primitives::{
    Error,
    group::{G1, G2},
    ops,
    variant::MinSig,
};

/// The namespace the issuers sign read tickets under.
pub const READ_NAMESPACE: &[u8] = b"kohaku-read-ticket-v1";

/// What a read ticket names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadClaim {
    /// The server's identity, which it publishes in its manifest.
    pub server: B256,
    pub serial: B256,
}

impl ReadClaim {
    #[must_use]
    pub fn message(&self) -> [u8; 64] {
        let mut m = [0u8; 64];
        m[..32].copy_from_slice(self.server.as_slice());
        m[32..].copy_from_slice(self.serial.as_slice());
        m
    }
}

/// A claim and the committee's signature on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadTicket {
    pub claim: ReadClaim,
    pub signature: G1,
}

impl ReadTicket {
    /// Whether the signature is the committee's (`key`) on the claim.
    pub fn verify(&self, key: &G2) -> Result<(), Error> {
        ops::verify_message::<MinSig>(key, READ_NAMESPACE, &self.claim.message(), &self.signature)
    }
}
