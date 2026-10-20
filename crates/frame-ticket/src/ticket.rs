//! The ticket: the message the issuers sign, and the bytes a transaction carries.
//!
//! A ticket pays for one slot, a sender at one nonce, so the protocol's nonce is its spent mark:
//! a slot is consumed once. The message binds the slot to the chain, the epoch it was issued in
//! and a salt, so that a sender may hold two tickets for one slot.
//!
//! ```text
//! message  = chain_id (32) || sender (20) || nonce_keys_hash (32) || nonce_seq (8)
//!            || epoch (8) || salt (32)                                        132 bytes
//! pay data = epoch (8) || salt (32) || signature (128, EIP-2537's G1)        168 bytes
//! ```
//!
//! `nonce_keys_hash` is EIP-8250's, the word `TXPARAM(0x0F)` reads. The issuers sign
//! `union_unique(NAMESPACE, message)` under `MinSig`, so `ops::verify_message::<MinSig>` checks
//! a ticket, and `TicketPaymaster.yul` checks the same bytes on chain.

use alloy::primitives::{Address, B256, U256};
use blst::min_sig;
use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::bls12381::primitives::{
    Error,
    group::{G1, G2},
    sharing::Sharing,
    variant::MinSig,
};
use kohaku_frame_kit::{FrameTx, digest::nonce_keys_hash};

use crate::blind;

/// The namespace the issuers sign tickets under.
pub const NAMESPACE: &[u8] = b"kohaku-ticket-v1";

/// Seconds an epoch lasts: the epoch of a block is its timestamp divided by this.
pub const EPOCH_SECONDS: u64 = 384;

/// The length of [`Claim::message`].
pub const MESSAGE_LEN: usize = 132;

/// The length of [`Ticket::pay_data`].
pub const PAY_DATA_LEN: usize = 168;

/// The epoch of a block with this timestamp.
#[must_use]
pub fn epoch_of(timestamp: u64) -> u64 {
    timestamp / EPOCH_SECONDS
}

/// The slot a ticket pays for: a sender at one nonce, on one chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slot {
    pub chain_id: u64,
    pub sender: Address,
    pub nonce_keys: Vec<U256>,
    pub nonce_seq: u64,
}

impl Slot {
    /// The slot `tx` uses.
    #[must_use]
    pub fn of(tx: &FrameTx) -> Self {
        Self {
            chain_id: tx.chain_id,
            sender: tx.sender,
            nonce_keys: tx.nonce_keys.clone(),
            nonce_seq: tx.nonce_seq,
        }
    }
}

/// What a ticket says: one slot, in one epoch, under one salt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub slot: Slot,
    pub epoch: u64,
    pub salt: B256,
}

impl Claim {
    /// The bytes the issuers sign, under [`NAMESPACE`].
    #[must_use]
    pub fn message(&self) -> [u8; MESSAGE_LEN] {
        let mut m = [0u8; MESSAGE_LEN];
        m[..32].copy_from_slice(&U256::from(self.slot.chain_id).to_be_bytes::<32>());
        m[32..52].copy_from_slice(self.slot.sender.as_slice());
        m[52..84].copy_from_slice(nonce_keys_hash(&self.slot.nonce_keys).as_slice());
        m[84..92].copy_from_slice(&self.slot.nonce_seq.to_be_bytes());
        m[92..100].copy_from_slice(&self.epoch.to_be_bytes());
        m[100..].copy_from_slice(self.salt.as_slice());
        m
    }

    /// The point the issuers' signature is on: the message hashed to G1.
    #[must_use]
    pub fn point(&self) -> G1 {
        blind::hash(NAMESPACE, &self.message())
    }
}

/// A claim and the issuers' signature on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub claim: Claim,
    pub signature: G1,
}

impl Ticket {
    /// Whether the signature is the committee's on the claim.
    pub fn verify(&self, sharing: &Sharing<MinSig>) -> Result<(), Error> {
        blind::verify(sharing, NAMESPACE, &self.claim.message(), &self.signature)
    }

    /// The pay frame's data: `epoch || salt || signature`.
    #[must_use]
    pub fn pay_data(&self) -> Vec<u8> {
        let mut d = Vec::with_capacity(PAY_DATA_LEN);
        d.extend_from_slice(&self.claim.epoch.to_be_bytes());
        d.extend_from_slice(self.claim.salt.as_slice());
        d.extend_from_slice(&g1_eip2537(&self.signature));
        d
    }

    /// Read the epoch, salt and signature back from a pay frame's data, for the slot of the
    /// transaction that carries it.
    #[must_use]
    pub fn from_pay_data(slot: Slot, data: &[u8]) -> Option<Self> {
        if data.len() != PAY_DATA_LEN {
            return None;
        }
        Some(Self {
            claim: Claim {
                slot,
                epoch: u64::from_be_bytes(data[..8].try_into().ok()?),
                salt: B256::from_slice(&data[8..40]),
            },
            signature: g1_from_eip2537(&data[40..])?,
        })
    }
}

/// EIP-2537's encoding of a G1 point: `x || y`, each a 64-byte big-endian field element.
///
/// # Panics
///
/// Never: a `G1` always decompresses.
#[must_use]
pub fn g1_eip2537(p: &G1) -> [u8; 128] {
    let affine = min_sig::Signature::uncompress(&p.encode())
        .expect("a G1 point decompresses")
        .serialize();
    let mut out = [0u8; 128];
    out[16..64].copy_from_slice(&affine[..48]);
    out[80..].copy_from_slice(&affine[48..]);
    out
}

/// A G1 point from EIP-2537's encoding, if it is one of the group's.
#[must_use]
pub fn g1_from_eip2537(b: &[u8]) -> Option<G1> {
    if b.len() != 128 || b[..16].iter().chain(&b[64..80]).any(|&x| x != 0) {
        return None;
    }
    let mut affine = [0u8; 96];
    affine[..48].copy_from_slice(&b[16..64]);
    affine[48..].copy_from_slice(&b[80..]);
    let compressed = min_sig::Signature::deserialize(&affine).ok()?.compress();
    G1::read(&mut compressed.as_slice()).ok()
}

/// EIP-2537's encoding of a G2 point: `x.c0 || x.c1 || y.c0 || y.c1`, each 64 bytes. blst
/// serializes an Fp2 element `c1` first.
///
/// # Panics
///
/// Never: a `G2` always decompresses.
#[must_use]
pub fn g2_eip2537(p: &G2) -> [u8; 256] {
    let affine = min_sig::PublicKey::uncompress(&p.encode())
        .expect("a G2 point decompresses")
        .serialize();
    let mut out = [0u8; 256];
    for (i, at) in [48, 0, 144, 96].into_iter().enumerate() {
        out[64 * i + 16..64 * (i + 1)].copy_from_slice(&affine[at..at + 48]);
    }
    out
}

#[cfg(test)]
mod tests {
    use commonware_math::algebra::{CryptoGroup, Random};
    use rand::{SeedableRng, rngs::StdRng};

    use super::*;

    /// `TicketPaymaster.yul`'s `negG2`.
    const NEG_G2: &str = "00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    #[test]
    fn the_contracts_negated_generator_is_minus_g2() {
        assert_eq!(hex::encode(g2_eip2537(&-G2::generator())), NEG_G2);
    }

    #[test]
    fn a_g1_point_round_trips_through_eip2537() {
        let mut rng = StdRng::seed_from_u64(2);
        let p = G1::generator()
            * &commonware_cryptography::bls12381::primitives::group::Scalar::random(&mut rng);
        assert_eq!(g1_from_eip2537(&g1_eip2537(&p)), Some(p));
    }
}
