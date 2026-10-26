//! The intent a note's current holder sends for its new owner.
//!
//! It is an ordinary call to the vault's `enqueue(bytes sealed)`, by anyone, and never by the
//! owner: if the owner sent it, the opening that answers it would be tied to the owner's sender.
//! `sealed` carries the owner's [`Receive`] to the committee alone, under the same scheme as an
//! opening:
//!
//! ```text
//! info       "x9/intent"
//! aad        vault (20) || intent index (uint64be)
//! plaintext  opening key P (33) || B(s) packed (32)          65 bytes
//! sealed     0x02 || view tag || E (33) || AES-256-GCM || tag (16)   116 bytes
//! ```
//!
//! The committee's key is the vault's `committeeKey()`.

use alloy::primitives::Address;

use crate::{ExitError, OVERHEAD, OpeningKey, note::Receive, open_with, seal_with};

/// HKDF's info for an intent.
pub const INFO: &[u8] = b"x9/intent";
/// An intent's plaintext: the owner's opening key and secret point.
pub const INTENT_LEN: usize = 33 + 32;
/// A sealed intent's length.
pub const SEALED_LEN: usize = INTENT_LEN + OVERHEAD;

fn aad(vault: Address, index: u64) -> [u8; 28] {
    let mut out = [0u8; 28];
    out[..20].copy_from_slice(vault.as_slice());
    out[20..].copy_from_slice(&index.to_be_bytes());
    out
}

/// Seals `owner` to the committee's key `committee`, for intent `index` of `vault`.
///
/// # Errors
///
/// If `committee` is not a compressed secp256k1 public key.
///
/// # Panics
///
/// Never: a fixed-length plaintext seals to a fixed-length message.
pub fn seal_intent(
    committee: &[u8; 33],
    vault: Address,
    index: u64,
    owner: &Receive,
    ephemeral: &OpeningKey,
) -> Result<[u8; SEALED_LEN], ExitError> {
    let mut plain = [0u8; INTENT_LEN];
    plain[..33].copy_from_slice(&owner.key);
    plain[33..].copy_from_slice(&owner.secret_point);
    let m = seal_with(INFO, committee, &aad(vault, index), &plain, ephemeral)?;
    Ok(m.try_into()
        .expect("a fixed-length plaintext gives a fixed-length message"))
}

/// The committee's side: what intent `index` carries, if it is sealed to `committee`.
#[must_use]
pub fn open_intent(
    committee: &OpeningKey,
    vault: Address,
    index: u64,
    sealed: &[u8],
) -> Option<Receive> {
    let plain = open_with(INFO, committee, &aad(vault, index), sealed, INTENT_LEN)?;
    Some(Receive {
        key: plain[..33].try_into().ok()?,
        secret_point: plain[33..].try_into().ok()?,
    })
}
