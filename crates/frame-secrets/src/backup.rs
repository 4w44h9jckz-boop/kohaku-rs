//! An encrypted backup that anyone can store (`exp-frames` experiment 47).
//!
//! ```text
//! key v      K("backup/<v>/key")          locator v   K("backup/<v>/locator")
//! posted     locator (32) || nonce (12) || AES-256-GCM(padded, aad = locator) || tag (16)
//! padded     uint32be(length) || plaintext || zeros, to a multiple of 2,048 bytes
//! ```
//!
//! Each version has its own key and its own locator, so one version's key opens that version
//! and no other, and two versions cannot be told to be the same wallet's from what is posted. A
//! fresh device with the seed counts `v` up from 0 until a locator is not found. There is no tag
//! byte: what is posted is random bytes of a bucket's size.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead, aead::Payload};
use alloy::primitives::B256;
use rand::CryptoRng;

use crate::Seed;

/// Plaintexts are padded to a multiple of this.
pub const BUCKET: usize = 2048;
/// Locator, nonce and tag around the padded plaintext.
pub const OVERHEAD: usize = 32 + 12 + 16;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackupError {
    #[error("not this version's backup")]
    NotThis,
    #[error("the backup does not open under this key")]
    Open,
    #[error("the plaintext is malformed")]
    Malformed,
}

/// Version `v`'s key and locator.
#[must_use]
pub fn keys(seed: &Seed, v: u32) -> ([u8; 32], B256) {
    (seed.backup_key(v), seed.backup_locator(v))
}

fn pad(plaintext: &[u8]) -> Vec<u8> {
    let len = u32::try_from(plaintext.len()).expect("a backup under 4 GiB");
    let mut p = len.to_be_bytes().to_vec();
    p.extend_from_slice(plaintext);
    p.resize(p.len().div_ceil(BUCKET) * BUCKET, 0);
    p
}

/// Seal `plaintext` as version `v`'s backup under `key`, posted under `locator`.
///
/// # Panics
///
/// Never: AES-GCM encrypts any plaintext under 64 GiB.
#[must_use]
pub fn seal(key: &[u8; 32], locator: B256, plaintext: &[u8], rng: &mut impl CryptoRng) -> Vec<u8> {
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let body = Aes256Gcm::new_from_slice(key)
        .expect("a 32-byte key")
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &pad(plaintext),
                aad: locator.as_slice(),
            },
        )
        .expect("encrypts");
    let mut out = locator.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    out
}

/// Whether `posted` is under `locator`, without opening it.
#[must_use]
pub fn is_at(posted: &[u8], locator: B256) -> bool {
    posted.len() >= OVERHEAD && posted[..32] == locator[..]
}

/// Open a posted backup with version `v`'s key and locator.
pub fn open(key: &[u8; 32], locator: B256, posted: &[u8]) -> Result<Vec<u8>, BackupError> {
    if !is_at(posted, locator) {
        return Err(BackupError::NotThis);
    }
    let nonce: [u8; 12] = posted[32..44]
        .try_into()
        .map_err(|_| BackupError::Malformed)?;
    let padded = Aes256Gcm::new_from_slice(key)
        .map_err(|_| BackupError::Open)?
        .decrypt(
            &Nonce::from(nonce),
            Payload {
                msg: &posted[44..],
                aad: locator.as_slice(),
            },
        )
        .map_err(|_| BackupError::Open)?;
    let len = u32::from_be_bytes(
        padded
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .ok_or(BackupError::Malformed)?,
    ) as usize;
    padded
        .get(4..4 + len)
        .map(<[u8]>::to_vec)
        .ok_or(BackupError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    #[test]
    fn a_version_opens_under_its_own_key_only() {
        let seed = Seed::from_mnemonic(PHRASE).unwrap();
        let mut rng = rand::rng();
        let (k0, l0) = keys(&seed, 0);
        let (k1, l1) = keys(&seed, 1);
        let b0 = seal(&k0, l0, b"version zero", &mut rng);
        let b1 = seal(&k1, l1, &[7u8; 3000], &mut rng);
        assert_eq!(b0.len(), OVERHEAD + BUCKET);
        assert_eq!(b1.len(), OVERHEAD + 2 * BUCKET);
        assert_eq!(open(&k0, l0, &b0).unwrap(), b"version zero");
        assert_eq!(open(&k1, l1, &b1).unwrap(), vec![7u8; 3000]);
        assert_eq!(open(&k0, l0, &b1).unwrap_err(), BackupError::NotThis);
        // Version 0's key, with version 1's locator, opens nothing.
        assert_eq!(open(&k0, l1, &b1).unwrap_err(), BackupError::Open);
        // A backup moved under another locator does not open: the locator is bound.
        let mut moved = b0.clone();
        moved[..32].copy_from_slice(l1.as_slice());
        assert_eq!(open(&k0, l1, &moved).unwrap_err(), BackupError::Open);
    }
}
