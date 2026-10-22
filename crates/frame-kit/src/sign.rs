//! Signing and checking frame transaction signatures.
//!
//! An entry with an empty `msg` signs the signature hash; an entry with a 32-byte `msg` signs
//! that digest. The signature hash elides only empty-`msg` signatures, so an explicit-digest
//! signature is part of what the others sign: [`sign_all`] fills every explicit-digest entry
//! first, then every signature-hash entry.

use alloy::{
    primitives::{Address, B256, Bytes, Signature, U256, keccak256},
    signers::{SignerSync, local::PrivateKeySigner},
};
use p256::ecdsa::{
    self as p256_ecdsa,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};

use crate::{
    constants::scheme,
    tx::{FrameSignature, FrameTx},
};

/// A key that can fill a frame transaction's signature entries.
#[derive(Debug, Clone)]
pub enum FrameSigner {
    Secp256k1(PrivateKeySigner),
    /// secp256r1, as a passkey or a secure enclave holds it.
    P256(p256_ecdsa::SigningKey),
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("secp256k1: {0}")]
    Secp256k1(#[from] alloy::signers::Error),
    #[error("P256: {0}")]
    P256(#[from] p256_ecdsa::Error),
    #[error("no {scheme} signature entry resolves to {address}")]
    NoEntry {
        scheme: &'static str,
        address: Address,
    },
    #[error("explicit msg must be 32 bytes, got {0}")]
    BadMsg(usize),
    #[error("signature must be {expected} bytes, got {got}")]
    BadLength { expected: usize, got: usize },
    #[error("y_parity must be 0 or 1, got {0}")]
    YParity(u8),
    #[error("unsupported signature scheme {0}")]
    Scheme(u8),
}

impl FrameSigner {
    #[must_use]
    pub fn scheme(&self) -> u8 {
        match self {
            Self::Secp256k1(_) => scheme::SECP256K1,
            Self::P256(_) => scheme::P256,
        }
    }

    /// The address an entry names this key by.
    #[must_use]
    pub fn address(&self) -> Address {
        match self {
            Self::Secp256k1(k) => k.address(),
            Self::P256(k) => p256_address(k.verifying_key()),
        }
    }

    /// Sign a 32-byte digest as the protocol expects it, with no prehash and a low `s`.
    ///
    /// `SECP256K1`: `y_parity || r || s` with a bare recovery id (0 or 1, not 27 or 28).
    /// `P256`: `r || s || qx || qy`.
    pub fn sign(&self, digest: B256) -> Result<Bytes, SignError> {
        match self {
            Self::Secp256k1(k) => {
                let sig = k.sign_hash_sync(&digest)?;
                let mut out = Vec::with_capacity(65);
                out.push(u8::from(sig.v()));
                out.extend_from_slice(&sig.r().to_be_bytes::<32>());
                out.extend_from_slice(&sig.s().to_be_bytes::<32>());
                Ok(out.into())
            }
            Self::P256(k) => {
                let sig: p256_ecdsa::Signature = k.sign_prehash(digest.as_slice())?;
                let sig = sig.normalize_s().unwrap_or(sig);
                let mut out = sig.to_bytes().to_vec();
                out.extend_from_slice(&p256_coordinates(k.verifying_key()));
                Ok(out.into())
            }
        }
    }

    /// An entry for this key with an empty signature, to be filled by [`sign_all`]. `signer: None`
    /// means the key is `tx.sender`'s.
    #[must_use]
    pub fn placeholder(&self, signer: Option<Address>) -> FrameSignature {
        FrameSignature {
            scheme: self.scheme(),
            signer,
            ..FrameSignature::default()
        }
    }
}

/// `qx || qy`, 64 bytes.
fn p256_coordinates(key: &p256_ecdsa::VerifyingKey) -> [u8; 64] {
    let point = key.to_encoded_point(false);
    let mut out = [0u8; 64];
    out.copy_from_slice(&point.as_bytes()[1..]);
    out
}

/// A P256 signer's address: `keccak256(qx || qy)[12..]`.
#[must_use]
pub fn p256_address(key: &p256_ecdsa::VerifyingKey) -> Address {
    Address::from_slice(&keccak256(p256_coordinates(key))[12..])
}

/// Fill every entry that resolves to one of `keys`, explicit digests first, then the signature
/// hash. Entries for other signers are left alone. Fails if a key fills no entry, since that is
/// always a mistake in the caller's layout.
pub fn sign_all(tx: &mut FrameTx, keys: &[FrameSigner]) -> Result<(), SignError> {
    let mut filled = vec![0usize; keys.len()];
    for sig_hash_entries in [false, true] {
        for (i, key) in keys.iter().enumerate() {
            let me = key.address();
            let sig_hash = tx.sig_hash();
            let sender = tx.sender;
            for entry in &mut tx.signatures {
                if entry.scheme != key.scheme()
                    || entry.signer.unwrap_or(sender) != me
                    || entry.msg.is_empty() != sig_hash_entries
                {
                    continue;
                }
                let digest = if sig_hash_entries {
                    sig_hash
                } else {
                    explicit_digest(&entry.msg)?
                };
                entry.signature = key.sign(digest)?;
                filled[i] += 1;
            }
        }
    }
    if let Some(i) = filled.iter().position(|&n| n == 0) {
        return Err(SignError::NoEntry {
            scheme: if keys[i].scheme() == scheme::P256 {
                "P256"
            } else {
                "SECP256K1"
            },
            address: keys[i].address(),
        });
    }
    Ok(())
}

fn explicit_digest(msg: &[u8]) -> Result<B256, SignError> {
    B256::try_from(msg).map_err(|_| SignError::BadMsg(msg.len()))
}

/// The address a `SECP256K1` or `P256` entry proves, given the transaction's signature hash:
/// the recovered signer for `SECP256K1`, and for `P256` the address of the embedded key once the
/// signature verifies against it. The protocol then compares it with `signer` (or `tx.sender`).
/// Malleability is not checked here: a high `s` is accepted.
pub fn signer_of(entry: &FrameSignature, sig_hash: B256) -> Result<Address, SignError> {
    let digest = if entry.msg.is_empty() {
        sig_hash
    } else {
        explicit_digest(&entry.msg)?
    };
    let sig = entry.signature.as_ref();
    match entry.scheme {
        scheme::SECP256K1 => {
            if sig.len() != 65 {
                return Err(SignError::BadLength {
                    expected: 65,
                    got: sig.len(),
                });
            }
            if sig[0] > 1 {
                return Err(SignError::YParity(sig[0]));
            }
            let signature = Signature::new(
                U256::from_be_slice(&sig[1..33]),
                U256::from_be_slice(&sig[33..]),
                sig[0] == 1,
            );
            signature
                .recover_address_from_prehash(&digest)
                .map_err(|e| SignError::Secp256k1(e.into()))
        }
        scheme::P256 => {
            if sig.len() != 128 {
                return Err(SignError::BadLength {
                    expected: 128,
                    got: sig.len(),
                });
            }
            let signature = p256_ecdsa::Signature::from_slice(&sig[..64])?;
            let mut sec1 = [0u8; 65];
            sec1[0] = 0x04;
            sec1[1..].copy_from_slice(&sig[64..]);
            let key = p256_ecdsa::VerifyingKey::from_sec1_bytes(&sec1)?;
            key.verify_prehash(digest.as_slice(), &signature)?;
            Ok(p256_address(&key))
        }
        other => Err(SignError::Scheme(other)),
    }
}
