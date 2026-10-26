//! The owner's side of an exit that nobody's permission opens (`exp-e2e-frames` X9, after
//! TACEO's "Escape hatches in MPC, and who may open them").
//!
//! A committee holds the owners' notes in a vault. With every update it publishes each new note's
//! opening, sealed to the note's owner. If the vault's queue stalls, the owner finds its latest
//! opening and redeems the note alone.
//!
//! Here: the owner's keys and the sealing (this module), what an opening holds and how the owner
//! checks it ([`note`]), the intent a holder sends for the owner ([`intent`]), and the vault on
//! chain ([`vault`]).
//!
//! **The key.** From the owner's one seed (`kohaku-frame-secrets`):
//!
//! ```text
//! opening key   K("exit/<vault>/opening/<o>")     secp256k1; P = k * G, 33 bytes compressed
//! recipient     K("exit/<vault>/recipient/<o>")   secp256k1; where the o-th redemption pays
//! ```
//!
//! `<vault>` is `0x` and 40 lowercase hex digits, as frame-secrets writes an address.
//!
//! **The sealing.** `exp-frames` experiment 33's announcement, with its own version, label and
//! associated data:
//!
//! ```text
//! shared   = x(e * P)
//! view tag = keccak256(shared)[0]
//! key, iv  = HKDF-SHA256(shared, salt = E, info = "x9/opening"), 32 + 12 bytes
//! aad      = vault (20) || update number (uint64be)
//! message  = 0x02 || view tag || E (33, compressed) || AES-256-GCM(key, iv, plaintext, aad) || tag (16)
//! ```
//!
//! Every plaintext has the same length, [`OPENING_LEN`], so every message has the same length,
//! [`MESSAGE_LEN`]. A message holds no part of `P`, and `E` is fresh each time, so who a message is
//! for is not in it ([`seal`]). Only `P`'s holder can open it ([`open`]), and only under the vault
//! and update it was sealed for.

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use alloy::primitives::{Address, B256, keccak256};
use hkdf::Hkdf;
use k256::{
    PublicKey, SecretKey,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
};
use kohaku_frame_secrets::derive::{DeriveError, Seed};
use sha2::Sha256;

pub mod intent;
pub mod note;
pub mod vault;

/// The sealing's version byte.
pub const VERSION: u8 = 0x02;
/// HKDF's info for an opening's key and nonce.
pub const INFO: &[u8] = b"x9/opening";
/// Every opening's plaintext length: one member's part of a note's nullifier and where it goes
/// ([`note::Part`]).
pub const OPENING_LEN: usize = 48;
/// Version, view tag, ephemeral key and the GCM tag around an opening.
pub const OVERHEAD: usize = 2 + 33 + 16;
/// Every sealed opening's length.
pub const MESSAGE_LEN: usize = OPENING_LEN + OVERHEAD;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ExitError {
    #[error("not a secp256k1 secret key")]
    Secret,
    #[error("not a compressed secp256k1 public key")]
    Public,
    #[error("encryption failed")]
    Seal,
    #[error("derivation: {0}")]
    Derive(String),
}

impl From<DeriveError> for ExitError {
    fn from(e: DeriveError) -> Self {
        ExitError::Derive(e.to_string())
    }
}

/// An opening key pair. `Debug` shows the public key only.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct OpeningKey {
    secret: B256,
    /// Compressed.
    pub public: [u8; 33],
}

impl std::fmt::Debug for OpeningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpeningKey")
            .field("public", &hex::encode(self.public))
            .finish_non_exhaustive()
    }
}

impl OpeningKey {
    pub fn from_secret(secret: B256) -> Result<Self, ExitError> {
        let sk = SecretKey::from_slice(secret.as_slice()).map_err(|_| ExitError::Secret)?;
        let public: [u8; 33] = sk
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .map_err(|_| ExitError::Public)?;
        Ok(Self { secret, public })
    }

    /// A fresh key, for the ephemeral side of a seal and for tests.
    #[must_use]
    pub fn random(rng: &mut impl rand::CryptoRng) -> Self {
        loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            if let Ok(k) = Self::from_secret(B256::from(b)) {
                return k;
            }
        }
    }
}

pub(crate) fn vault_label(vault: Address) -> String {
    format!("0x{}", hex::encode(vault))
}

/// `exit/<vault>/opening/<o>`: the key the vault's committee seals the owner's o-th note's
/// openings to.
pub fn opening_key(seed: &Seed, vault: Address, o: u32) -> Result<OpeningKey, ExitError> {
    let label = format!("exit/{}/opening/{o}", vault_label(vault));
    let signer = seed.secp256k1(&label)?;
    OpeningKey::from_secret(B256::from_slice(&signer.credential().to_bytes()))
}

/// `exit/<vault>/recipient/<o>`: where the owner's o-th redemption pays out.
pub fn recipient(seed: &Seed, vault: Address, o: u32) -> Result<Address, ExitError> {
    Ok(seed
        .secp256k1(&format!("exit/{}/recipient/{o}", vault_label(vault)))?
        .address())
}

/// The context an opening is sealed under: it opens for this vault and this update only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    pub vault: Address,
    pub update: u64,
}

impl Context {
    #[must_use]
    pub fn aad(&self) -> [u8; 28] {
        let mut out = [0u8; 28];
        out[..20].copy_from_slice(self.vault.as_slice());
        out[20..].copy_from_slice(&self.update.to_be_bytes());
        out
    }
}

fn shared(secret: &B256, public: &[u8; 33]) -> Result<[u8; 32], ExitError> {
    let sk = SecretKey::from_slice(secret.as_slice()).map_err(|_| ExitError::Secret)?;
    let point = k256::EncodedPoint::from_bytes(public).map_err(|_| ExitError::Public)?;
    let pk = Option::<PublicKey>::from(PublicKey::from_encoded_point(&point))
        .ok_or(ExitError::Public)?;
    let x = k256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    Ok((*x.raw_secret_bytes()).into())
}

fn cipher(shared: &[u8; 32], ephemeral: &[u8; 33], info: &[u8]) -> (Aes256Gcm, [u8; 12]) {
    let mut okm = [0u8; 44];
    Hkdf::<Sha256>::new(Some(ephemeral), shared)
        .expand(info, &mut okm)
        .expect("44 bytes is a valid HKDF-SHA256 length");
    let cipher = Aes256Gcm::new_from_slice(&okm[..32]).expect("a 32-byte key");
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&okm[32..]);
    (cipher, iv)
}

/// The scheme under any label: `VERSION || view tag || E || AES-256-GCM(plaintext, aad) || tag`.
pub(crate) fn seal_with(
    info: &[u8],
    to: &[u8; 33],
    aad: &[u8],
    plaintext: &[u8],
    ephemeral: &OpeningKey,
) -> Result<Vec<u8>, ExitError> {
    let s = shared(&ephemeral.secret, to)?;
    let (c, iv) = cipher(&s, &ephemeral.public, info);
    let body = c
        .encrypt(
            &Nonce::from(iv),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| ExitError::Seal)?;
    let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
    out.push(VERSION);
    out.push(keccak256(s)[0]);
    out.extend_from_slice(&ephemeral.public);
    out.extend_from_slice(&body);
    Ok(out)
}

pub(crate) fn open_with(
    info: &[u8],
    key: &OpeningKey,
    aad: &[u8],
    message: &[u8],
    len: usize,
) -> Option<Vec<u8>> {
    if message.len() != len + OVERHEAD || message[0] != VERSION {
        return None;
    }
    let ephemeral: [u8; 33] = message[2..35].try_into().ok()?;
    let s = shared(&key.secret, &ephemeral).ok()?;
    if keccak256(s)[0] != message[1] {
        return None;
    }
    let (c, iv) = cipher(&s, &ephemeral, info);
    c.decrypt(
        &Nonce::from(iv),
        Payload {
            msg: &message[35..],
            aad,
        },
    )
    .ok()
}

/// Seals `opening` to `to` under `context`, with the fresh key `ephemeral`.
///
/// # Errors
///
/// If `to` is not a compressed secp256k1 public key.
///
/// # Panics
///
/// Never: a fixed-length plaintext seals to a fixed-length message.
pub fn seal(
    to: &[u8; 33],
    context: &Context,
    opening: &[u8; OPENING_LEN],
    ephemeral: &OpeningKey,
) -> Result<[u8; MESSAGE_LEN], ExitError> {
    let m = seal_with(INFO, to, &context.aad(), opening, ephemeral)?;
    Ok(m.try_into()
        .expect("a fixed-length plaintext gives a fixed-length message"))
}

/// Opens `message` with `key` under `context`, or `None` if it is not for `key`, not for this
/// context, or malformed. A wrong view tag ends it before any decryption.
#[must_use]
pub fn open(key: &OpeningKey, context: &Context, message: &[u8]) -> Option<[u8; OPENING_LEN]> {
    open_with(INFO, key, &context.aad(), message, OPENING_LEN)?
        .try_into()
        .ok()
}

/// One update's published openings, in the order the vault emitted them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Published {
    pub context: Context,
    pub messages: Vec<Vec<u8>>,
}

/// An opening found for `key`: where it was published and what it says.
#[derive(Clone, PartialEq, Eq)]
pub struct Found {
    pub update: u64,
    pub position: usize,
    pub opening: [u8; OPENING_LEN],
}

impl std::fmt::Debug for Found {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Found")
            .field("update", &self.update)
            .field("position", &self.position)
            .finish_non_exhaustive()
    }
}

/// Every opening for `key` among `published`, oldest update first.
#[must_use]
pub fn scan(key: &OpeningKey, published: &[Published]) -> Vec<Found> {
    let mut found: Vec<Found> = published
        .iter()
        .flat_map(|p| {
            p.messages
                .iter()
                .enumerate()
                .filter_map(move |(position, m)| {
                    open(key, &p.context, m).map(|opening| Found {
                        update: p.context.update,
                        position,
                        opening,
                    })
                })
        })
        .collect();
    found.sort_by_key(|f| (f.update, f.position));
    found
}

/// The latest opening for `key`: the one the owner redeems with.
#[must_use]
pub fn latest(key: &OpeningKey, published: &[Published]) -> Option<Found> {
    scan(key, published).pop()
}
