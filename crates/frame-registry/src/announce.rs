//! Encrypted announcements on a board, and the two messages of a swap (`exp-frames`
//! experiment 33).
//!
//! A message is sealed to a recipient's secp256k1 public key `P` with a fresh key `e`:
//!
//! ```text
//! shared   = x(e * P)                                        32 bytes
//! view tag = keccak256(shared)[0]                            lets a scanner skip most messages
//! key, iv  = HKDF-SHA256(shared, salt = E, info = "exp-frames/33/announcement"), 32 + 12 bytes
//! message  = 0x01 || view tag || E (33, compressed) || AES-256-GCM(key, iv, plaintext) || tag (16)
//! ```
//!
//! A wallet scans the board's `Posted` events and opens what it can ([`scan`]). Nobody else
//! learns who a message is for; who posted it is the posting transaction's sender.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::{SolCall, SolEvent},
};
use hkdf::Hkdf;
use k256::{PublicKey, SecretKey, elliptic_curve::sec1::ToEncodedPoint};
use kohaku_frame_kit::Frame;
use sha2::Sha256;

const INFO: &[u8] = b"exp-frames/33/announcement";
const VERSION: u8 = 0x01;
/// Version, view tag, ephemeral key and the GCM tag around a plaintext.
pub const OVERHEAD: usize = 2 + 33 + 16;

/// The board's interface, as `Board.yul` implements it.
pub mod abi {
    alloy::sol! {
        function post(bytes message);
        event Posted(bytes message);
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AnnounceError {
    #[error("not a secp256k1 secret key")]
    Secret,
    #[error("not a compressed secp256k1 public key")]
    Public,
    #[error("encryption failed")]
    Seal,
}

/// An announcement key pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Keys {
    pub secret: B256,
    /// Compressed.
    pub public: [u8; 33],
}

impl Keys {
    pub fn from_secret(secret: B256) -> Result<Self, AnnounceError> {
        let sk = SecretKey::from_slice(secret.as_slice()).map_err(|_| AnnounceError::Secret)?;
        let point = sk.public_key().to_encoded_point(true);
        let mut public = [0u8; 33];
        public.copy_from_slice(point.as_bytes());
        Ok(Self { secret, public })
    }

    /// Keys from a seed and a label, as `exp-frames` experiment 33 derives them:
    /// `keccak256(seed || "exp-frames/33/key/<label>")`.
    pub fn derive(seed: &[u8], label: &str) -> Result<Self, AnnounceError> {
        let mut buf = seed.to_vec();
        buf.extend_from_slice(format!("exp-frames/33/key/{label}").as_bytes());
        Self::from_secret(keccak256(buf))
    }
}

fn shared(secret: B256, public: &[u8]) -> Option<[u8; 32]> {
    let sk = SecretKey::from_slice(secret.as_slice()).ok()?;
    let pk = PublicKey::from_sec1_bytes(public).ok()?;
    let s = k256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    Some((*s.raw_secret_bytes()).into())
}

fn cipher(shared: &[u8; 32], ephemeral: &[u8]) -> (Aes256Gcm, [u8; 12]) {
    let mut okm = [0u8; 44];
    Hkdf::<Sha256>::new(Some(ephemeral), shared)
        .expand(INFO, &mut okm)
        .expect("44 bytes is a valid HKDF-SHA256 length");
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&okm[32..]);
    (
        Aes256Gcm::new_from_slice(&okm[..32]).expect("a 32-byte key"),
        iv,
    )
}

/// Seal `plaintext` to `to` with the ephemeral key `ephemeral`.
pub fn seal(to: &[u8; 33], plaintext: &[u8], ephemeral: &Keys) -> Result<Vec<u8>, AnnounceError> {
    let shared = shared(ephemeral.secret, to).ok_or(AnnounceError::Public)?;
    let (aes, iv) = cipher(&shared, &ephemeral.public);
    let body = aes
        .encrypt(&Nonce::from(iv), plaintext)
        .map_err(|_| AnnounceError::Seal)?;
    let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
    out.push(VERSION);
    out.push(keccak256(shared)[0]);
    out.extend_from_slice(&ephemeral.public);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open a message with `secret`, or `None` if it is not for this key.
#[must_use]
pub fn open(secret: B256, message: &[u8]) -> Option<Vec<u8>> {
    if message.len() < OVERHEAD || message[0] != VERSION {
        return None;
    }
    let ephemeral = &message[2..35];
    let shared = shared(secret, ephemeral)?;
    if keccak256(shared)[0] != message[1] {
        return None;
    }
    let (aes, iv) = cipher(&shared, ephemeral);
    aes.decrypt(&Nonce::from(iv), &message[35..]).ok()
}

/// An offer is named by the hash of its message as posted.
#[must_use]
pub fn offer_id(message: &[u8]) -> B256 {
    keccak256(message)
}

/// A `SENDER` frame posting `message` to `board`.
#[must_use]
pub fn post_frame(board: Address, message: &[u8]) -> Frame {
    Frame::sender(Some(board))
        .with_data(
            abi::postCall {
                message: Bytes::copy_from_slice(message),
            }
            .abi_encode(),
        )
        .with_execution(40_000)
}

/// A message on the board, and where it was posted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posted {
    pub message: Bytes,
    pub tx: B256,
    pub block: u64,
}

/// Every message posted to `board`, oldest first.
pub async fn board_messages<P: Provider>(
    provider: &P,
    board: Address,
) -> Result<Vec<Posted>, alloy::transports::TransportError> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(board)
                .event_signature(abi::Posted::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?;
    Ok(logs
        .iter()
        .filter_map(|l| {
            let p = abi::Posted::decode_log_data(l.data()).ok()?;
            Some(Posted {
                message: p.message,
                tx: l.transaction_hash?,
                block: l.block_number?,
            })
        })
        .collect())
}

/// The messages `secret` can open, with their plaintexts.
#[must_use]
pub fn scan(secret: B256, messages: &[Posted]) -> Vec<(Posted, Vec<u8>)> {
    messages
        .iter()
        .filter_map(|m| open(secret, &m.message).map(|p| (m.clone(), p)))
        .collect()
}

/// What an offer gives or wants: an application and an amount of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Side {
    pub app: Address,
    pub value: u64,
}

/// An offer: what the offerer gives and wants, the note it spends, and where to answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offer {
    pub registry: Address,
    pub give: Side,
    pub want: Side,
    /// The expiry frame's deadline both proofs will bind.
    pub deadline: u64,
    /// The nullifier of the note the offerer gives.
    pub nullifier: U256,
    /// The offerer's inner for the note it receives.
    pub receive_inner: U256,
    /// The offerer's announcement key, for the answer.
    pub reply_key: [u8; 33],
}

impl Offer {
    pub const LEN: usize = 182;

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.push(0x01);
        out.extend_from_slice(self.registry.as_slice());
        out.extend_from_slice(self.give.app.as_slice());
        out.extend_from_slice(&self.give.value.to_be_bytes());
        out.extend_from_slice(self.want.app.as_slice());
        out.extend_from_slice(&self.want.value.to_be_bytes());
        out.extend_from_slice(&self.deadline.to_be_bytes());
        out.extend_from_slice(&self.nullifier.to_be_bytes::<32>());
        out.extend_from_slice(&self.receive_inner.to_be_bytes::<32>());
        out.extend_from_slice(&self.reply_key);
        out
    }

    /// `None` unless `p` is one, by length and kind.
    ///
    /// # Panics
    ///
    /// Never: the length is checked first.
    #[must_use]
    pub fn decode(p: &[u8]) -> Option<Self> {
        if p.len() != Self::LEN || p[0] != 0x01 {
            return None;
        }
        let u64_at = |i: usize| u64::from_be_bytes(p[i..i + 8].try_into().expect("8 bytes"));
        Some(Self {
            registry: Address::from_slice(&p[1..21]),
            give: Side {
                app: Address::from_slice(&p[21..41]),
                value: u64_at(41),
            },
            want: Side {
                app: Address::from_slice(&p[49..69]),
                value: u64_at(69),
            },
            deadline: u64_at(77),
            nullifier: U256::from_be_slice(&p[85..117]),
            receive_inner: U256::from_be_slice(&p[117..149]),
            reply_key: p[149..182].try_into().expect("33 bytes"),
        })
    }
}

/// An answer: the offer it accepts, the note the acceptor gives, and the root to prove against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Accept {
    pub offer: B256,
    pub nullifier: U256,
    pub receive_inner: U256,
    pub root: U256,
    pub slot: u64,
}

impl Accept {
    pub const LEN: usize = 137;

    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.push(0x02);
        out.extend_from_slice(self.offer.as_slice());
        out.extend_from_slice(&self.nullifier.to_be_bytes::<32>());
        out.extend_from_slice(&self.receive_inner.to_be_bytes::<32>());
        out.extend_from_slice(&self.root.to_be_bytes::<32>());
        out.extend_from_slice(&self.slot.to_be_bytes());
        out
    }

    /// `None` unless `p` is one, by length and kind.
    ///
    /// # Panics
    ///
    /// Never: the length is checked first.
    #[must_use]
    pub fn decode(p: &[u8]) -> Option<Self> {
        if p.len() != Self::LEN || p[0] != 0x02 {
            return None;
        }
        Some(Self {
            offer: B256::from_slice(&p[1..33]),
            nullifier: U256::from_be_slice(&p[33..65]),
            receive_inner: U256::from_be_slice(&p[65..97]),
            root: U256::from_be_slice(&p[97..129]),
            slot: u64::from_be_bytes(p[129..137].try_into().expect("8 bytes")),
        })
    }
}
