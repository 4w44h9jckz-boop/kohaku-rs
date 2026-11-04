//! The wallet's keys in a post-quantum form (`exp-frames` experiment 49): leanSPHINCS keys from
//! the seed, and the EIP-8288 dependencies that let an account or a paymaster accept them.
//!
//! leanSPHINCS is leanVM's at `3cbac04`: a 32-byte secret seed, a 32-byte public key laid out as
//! `root (16) || public parameter (16)`, a 7,740-byte signature on a 32-byte message, stateless,
//! at most $2^{30}$ signatures per key. leanVM says its parameters are not final.
//!
//! A key authorises a transaction when the transaction declares the triple
//!
//! ```text
//! scheme (32: 31 zero bytes, then 0x10) || data_hash (32: zero) || key (32)
//! ```
//!
//! EIP-8288 reads a zero `data_hash` as the transaction's signature hash, and the block's proof
//! checks a signature by `key` over it. Where EIP-8288 runs, the triple is in a dependency frame
//! (mode 4) of its own; where it is modelled, it travels in the checking frame's own data and the
//! signature is checked off chain with [`verify`].
//!
//! Labels, under [`Seed::key`]:
//!
//! ```text
//! sphincs/account/<i>/owner/<j>   account i's owner, the j-th since it was made
//! sphincs/ticket/<k>/sender       ticket k's fresh sender
//! sphincs/ticket/<k>/binder       ticket k's one-time key
//! sphincs/recipient/<n>           the pool's n-th recipient
//! ```

pub mod account;
pub mod envelope;
pub mod seal;
pub mod ticket;

use alloy::primitives::{B256, U256};
use kohaku_frame_kit::Frame;
use kohaku_frame_secrets::Seed;
use signatures::lean_sphincs as sp;

/// `LEANSPHINCS_SCHEME`, EIP-8288.
pub const LEANSPHINCS_SCHEME: u8 = 0x10;
/// `LEANSPHINCS_VERIFICATION_GAS`, EIP-8288: what each leanSPHINCS dependency declares.
pub const LEANSPHINCS_VERIFICATION_GAS: u64 = 3_000;
/// `DEP_VERIFY_FRAME_MODE`, EIP-8288.
pub const DEP_VERIFY_FRAME_MODE: u8 = 4;
/// A public key's length.
pub const PUBLIC_KEY_LEN: usize = sp::PUB_KEY_SIZE;
/// A signature's length.
pub const SIGNATURE_LEN: usize = sp::SIG_SIZE;
/// A triple's length.
pub const TRIPLE_LEN: usize = 96;

#[derive(Debug, thiserror::Error)]
pub enum PqError {
    #[error("leanSPHINCS could not sign: {0:?}")]
    Sign(sp::LeanSphincsSignError),
    #[error("a signature is {0} bytes, not {SIGNATURE_LEN}")]
    SignatureLength(usize),
}

/// A leanSPHINCS key pair. Its `Debug` prints the public key only.
pub struct SphincsKey {
    secret: sp::LeanSphincsSecretKey,
    public: sp::LeanSphincsPublicKey,
}

impl std::fmt::Debug for SphincsKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SphincsKey")
            .field("public", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl SphincsKey {
    /// The key pair of a 32-byte seed, leanVM's deterministic key generation.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let (secret, public) = sp::key_gen_from_seed(seed);
        Self { secret, public }
    }

    /// The key at `label` under the wallet's seed.
    #[must_use]
    pub fn derive(seed: &Seed, label: &str) -> Self {
        Self::from_seed(seed.key(label))
    }

    /// The 32-byte public key, `root || public parameter`.
    #[must_use]
    pub fn public_key(&self) -> B256 {
        B256::from(self.public.to_bytes())
    }

    /// A signature on a 32-byte message.
    pub fn sign(&self, message: B256) -> Result<Vec<u8>, PqError> {
        sp::sign(&self.secret, &message.0)
            .map(|s| s.to_bytes().to_vec())
            .map_err(PqError::Sign)
    }

    /// The triple by which a transaction declares this key's signature over its signature hash.
    #[must_use]
    pub fn triple(&self) -> [u8; TRIPLE_LEN] {
        triple(self.public_key(), B256::ZERO)
    }
}

/// Whether `signature` is `key`'s on `message`.
pub fn verify(key: B256, message: B256, signature: &[u8]) -> Result<bool, PqError> {
    let bytes: &[u8; SIGNATURE_LEN] = signature
        .try_into()
        .map_err(|_| PqError::SignatureLength(signature.len()))?;
    let public = sp::LeanSphincsPublicKey::from_bytes(&key.0);
    Ok(sp::verify(&public, &message.0, &sp::LeanSphincsSignature::from_bytes(bytes)).is_ok())
}

/// `scheme || data_hash || key` for a leanSPHINCS dependency; a zero `data_hash` stands for the
/// transaction's signature hash.
#[must_use]
pub fn triple(key: B256, data_hash: B256) -> [u8; TRIPLE_LEN] {
    let mut t = [0u8; TRIPLE_LEN];
    t[31] = LEANSPHINCS_SCHEME;
    t[32..64].copy_from_slice(data_hash.as_slice());
    t[64..].copy_from_slice(key.as_slice());
    t
}

/// A dependency frame declaring `triples`: no target, no value, no flags, and the execution limit
/// EIP-8288 fixes, 3,000 per leanSPHINCS dependency.
#[must_use]
pub fn dependency_frame(triples: &[[u8; TRIPLE_LEN]]) -> Frame {
    Frame {
        mode: DEP_VERIFY_FRAME_MODE,
        data: triples.concat().into(),
        value: U256::ZERO,
        ..Frame::default()
    }
    .with_execution(LEANSPHINCS_VERIFICATION_GAS * triples.len() as u64)
}

/// Account `i`'s `j`-th owner.
#[must_use]
pub fn owner(seed: &Seed, i: u32, j: u32) -> SphincsKey {
    SphincsKey::derive(seed, &format!("sphincs/account/{i}/owner/{j}"))
}

/// Ticket `k`'s fresh sender.
#[must_use]
pub fn sender(seed: &Seed, k: u32) -> SphincsKey {
    SphincsKey::derive(seed, &format!("sphincs/ticket/{k}/sender"))
}

/// Ticket `k`'s one-time key.
#[must_use]
pub fn binder(seed: &Seed, k: u32) -> SphincsKey {
    SphincsKey::derive(seed, &format!("sphincs/ticket/{k}/binder"))
}

/// The pool's `n`-th recipient.
#[must_use]
pub fn recipient(seed: &Seed, n: u32) -> SphincsKey {
    SphincsKey::derive(seed, &format!("sphincs/recipient/{n}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    #[test]
    fn keys_sign_and_verify_and_refuse_another_message() {
        let key = SphincsKey::from_seed([7u8; 32]);
        let m = B256::repeat_byte(0x42);
        let sig = key.sign(m).unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(verify(key.public_key(), m, &sig).unwrap());
        assert!(!verify(key.public_key(), B256::repeat_byte(0x43), &sig).unwrap());
        let other = SphincsKey::from_seed([8u8; 32]);
        assert!(!verify(other.public_key(), m, &sig).unwrap());
    }

    #[test]
    fn labels_give_distinct_deterministic_keys() {
        let seed = Seed::from_mnemonic(WORDS).unwrap();
        let a = owner(&seed, 0, 0).public_key();
        assert_eq!(a, owner(&seed, 0, 0).public_key());
        let all = [
            a,
            owner(&seed, 0, 1).public_key(),
            owner(&seed, 1, 0).public_key(),
            sender(&seed, 0).public_key(),
            binder(&seed, 0).public_key(),
            recipient(&seed, 0).public_key(),
        ];
        for (x, p) in all.iter().enumerate() {
            for q in &all[x + 1..] {
                assert_ne!(p, q);
            }
        }
    }

    #[test]
    fn the_triple_and_the_frame_are_eip_8288s() {
        let key = B256::repeat_byte(0xab);
        let t = triple(key, B256::ZERO);
        assert_eq!(&t[..31], &[0u8; 31]);
        assert_eq!(t[31], 0x10);
        assert_eq!(&t[32..64], &[0u8; 32]);
        assert_eq!(&t[64..], key.as_slice());
        let f = dependency_frame(&[t, t]);
        assert_eq!(f.mode, 4);
        assert!(f.target.is_none());
        assert_eq!(f.flags, 0);
        assert_eq!(f.limits.execution, 6_000);
        assert_eq!(f.limits.state, 0);
        assert_eq!(f.data.len(), 192);
    }

    #[test]
    fn debug_prints_no_secret() {
        let key = SphincsKey::from_seed([9u8; 32]);
        let shown = format!("{key:?}");
        assert!(shown.contains(&format!("{}", key.public_key())));
        assert!(!shown.contains(&hex::encode([9u8; 32])));
    }
}
