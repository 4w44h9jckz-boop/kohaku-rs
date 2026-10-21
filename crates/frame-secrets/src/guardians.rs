//! Social recovery that does not hand anyone the seed (`exp-frames` experiment 46).
//!
//! The account is experiment 31's `DeviceRecoveryAccount`, unchanged, with one "device": a
//! recovery key `R` that exists whole only twice, when it is made and when it is used.
//!
//! ```text
//! R           a fresh secp256k1 key for each guardian set, never derived from the seed
//! shares      Shamir t-of-n of R over secp256k1's scalar field, one to each guardian:
//!             index (1 byte) || y (32 bytes)
//! commitment  keccak256(salt || 1 || address(R)), salt = K("account/<i>/recovery-salt/<r>")
//! envelope    the seed's words, sealed under
//!             key = HKDF-SHA256(IKM = R || P, salt = "kohaku-seed-envelope-v1", info = address(R))
//!             P   = Argon2id(the user's phrase, salt = "kohaku-seed-envelope-v1" || address(R))
//!             0x20 || locator (32) || nonce (12) || AES-256-GCM(words padded to 216 bytes) || tag (16)
//! locator     keccak256("kohaku-seed-envelope-v1" || address(R))
//! ```
//!
//! The account checks only `R`'s signature, behind its delay, which its owner can cancel. The
//! seed is not on the chain's side of the delay: whoever opens the envelope has every note at
//! once. So the envelope needs `R` and a phrase the user keeps, which no guardian holds. A quorum
//! of guardians without the phrase gets nothing from it, and without the seed it does not know the
//! salt, so it cannot even reveal the account's commitment.
//!
//! Rotation is the owner's `0x04` with a new commitment, for a new `R` split to a new set. It
//! needs neither the old set nor the old `R`. The old envelope stays wherever it was posted.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use alloy::{
    primitives::{Address, B256, keccak256},
    signers::local::PrivateKeySigner,
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use k256::{Scalar, elliptic_curve::PrimeField};
use rand::CryptoRng;
use sha2::Sha256;

/// The envelope's domain, in its key, its stretch and its locator.
pub const ENVELOPE_DOMAIN: &[u8] = b"kohaku-seed-envelope-v1";
/// The first byte of an envelope on the board.
pub const ENVELOPE_TAG: u8 = 0x20;
/// The words, padded with spaces so that every envelope is the same size.
pub const PADDED_WORDS: usize = 216;
pub const ENVELOPE_LEN: usize = 1 + 32 + 12 + PADDED_WORDS + 16;
/// RFC 9106's second recommended Argon2id setting, with one lane: 64 MiB, three passes.
pub const ARGON2_MEMORY_KIB: u32 = 65_536;
pub const ARGON2_PASSES: u32 = 3;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuardianError {
    #[error("a share is malformed")]
    Share,
    #[error("need {0} distinct shares")]
    TooFew(usize),
    #[error("the shares do not give a valid key")]
    Key,
    #[error("the envelope does not open")]
    Envelope,
    #[error("the words are longer than an envelope holds")]
    TooLong,
}

/// One guardian's share: what it holds, and all it holds.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// 1 to n: the point the polynomial is evaluated at.
    pub index: u8,
    pub y: [u8; 32],
}

impl std::fmt::Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share {{ index: {}, .. }}", self.index)
    }
}

impl Share {
    pub const LEN: usize = 33;

    #[must_use]
    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.index;
        out[1..].copy_from_slice(&self.y);
        out
    }

    pub fn decode(b: &[u8]) -> Result<Self, GuardianError> {
        if b.len() != Self::LEN || b[0] == 0 {
            return Err(GuardianError::Share);
        }
        Ok(Self {
            index: b[0],
            y: b[1..].try_into().map_err(|_| GuardianError::Share)?,
        })
    }
}

fn scalar(b: &[u8; 32]) -> Result<Scalar, GuardianError> {
    Option::from(Scalar::from_repr((*b).into())).ok_or(GuardianError::Share)
}

/// Split `key` into `n` shares, any `t` of which give it back.
///
/// # Panics
///
/// If `t` is zero, or `n` is below `t` or above 255.
#[must_use]
pub fn split(key: &PrivateKeySigner, t: usize, n: usize, rng: &mut impl CryptoRng) -> Vec<Share> {
    assert!(t >= 1 && t <= n && n <= 255);
    let secret = scalar(&key.to_bytes().0).expect("a signer's key is a scalar");
    let mut coefficients = vec![secret];
    for _ in 1..t {
        // Uniform by rejection: a 32-byte string is a scalar with probability 1 - 2^-128.
        let c = loop {
            let mut b = [0u8; 32];
            rng.fill_bytes(&mut b);
            if let Ok(c) = scalar(&b) {
                break c;
            }
        };
        coefficients.push(c);
    }
    (1..=n)
        .map(|i| {
            let x = Scalar::from(i as u64);
            // Horner, from the highest coefficient.
            let y = coefficients
                .iter()
                .rev()
                .fold(Scalar::ZERO, |acc, c| acc * x + c);
            Share {
                index: i as u8,
                y: y.to_repr().into(),
            }
        })
        .collect()
}

/// The key `t` distinct shares were split from: Lagrange interpolation at 0.
pub fn join(shares: &[Share], t: usize) -> Result<PrivateKeySigner, GuardianError> {
    let mut seen: Vec<&Share> = vec![];
    for s in shares {
        if !seen.iter().any(|o| o.index == s.index) {
            seen.push(s);
        }
    }
    if seen.len() < t {
        return Err(GuardianError::TooFew(t));
    }
    let seen = &seen[..t];
    let mut secret = Scalar::ZERO;
    for (j, sj) in seen.iter().enumerate() {
        let xj = Scalar::from(u64::from(sj.index));
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for (m, sm) in seen.iter().enumerate() {
            if m != j {
                let xm = Scalar::from(u64::from(sm.index));
                num *= xm;
                den *= xm - xj;
            }
        }
        let inv = Option::<Scalar>::from(den.invert()).ok_or(GuardianError::Share)?;
        secret += scalar(&sj.y)? * num * inv;
    }
    if bool::from(secret.is_zero()) {
        return Err(GuardianError::Key);
    }
    PrivateKeySigner::from_bytes(&B256::from(<[u8; 32]>::from(secret.to_repr())))
        .map_err(|_| GuardianError::Key)
}

/// Where the envelope for recovery key `r` is posted.
#[must_use]
pub fn locator(r: Address) -> B256 {
    keccak256([ENVELOPE_DOMAIN, r.as_slice()].concat())
}

/// `P`: the user's phrase, stretched with Argon2id.
///
/// # Panics
///
/// Never: the parameters are fixed and valid.
#[must_use]
pub fn stretch(phrase: &str, r: Address) -> [u8; 32] {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_PASSES, 1, Some(32)).expect("valid");
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(
            phrase.as_bytes(),
            &[ENVELOPE_DOMAIN, r.as_slice()].concat(),
            &mut out,
        )
        .expect("valid lengths");
    out
}

/// What opens an envelope: the recovery key and, unless `None`, the stretched phrase.
///
/// `None` is the construction this experiment shows wrong: an envelope that `R` alone opens.
fn cipher(r: &PrivateKeySigner, stretched: Option<&[u8; 32]>) -> Aes256Gcm {
    let mut ikm = r.to_bytes().to_vec();
    if let Some(p) = stretched {
        ikm.extend_from_slice(p);
    }
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(ENVELOPE_DOMAIN), &ikm)
        .expand(r.address().as_slice(), &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Aes256Gcm::new_from_slice(&key).expect("a 32-byte key")
}

/// Seal the seed's words for recovery key `r`.
pub fn seal(
    words: &str,
    r: &PrivateKeySigner,
    stretched: Option<&[u8; 32]>,
    rng: &mut impl CryptoRng,
) -> Result<Vec<u8>, GuardianError> {
    if words.len() > PADDED_WORDS {
        return Err(GuardianError::TooLong);
    }
    let mut padded = words.as_bytes().to_vec();
    padded.resize(PADDED_WORDS, b' ');
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let body = cipher(r, stretched)
        .encrypt(&Nonce::from(nonce), padded.as_slice())
        .map_err(|_| GuardianError::Envelope)?;
    let mut out = Vec::with_capacity(ENVELOPE_LEN);
    out.push(ENVELOPE_TAG);
    out.extend_from_slice(locator(r.address()).as_slice());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open an envelope for recovery key `r`: the seed's words.
pub fn open(
    envelope: &[u8],
    r: &PrivateKeySigner,
    stretched: Option<&[u8; 32]>,
) -> Result<String, GuardianError> {
    if envelope.len() != ENVELOPE_LEN
        || envelope[0] != ENVELOPE_TAG
        || envelope[1..33] != locator(r.address())[..]
    {
        return Err(GuardianError::Envelope);
    }
    let nonce: [u8; 12] = envelope[33..45]
        .try_into()
        .map_err(|_| GuardianError::Envelope)?;
    let padded = cipher(r, stretched)
        .decrypt(&Nonce::from(nonce), &envelope[45..])
        .map_err(|_| GuardianError::Envelope)?;
    String::from_utf8(padded)
        .map(|s| s.trim_end().to_owned())
        .map_err(|_| GuardianError::Envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn any_t_shares_give_the_key_and_fewer_do_not() {
        let mut rng = rand::rng();
        let r = PrivateKeySigner::random();
        let shares = split(&r, 2, 3, &mut rng);
        for pair in [[0, 1], [0, 2], [1, 2], [2, 0]] {
            let picked = [shares[pair[0]].clone(), shares[pair[1]].clone()];
            assert_eq!(join(&picked, 2).unwrap().address(), r.address());
        }
        assert_eq!(join(&shares[..1], 2).unwrap_err(), GuardianError::TooFew(2));
        // The same share twice is one share.
        let twice = [shares[0].clone(), shares[0].clone()];
        assert_eq!(join(&twice, 2).unwrap_err(), GuardianError::TooFew(2));
        // One share with the threshold set to one gives a wrong key, not the key.
        assert_ne!(
            join(&shares[..1], 1).map(|k| k.address()).ok(),
            Some(r.address())
        );
        let t3 = split(&r, 3, 5, &mut rng);
        assert_eq!(join(&t3[2..], 3).unwrap().address(), r.address());
        assert_ne!(join(&t3[3..], 2).unwrap().address(), r.address());
    }

    #[test]
    fn shares_encode_and_decode() {
        let shares = split(&PrivateKeySigner::random(), 2, 3, &mut rand::rng());
        for s in &shares {
            assert_eq!(&Share::decode(&s.encode()).unwrap(), s);
        }
        assert!(Share::decode(&[0u8; 33]).is_err());
    }

    #[test]
    fn the_envelope_needs_the_key_and_the_phrase() {
        let mut rng = rand::rng();
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
        let r = PrivateKeySigner::random();
        // A cheap stretch stands in for Argon2id here; the run uses `stretch`.
        let p = [7u8; 32];
        let e = seal(words, &r, Some(&p), &mut rng).unwrap();
        assert_eq!(e.len(), ENVELOPE_LEN);
        assert_eq!(open(&e, &r, Some(&p)).unwrap(), words);
        assert!(open(&e, &r, None).is_err());
        assert!(open(&e, &r, Some(&[8u8; 32])).is_err());
        assert!(open(&e, &PrivateKeySigner::random(), Some(&p)).is_err());
        // The construction shown wrong: R alone opens it.
        let weak = seal(words, &r, None, &mut rng).unwrap();
        assert_eq!(open(&weak, &r, None).unwrap(), words);
    }
}
