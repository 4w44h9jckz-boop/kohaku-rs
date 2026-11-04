//! Experiment 46's envelope with a leanSPHINCS recovery key: the seed's words sealed under the
//! recovery key's 32-byte seed and the user's stretched phrase, found on the board by a locator
//! of the recovery key's public key. Everything here is symmetric, so it outlasts a quantum
//! computer as experiment 46's did; what changes is that nothing names a secp256k1 address.
//!
//! ```text
//! envelope = 0x21 || locator (32) || nonce (12) || AES-256-GCM(k, nonce, words padded to 216) (232)
//! locator  = keccak256("kohaku-seed-envelope-pq-v1" || R's public key)
//! k        = HKDF-SHA256(ikm = R's seed || P, salt = the domain, info = R's public key)
//! P        = Argon2id(phrase, salt = the domain || R's public key), 64 MiB, 3 passes
//! ```

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use alloy::primitives::{B256, keccak256};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

/// The envelope's domain.
pub const DOMAIN: &[u8] = b"kohaku-seed-envelope-pq-v1";
/// The first byte of an envelope.
pub const TAG: u8 = 0x21;
/// The words, padded with spaces.
pub const PADDED_WORDS: usize = 216;
/// An envelope's length.
pub const LEN: usize = 1 + 32 + 12 + PADDED_WORDS + 16;

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("the words are longer than {PADDED_WORDS} bytes")]
    TooLong,
    #[error("not this recovery key's envelope, or not opened by this phrase")]
    Open,
}

/// Where the envelope for the recovery key `public` is posted.
#[must_use]
pub fn locator(public: B256) -> B256 {
    keccak256([DOMAIN, public.as_slice()].concat())
}

/// `P`: the phrase, stretched with Argon2id as experiment 46's.
///
/// # Panics
///
/// Never: the parameters are fixed and valid.
#[must_use]
pub fn stretch(phrase: &str, public: B256) -> [u8; 32] {
    let params = Params::new(65_536, 3, 1, Some(32)).expect("valid");
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(phrase.as_bytes(), &[DOMAIN, public.as_slice()].concat(), &mut out)
        .expect("valid lengths");
    out
}

fn cipher(r_seed: &[u8; 32], public: B256, stretched: &[u8; 32]) -> Aes256Gcm {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(DOMAIN), &[r_seed.as_slice(), stretched].concat())
        .expand(public.as_slice(), &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Aes256Gcm::new_from_slice(&key).expect("a 32-byte key")
}

/// Seal `words` for the recovery key with seed `r_seed` and public key `public`.
///
/// # Panics
///
/// Never: the lengths are fixed.
pub fn seal(words: &str, r_seed: &[u8; 32], public: B256, stretched: &[u8; 32], nonce: [u8; 12]) -> Result<Vec<u8>, EnvelopeError> {
    if words.len() > PADDED_WORDS {
        return Err(EnvelopeError::TooLong);
    }
    let mut padded = words.as_bytes().to_vec();
    padded.resize(PADDED_WORDS, b' ');
    let body = cipher(r_seed, public, stretched)
        .encrypt(&Nonce::from(nonce), padded.as_slice())
        .expect("AES-GCM encrypts any length here");
    let mut out = Vec::with_capacity(LEN);
    out.push(TAG);
    out.extend_from_slice(locator(public).as_slice());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Open an envelope: the seed's words.
///
/// # Panics
///
/// Never: the lengths are checked.
pub fn open(envelope: &[u8], r_seed: &[u8; 32], public: B256, stretched: &[u8; 32]) -> Result<String, EnvelopeError> {
    if envelope.len() != LEN || envelope[0] != TAG || envelope[1..33] != locator(public)[..] {
        return Err(EnvelopeError::Open);
    }
    let nonce: [u8; 12] = envelope[33..45].try_into().expect("12 bytes");
    let padded = cipher(r_seed, public, stretched)
        .decrypt(&Nonce::from(nonce), &envelope[45..])
        .map_err(|_| EnvelopeError::Open)?;
    String::from_utf8(padded).map(|s| s.trim_end().to_owned()).map_err(|_| EnvelopeError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_envelope_opens_with_the_key_and_the_phrase_only() {
        let (seed, public) = ([5u8; 32], B256::repeat_byte(6));
        let p = stretch("a phrase", public);
        let e = seal("the words", &seed, public, &p, [7u8; 12]).unwrap();
        assert_eq!(e.len(), LEN);
        assert_eq!(open(&e, &seed, public, &p).unwrap(), "the words");
        assert!(open(&e, &seed, public, &stretch("a guess", public)).is_err());
        assert!(open(&e, &[8u8; 32], public, &p).is_err());
    }
}
