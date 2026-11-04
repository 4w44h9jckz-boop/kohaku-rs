//! A message sealed to a key with ML-KEM-768 (FIPS 203), where experiments 45 to 47 used ECDH on
//! secp256k1: the guardians' shares to a new device's transport key, and notes to the viewing
//! key. A recorded ciphertext stays on the board for good, so its key exchange must outlast a
//! quantum computer, not only the signatures.
//!
//! ```text
//! sealed = 0x31 || ML-KEM-768 ciphertext (1,088) || AES-256-GCM(k, nonce 0, plaintext) (len + 16)
//! k      = HKDF-SHA256(ikm = the shared key, salt = "kohaku-pq-seal-v1", info = the ciphertext)
//! ```
//!
//! Each seal encapsulates afresh, so each AES key is used once and a zero nonce is safe.

use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use hkdf::Hkdf;
use ml_kem::{
    Decapsulate, DecapsulationKey, EncapsulationKey, KeyExport, MlKem768,
    array::Array,
};
use sha2::Sha256;

/// The first byte of a sealed message.
pub const VERSION: u8 = 0x31;
/// ML-KEM-768's ciphertext length.
pub const CIPHERTEXT_LEN: usize = 1_088;
/// ML-KEM-768's encapsulation key length.
pub const ENCAPSULATION_KEY_LEN: usize = 1_184;
/// What sealing adds to a plaintext.
pub const OVERHEAD: usize = 1 + CIPHERTEXT_LEN + 16;
const DOMAIN: &[u8] = b"kohaku-pq-seal-v1";

/// A decapsulation key. Its `Debug` prints nothing secret.
pub struct SealKey(DecapsulationKey<MlKem768>);

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey(..)")
    }
}

impl SealKey {
    /// FIPS 203's key generation from its 64-byte seed `d || z`.
    #[must_use]
    pub fn from_seed(seed: [u8; 64]) -> Self {
        Self(DecapsulationKey::from_seed(Array::from(seed)))
    }

    /// The encapsulation key, to publish.
    #[must_use]
    pub fn public(&self) -> Vec<u8> {
        self.0.encapsulation_key().to_bytes().to_vec()
    }

    /// The plaintext of a message sealed to this key, or `None`.
    #[must_use]
    pub fn open(&self, sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < OVERHEAD || sealed[0] != VERSION {
            return None;
        }
        let ct = &sealed[1..=CIPHERTEXT_LEN];
        let shared = self.0.decapsulate(&Array::try_from(ct).ok()?);
        cipher(shared.as_slice(), ct)
            .decrypt(&Nonce::default(), &sealed[1 + CIPHERTEXT_LEN..])
            .ok()
    }
}

fn cipher(shared: &[u8], ct: &[u8]) -> Aes256Gcm {
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(Some(DOMAIN), shared)
        .expand(ct, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    Aes256Gcm::new_from_slice(&key).expect("a 32-byte key")
}

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("not an ML-KEM-768 encapsulation key")]
    Key,
    #[error("AES-GCM failed")]
    Cipher,
}

/// Seal `plaintext` to the encapsulation key `to`, with 32 uniformly random bytes `m`.
///
/// # Panics
///
/// Never: the lengths are fixed.
pub fn seal(to: &[u8], plaintext: &[u8], m: [u8; 32]) -> Result<Vec<u8>, SealError> {
    let key = Array::try_from(to).map_err(|_| SealError::Key)?;
    let ek = EncapsulationKey::<MlKem768>::new(&key).map_err(|_| SealError::Key)?;
    let (ct, shared) = ek.encapsulate_deterministic(&Array::from(m));
    let body = cipher(shared.as_slice(), ct.as_slice())
        .encrypt(&Nonce::default(), plaintext)
        .map_err(|_| SealError::Cipher)?;
    let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
    out.push(VERSION);
    out.extend_from_slice(ct.as_slice());
    out.extend_from_slice(&body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_message_opens_with_its_key_only() {
        let k = SealKey::from_seed([1u8; 64]);
        assert_eq!(k.public().len(), ENCAPSULATION_KEY_LEN);
        let s = seal(&k.public(), b"a share", [2u8; 32]).unwrap();
        assert_eq!(s.len(), OVERHEAD + 7);
        assert_eq!(k.open(&s).as_deref(), Some(&b"a share"[..]));
        assert!(SealKey::from_seed([3u8; 64]).open(&s).is_none());
        let mut t = s.clone();
        t[5] ^= 1;
        assert!(k.open(&t).is_none());
    }
}
