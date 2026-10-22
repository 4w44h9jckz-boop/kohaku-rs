//! `WebAuthnAccount.yul` (`exp-frames` experiment 11): an account owned by a browser passkey.
//!
//! A `WebAuthn` authenticator never signs a digest it is handed. It signs
//! `sha256(authenticatorData || sha256(clientDataJSON))`, and `clientDataJSON` carries the
//! challenge in base64url. The protocol's P256 scheme verifies a signature over the signature
//! hash itself, so it cannot carry an assertion. The assertion travels in an `ARBITRARY` entry
//! instead, whose bytes the signature hash leaves out, so the challenge can be the signature hash
//! without circularity. The account then checks it in the EVM:
//!
//! - the user-presence flag;
//! - `"type":"webauthn.get"`;
//! - `"challenge":"<base64url(sig hash)>"`;
//! - a low `s`;
//! - `P256VERIFY`.
//!
//! Experiment 11 measured that `VERIFY` at 15,542 gas, against 288 for
//! [`crate::P256Account`], whose raw P256 key the protocol checks.
//!
//! The authenticator does the signing:
//!
//! 1. Ask it (`navigator.credentials.get`) for an assertion with the transaction's signature
//!    hash, its 32 bytes, as the challenge.
//! 2. Pass the response to [`Assertion::from_der`].
//! 3. Put [`WebAuthnAccount::entry`] in signature entry 0.
//!
//! An `ARBITRARY` entry's length is not known until the authenticator has signed. A sponsor that
//! prices the transaction before then, [`crate::TokenSponsor`], leaves the assertion's calldata
//! out of the price. A sponsor that only approves payment, [`crate::EoaSponsor`] or
//! [`crate::CanonicalPaymaster`], is not affected.

use alloy::primitives::{Address, B256, Bytes, U256, uint};
use kohaku_frame_kit::{Frame, FrameSignature, constants::scheme};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use sha2::{Digest, Sha256};

use crate::{
    account::FrameAccount,
    contracts::{create2_address, deploy_frame, webauthn_account_code},
};

/// The order of P256's group, and half of it: the account accepts `s` up to `HALF_N` only.
const N: U256 = uint!(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551_U256);
const HALF_N: U256 = uint!(0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8_U256);

const TYPE: &[u8] = br#""type":"webauthn.get""#;

/// A `WebAuthnAccount`, owned by the passkey whose public key is `(qx, qy)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WebAuthnAccount {
    pub qx: B256,
    pub qy: B256,
    pub salt: B256,
    pub verify_execution: u64,
}

impl WebAuthnAccount {
    /// Experiment 11's assertion was 243 bytes. Hashing a longer `clientDataJSON` costs more.
    pub const VERIFY_EXECUTION: u64 = 60_000;

    #[must_use]
    pub fn new(qx: B256, qy: B256, salt: B256) -> Self {
        Self {
            qx,
            qy,
            salt,
            verify_execution: Self::VERIFY_EXECUTION,
        }
    }

    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = webauthn_account_code();
        code.extend_from_slice(self.qx.as_slice());
        code.extend_from_slice(self.qy.as_slice());
        code
    }

    /// A `SENDER` frame deploying this account from someone else's transaction. Its 783 bytes of
    /// code need more state gas than a validation prefix may use, 1,381,590 against 500,000
    /// (experiment 11), so it cannot deploy itself in its first transaction.
    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }

    /// Signature entry 0 for `assertion`, once it has been checked as the account will check it,
    /// signature included.
    ///
    /// # Errors
    ///
    /// Whatever [`Assertion::encode`] refuses, and [`AssertionError::Signature`] when the
    /// assertion is not this passkey's.
    pub fn entry(&self, assertion: &Assertion, sig_hash: B256) -> Result<Bytes, AssertionError> {
        let entry = assertion.encode(sig_hash)?;
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(self.qx.as_slice());
        sec1[33..].copy_from_slice(self.qy.as_slice());
        let key = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| AssertionError::Signature)?;
        let signature = Signature::from_scalars(
            assertion.r.to_be_bytes::<32>(),
            low_s(assertion.s).to_be_bytes::<32>(),
        )
        .map_err(|_| AssertionError::Signature)?;
        key.verify_prehash(&assertion.message(), &signature)
            .map_err(|_| AssertionError::Signature)?;
        Ok(entry)
    }
}

impl FrameAccount for WebAuthnAccount {
    fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        Frame::verify(scope, None).with_execution(self.verify_execution)
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        vec![FrameSignature {
            scheme: scheme::ARBITRARY,
            signer: None,
            ..FrameSignature::default()
        }]
    }
}

/// What `navigator.credentials.get()` returns, as the account needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    pub authenticator_data: Bytes,
    pub client_data_json: Bytes,
    pub r: U256,
    pub s: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AssertionError {
    #[error("authenticator data of {0} bytes, under 37")]
    AuthenticatorData(usize),
    #[error("the user-presence flag is clear")]
    UserPresence,
    #[error("clientDataJSON has no \"type\":\"webauthn.get\"")]
    Type,
    #[error("clientDataJSON's challenge is not this transaction's signature hash")]
    Challenge,
    #[error("too long to index in two bytes")]
    TooLong,
    #[error("not a DER-encoded P256 signature")]
    Der,
    #[error("the signature is not the passkey's")]
    Signature,
}

impl Assertion {
    /// From the response's `authenticatorData`, `clientDataJSON` and `signature`, which a browser
    /// returns DER-encoded.
    ///
    /// # Errors
    ///
    /// [`AssertionError::Der`] when `signature` is not a DER-encoded P256 signature.
    pub fn from_der(
        authenticator_data: impl Into<Bytes>,
        client_data_json: impl Into<Bytes>,
        signature: &[u8],
    ) -> Result<Self, AssertionError> {
        let sig = Signature::from_der(signature).map_err(|_| AssertionError::Der)?;
        let (r, s) = sig.split_bytes();
        Ok(Self {
            authenticator_data: authenticator_data.into(),
            client_data_json: client_data_json.into(),
            r: U256::from_be_slice(&r),
            s: U256::from_be_slice(&s),
        })
    }

    /// What the authenticator signed: `sha256(authenticatorData || sha256(clientDataJSON))`.
    #[must_use]
    pub fn message(&self) -> [u8; 32] {
        Sha256::new()
            .chain_update(&self.authenticator_data)
            .chain_update(Sha256::digest(&self.client_data_json))
            .finalize()
            .into()
    }

    /// The `ARBITRARY` entry the account reads:
    /// `authLen (2) || challengeIndex (2) || typeIndex (2) || authenticatorData || clientDataJSON
    /// || r (32) || s (32)`.
    ///
    /// It refuses what the account would refuse, apart from the signature, so the node is not the
    /// first to notice. It replaces a high `s` with `n - s`. The account accepts only the low form
    /// because the entry is outside the signature hash: a second accepted form would give the
    /// same authorisation a second transaction hash.
    ///
    /// # Errors
    ///
    /// When the account would refuse the assertion, or it is too long for two-byte indices.
    pub fn encode(&self, sig_hash: B256) -> Result<Bytes, AssertionError> {
        let auth = &self.authenticator_data;
        let client = &self.client_data_json;
        if auth.len() < 37 {
            return Err(AssertionError::AuthenticatorData(auth.len()));
        }
        if auth[32] & 0x01 == 0 {
            return Err(AssertionError::UserPresence);
        }
        let type_index = find(client, TYPE).ok_or(AssertionError::Type)?;
        let challenge = format!("\"challenge\":\"{}\"", base64url(sig_hash.as_slice()));
        let challenge_index =
            find(client, challenge.as_bytes()).ok_or(AssertionError::Challenge)?;
        let two = |n: usize| u16::try_from(n).map_err(|_| AssertionError::TooLong);

        let mut entry = Vec::with_capacity(6 + auth.len() + client.len() + 64);
        entry.extend_from_slice(&two(auth.len())?.to_be_bytes());
        entry.extend_from_slice(&two(challenge_index)?.to_be_bytes());
        entry.extend_from_slice(&two(type_index)?.to_be_bytes());
        entry.extend_from_slice(auth);
        entry.extend_from_slice(client);
        entry.extend_from_slice(&self.r.to_be_bytes::<32>());
        entry.extend_from_slice(&low_s(self.s).to_be_bytes::<32>());
        Ok(entry.into())
    }
}

fn low_s(s: U256) -> U256 {
    if s > HALF_N { N - s } else { s }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Base64url without padding, as `clientDataJSON` carries a challenge.
#[must_use]
pub fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out.push(char::from(ALPHABET[(n >> (18 - 6 * i)) as usize & 63]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::base64url;

    #[test]
    fn base64url_matches_rfc_4648() {
        // Section 10's vectors, without padding, and the two characters base64url changes.
        for (input, output) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(input.as_bytes()), output);
        }
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64url(&[0u8; 32]).len(), 43);
    }
}
