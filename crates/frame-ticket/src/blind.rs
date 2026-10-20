//! Threshold blind BLS signatures on Commonware's public API.
//!
//! Commonware's threshold signing hashes its message before it signs, so no issuer can be asked
//! to sign a point the buyer chose. Its public API still has every piece a blind signature
//! needs, so this layer adds none to the crate:
//!
//! - [`blind`]: the buyer hashes the message `m` to `H(m)` in G1 (`ops::hash_with_namespace`,
//!   the same hash `ops::verify_message` uses) and sends `B = r * H(m)` for a random nonzero `r`.
//!   `B` is a uniformly random point of G1 whatever `m` is: the issuer learns nothing of `m`.
//! - [`answer`]: issuer `i` multiplies `B` by its share `x_i` (`Private::expose`) and returns a
//!   `PartialSignature` with its index, as threshold signing would.
//! - [`check_answer`]: the buyer checks each answer against the issuer's public share, as a
//!   pairing check with `B` in place of a hashed message (`Variant::verify`).
//! - [`unblind`]: `threshold::recover` interpolates `x * B` from a quorum of answers, and the
//!   buyer multiplies by `1 / r`: `x * B / r = x * H(m)`, the group's ordinary signature on `m`,
//!   which `ops::verify_message` accepts.
//!
//! The variant is `MinSig`: signatures in G1, keys in G2, so that a contract hashes the message
//! to the cheaper group.

use commonware_cryptography::bls12381::primitives::{
    Error,
    group::{G1, Scalar, Share},
    ops,
    sharing::Sharing,
    variant::{MinSig, PartialSignature, Variant},
};
use commonware_math::algebra::{Additive, Field, Random};
use commonware_parallel::Sequential;
use rand::CryptoRng;

/// The buyer's secret for one ticket: what turns the issuers' answer into the signature.
pub struct Blinding {
    r: Scalar,
}

impl std::fmt::Debug for Blinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Blinding(..)")
    }
}

/// The message as the group signs it: `ops::hash_with_namespace` under `MinSig`'s message tag.
#[must_use]
pub fn hash(namespace: &[u8], message: &[u8]) -> G1 {
    ops::hash_with_namespace::<MinSig>(MinSig::MESSAGE, namespace, message)
}

/// Blind a message: the point to send to the issuers, and the secret to unblind their answer.
pub fn blind(rng: &mut impl CryptoRng, namespace: &[u8], message: &[u8]) -> (G1, Blinding) {
    let r = loop {
        let r = Scalar::random(&mut *rng);
        if r != Scalar::zero() {
            break r;
        }
    };
    (hash(namespace, message) * &r, Blinding { r })
}

/// An issuer's answer to a blinded point: the point times its share.
#[must_use]
pub fn answer(share: &Share, blinded: &G1) -> PartialSignature<MinSig> {
    PartialSignature {
        index: share.index,
        value: share.private.expose(|x| *blinded * x),
    }
}

/// Check an issuer's answer `s_i` against its public share `X_i`: `e(s_i, g2) = e(B, X_i)`.
pub fn check_answer(
    sharing: &Sharing<MinSig>,
    blinded: &G1,
    answer: &PartialSignature<MinSig>,
) -> Result<(), Error> {
    MinSig::verify(
        &sharing.partial_public(answer.index)?,
        blinded,
        &answer.value,
    )
}

/// Combine a quorum of checked answers and unblind: the group's signature on the message.
pub fn unblind<'a>(
    sharing: &Sharing<MinSig>,
    answers: impl IntoIterator<Item = &'a PartialSignature<MinSig>>,
    blinding: &Blinding,
) -> Result<G1, Error> {
    let blinded = ops::threshold::recover::<MinSig, _>(sharing, answers, &Sequential)?;
    Ok(blinded * &blinding.r.inv())
}

/// Whether `signature` is the group's signature on the message.
pub fn verify(
    sharing: &Sharing<MinSig>,
    namespace: &[u8],
    message: &[u8],
    signature: &G1,
) -> Result<(), Error> {
    ops::verify_message::<MinSig>(sharing.public(), namespace, message, signature)
}
