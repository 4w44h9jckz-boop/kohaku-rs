//! Groth16 over BN254, as `Groth16Verifier.yul` checks it: the same key layout, the same proof
//! words, the same pairing equation
//! `e(-A, B) e(alpha, beta) e(vk_x, gamma) e(C, delta) = 1`, with `vk_x = IC_0 + sum x_i IC_i`.

use alloy::primitives::U256;
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, CurveGroup, pairing::Pairing};
use ark_ff::{BigInt, PrimeField, Zero};

/// A verifying key. G2 points are in EIP-197's order: x1, x0, y1, y0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyingKey {
    pub alpha: [U256; 2],
    pub beta: [U256; 4],
    pub gamma: [U256; 4],
    pub delta: [U256; 4],
    /// `IC_0 .. IC_n`, one more than the public inputs.
    pub ic: Vec<[U256; 2]>,
}

impl VerifyingKey {
    /// What the verifier's code carries after it: alpha, beta, gamma, delta, the IC points, then
    /// the number of public inputs, as 32-byte words.
    #[must_use]
    pub fn words(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 * (15 + 2 * self.ic.len()));
        let words = self
            .alpha
            .iter()
            .chain(&self.beta)
            .chain(&self.gamma)
            .chain(&self.delta)
            .chain(self.ic.iter().flatten())
            .copied()
            .chain([U256::from(self.ic.len() - 1)]);
        for w in words {
            out.extend_from_slice(&w.to_be_bytes::<32>());
        }
        out
    }

    /// Whether `proof` (A.x A.y B.x1 B.x0 B.y1 B.y0 C.x C.y) is valid for `inputs`. False for a
    /// wrong number of inputs, an input outside the scalar field, or a point off the curve.
    #[must_use]
    pub fn verify(&self, proof: &[U256; 8], inputs: &[U256]) -> bool {
        self.check(proof, inputs).unwrap_or(false)
    }

    fn check(&self, proof: &[U256; 8], inputs: &[U256]) -> Option<bool> {
        if inputs.len() + 1 != self.ic.len() {
            return None;
        }
        let mut vk_x: G1Projective = g1(&self.ic[0])?.into();
        for (x, ic) in inputs.iter().zip(&self.ic[1..]) {
            let x = Fr::from_bigint(BigInt(x.into_limbs()))?;
            vk_x += g1(ic)? * x;
        }
        let a = g1(&[proof[0], proof[1]])?;
        let b = g2(&[proof[2], proof[3], proof[4], proof[5]])?;
        let c = g1(&[proof[6], proof[7]])?;
        let out = Bn254::multi_pairing(
            [-a, g1(&self.alpha)?, vk_x.into_affine(), c],
            [b, g2(&self.beta)?, g2(&self.gamma)?, g2(&self.delta)?],
        );
        Some(out.is_zero())
    }
}

fn fq(x: U256) -> Option<Fq> {
    Fq::from_bigint(BigInt(x.into_limbs()))
}

fn g1(p: &[U256; 2]) -> Option<G1Affine> {
    if p[0].is_zero() && p[1].is_zero() {
        return Some(G1Affine::zero());
    }
    let p = G1Affine::new_unchecked(fq(p[0])?, fq(p[1])?);
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

fn g2(p: &[U256; 4]) -> Option<G2Affine> {
    let p = G2Affine::new_unchecked(
        Fq2::new(fq(p[1])?, fq(p[0])?),
        Fq2::new(fq(p[3])?, fq(p[2])?),
    );
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}
