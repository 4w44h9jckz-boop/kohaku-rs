//! A TFHE input's proof of knowledge on BLS12-381, and what a `VERIFY` frame would pay to check
//! it (`exp-frames` experiment 41).
//!
//! Zama's `tfhe-zk-pok`, unmodified and pinned, proves that a compact public-key ciphertext is a
//! well-formed encryption. tfhe-rs fixes its curve to BLS12-446, which the EVM does not pair, but
//! `tfhe-zk-pok` itself is generic over its `Curve` and ships BLS12-381, the curve EIP-2537
//! prices. This crate proves and verifies on BLS12-381 at tfhe-rs's own parameters for compact
//! public-key encryption with proofs (`PARAM_PKE_..._TUNIFORM_2M128_ZKV2`: dimension 2048, noise
//! `TUniform(17)`, a native modulus, a 2-bit message with 2 carry bits and a padding bit), and
//! counts what an EVM verifier must do:
//!
//! - [`floor`]: the gas no EVM verifier of the unmodified proof can avoid, from EIP-2537's schedule
//!   and the Fiat-Shamir transcript's size.
//! - [`run`]: a proof made and verified natively, with its sizes and times.

use std::time::Instant;

use rand08::{Rng, SeedableRng, rngs::StdRng};
use tfhe_zk_pok::{
    curve_api::Curve,
    proofs::{
        ComputeLoad,
        pke_v2::{self, VerificationPairingMode},
    },
};

/// tfhe-rs's compact public-key encryption parameters for proofs, as `PkeParams`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkeParams {
    /// The LWE dimension of the compact public key.
    pub d: usize,
    /// How many LWE ciphertexts the list packs: one per 2-bit block.
    pub k: usize,
    /// The noise bound: `TUniform(17)` draws from `[-2^17, 2^17]`.
    pub b: u64,
    /// The ciphertext modulus; 0 is the native `2^64`.
    pub q: u64,
    /// The plaintext modulus with its padding bit: 2 message bits, 2 carry bits, 1 padding bit.
    pub t: u64,
    pub msbs_zero_padding_bit_count: u64,
}

impl PkeParams {
    /// tfhe-rs's ZK v2 parameters, for a list of `k` blocks.
    #[must_use]
    pub fn tfhe_zkv2(k: usize) -> Self {
        Self {
            d: 2048,
            k,
            b: 1 << 17,
            q: 0,
            t: 32,
            msbs_zero_padding_bit_count: 1,
        }
    }
}

/// EIP-2537's gas schedule (Final): what the precompiles charge.
pub mod eip2537 {
    pub const G1_MUL: u64 = 12_000;
    pub const G2_MUL: u64 = 22_500;
    pub const PAIRING_PER_PAIR: u64 = 32_600;
    pub const PAIRING_BASE: u64 = 37_700;
    /// The G2 MSM discount for `k` pairs, from EIP-2537's table, capped at 524 above 128.
    #[must_use]
    pub fn g2_discount(k: u64) -> u64 {
        const T: [u64; 128] = [
            1000, 1000, 923, 884, 855, 832, 812, 796, 782, 770, 759, 749, 740, 732, 724, 717, 711,
            704, 699, 693, 688, 683, 679, 674, 670, 666, 663, 659, 655, 652, 649, 646, 643, 640,
            637, 634, 632, 629, 627, 624, 622, 620, 618, 615, 613, 611, 609, 607, 606, 604, 602,
            600, 598, 597, 595, 593, 592, 590, 589, 587, 586, 584, 583, 582, 580, 579, 578, 576,
            575, 574, 573, 571, 570, 569, 568, 567, 566, 565, 563, 562, 561, 560, 559, 558, 557,
            556, 555, 554, 553, 552, 552, 551, 550, 549, 548, 547, 546, 545, 545, 544, 543, 542,
            541, 541, 540, 539, 538, 537, 537, 536, 535, 535, 534, 533, 532, 532, 531, 530, 530,
            529, 528, 528, 527, 526, 526, 525, 524, 524,
        ];
        let i = usize::try_from(k.clamp(1, 128)).unwrap_or(127) - 1;
        T[i]
    }
    #[must_use]
    pub fn g2_msm(k: u64) -> u64 {
        k * G2_MUL * g2_discount(k) / 1000
    }
    #[must_use]
    pub fn pairing(pairs: u64) -> u64 {
        PAIRING_PER_PAIR * pairs + PAIRING_BASE
    }
}

/// SHAKE256's rate: bytes absorbed or squeezed per Keccak-f permutation.
pub const SHAKE256_RATE: u64 = 136;
/// The least gas any EVM code spends on one Keccak-f[1600] permutation: χ is the only nonlinear
/// step, it touches all 1600 bits in each of 24 rounds, and the EVM's nonlinear bitwise opcodes
/// (`AND`, `OR`) act on 256 bits for 3 gas each, so at least 7 of them a round.
pub const KECCAK_F_FLOOR_GAS: u64 = 24 * 7 * 3;

/// What an EVM verifier of the unmodified proof cannot avoid, in the cheaper of its two modes
/// (`ComputeLoad::Proof`, which moves the large G2 multiplications into the proof).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Floor {
    /// The pairing `e(C_R, sum_j (delta_r phi_j + delta_dec xi_j) g_hat_{n-128+j})`: its G2 side
    /// is a 128-point MSM whose scalars are Fiat-Shamir challenges, so it is made per proof.
    pub g2_msm_points: u64,
    pub g2_msm_gas: u64,
    /// The batched check's pairs: eight, with eight different G2 points, so none merge.
    pub pairs: u64,
    pub pairing_gas: u64,
    /// The first hash: everything it absorbs, the key and the ciphertext included.
    pub absorbed_bytes: u64,
    /// The matrix `R`: one squeezed byte per entry, `128 * (2 (d + k) + 4)` entries.
    pub squeezed_bytes: u64,
    pub permutations: u64,
    pub hashing_gas: u64,
    /// The sum: a lower bound on the `VERIFY` gas of any EVM verifier of this proof.
    pub total_gas: u64,
}

/// The floor at `p`. The absorbed bytes count only the key and the ciphertext (`a`, `b`, `c1`,
/// `c2`, eight bytes per coefficient), and the hashing only the first hash and `R`, so every term
/// is a lower bound and so is the total.
#[must_use]
pub fn floor(p: &PkeParams) -> Floor {
    let (d, k) = (p.d as u64, p.k as u64);
    let g2_msm_points = 128;
    let pairs = 8;
    let absorbed_bytes = 8 * (3 * d + k);
    let squeezed_bytes = 128 * (2 * (d + k) + 4);
    let permutations =
        absorbed_bytes.div_ceil(SHAKE256_RATE) + squeezed_bytes.div_ceil(SHAKE256_RATE);
    let hashing_gas = permutations * KECCAK_F_FLOOR_GAS;
    let g2_msm_gas = eip2537::g2_msm(g2_msm_points);
    let pairing_gas = eip2537::pairing(pairs);
    Floor {
        g2_msm_points,
        g2_msm_gas,
        pairs,
        pairing_gas,
        absorbed_bytes,
        squeezed_bytes,
        permutations,
        hashing_gas,
        total_gas: g2_msm_gas + pairing_gas + hashing_gas,
    }
}

/// An encryption and its randomness, in the form `tfhe-zk-pok` commits to.
///
/// Adapted from `tfhe-zk-pok`'s own test case (`proofs/mod.rs`, `PkeTestcase`, BSD-3-Clause-Clear,
/// Copyright Zama): the same key, encryption and reductions, with the same parameters, so the
/// ciphertext is the compact public-key ciphertext tfhe-rs makes.
#[derive(Debug, Clone)]
pub struct Encryption {
    pub a: Vec<i64>,
    pub b: Vec<i64>,
    pub c1: Vec<i64>,
    pub c2: Vec<i64>,
    pub r: Vec<i64>,
    pub e1: Vec<i64>,
    pub m: Vec<i64>,
    pub e2: Vec<i64>,
}

// The names are the reference's (a, b, c1, c2, r, e1, m, e2, as in tfhe-zk-pok and its paper), and
// the casts are its reductions modulo 2^64.
#[allow(
    clippy::many_single_char_names,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn center_mod_q(x: i128, q: u64) -> i64 {
    if q == 0 {
        // The native modulus 2^64: wrap to i64.
        x as i64
    } else {
        let q = i128::from(q);
        let r = x.rem_euclid(q);
        (if 2 * r >= q { r - q } else { r }) as i64
    }
}

// The names are the reference's (a, b, c1, c2, r, e1, m, e2, as in tfhe-zk-pok and its paper), and
// the casts are its reductions modulo 2^64.
#[allow(
    clippy::many_single_char_names,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
fn polymul_rev(a: &[i64], b: &[i64]) -> Vec<i128> {
    let d = a.len();
    let mut c = vec![0i128; d];
    for i in 0..d {
        for j in 0..d {
            let x = i128::from(a[i]) * i128::from(b[d - j - 1]);
            if i + j < d {
                c[i + j] = c[i + j].wrapping_add(x);
            } else {
                c[i + j - d] = c[i + j - d].wrapping_sub(x);
            }
        }
    }
    c
}

/// A fresh key and an encryption of random `k` messages under it.
#[must_use]
// The names are the reference's (a, b, c1, c2, r, e1, m, e2, as in tfhe-zk-pok and its paper), and
// the casts are its reductions modulo 2^64.
#[allow(
    clippy::many_single_char_names,
    clippy::cast_possible_wrap,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn encrypt(p: &PkeParams, rng: &mut StdRng) -> Encryption {
    let (d, k, bound) = (p.d, p.k, p.b);
    let noise = |rng: &mut StdRng| (rng.r#gen::<u64>() % (2 * bound)) as i64 - bound as i64;
    let effective_t = p.t >> p.msbs_zero_padding_bit_count;
    let a: Vec<i64> = (0..d).map(|_| rng.r#gen::<i64>()).collect();
    let s: Vec<i64> = (0..d).map(|_| (rng.r#gen::<u64>() % 2) as i64).collect();
    let e: Vec<i64> = (0..d).map(|_| noise(rng)).collect();
    let e1: Vec<i64> = (0..d).map(|_| noise(rng)).collect();
    let e2: Vec<i64> = (0..k).map(|_| noise(rng)).collect();
    let r: Vec<i64> = (0..d).map(|_| (rng.r#gen::<u64>() % 2) as i64).collect();
    let m: Vec<i64> = (0..k)
        .map(|_| (rng.r#gen::<u64>() % effective_t) as i64)
        .collect();
    let b: Vec<i64> = polymul_rev(&a, &s)
        .into_iter()
        .zip(&e)
        .map(|(x, &e)| center_mod_q(x.wrapping_add(i128::from(e)), p.q))
        .collect();
    let delta = ((1u128 << 64) / u128::from(p.t)) as u64;
    let c1: Vec<i64> = polymul_rev(&a, &r)
        .into_iter()
        .zip(&e1)
        .map(|(x, &e1)| center_mod_q(x.wrapping_add(i128::from(e1)), p.q))
        .collect();
    let c2: Vec<i64> = (0..k)
        .map(|i| {
            let mut dot = 0i128;
            for j in 0..d {
                let bj = if i + j < d {
                    i128::from(b[d - j - i - 1])
                } else {
                    -i128::from(b[2 * d - j - i - 1])
                };
                dot = dot.wrapping_add(i128::from(r[d - j - 1]) * bj);
            }
            center_mod_q(
                dot.wrapping_add(i128::from(e2[i]))
                    .wrapping_add(i128::from(delta) * i128::from(m[i])),
                p.q,
            )
        })
        .collect();
    Encryption {
        a,
        b,
        c1,
        c2,
        r,
        e1,
        m,
        e2,
    }
}

/// One proof made and verified natively on curve `G`.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub curve: &'static str,
    pub d: usize,
    pub k: usize,
    pub n: usize,
    pub load: &'static str,
    /// The proof's points: G1 and G2.
    pub g1_points: usize,
    pub g2_points: usize,
    /// In EIP-2537's encoding: 128 bytes per G1 point, 256 per G2 point.
    pub evm_proof_bytes: usize,
    pub crs_millis: u128,
    pub prove_millis: u128,
    pub verify_batched_millis: u128,
    pub verify_two_steps_millis: u128,
    pub verified: bool,
    /// A ciphertext changed after proving, so the proof is about another one.
    pub tampered_refused: bool,
}

/// Prove an encryption at `p` on curve `G` with `load`, and verify it in both pairing modes, and
/// against a ciphertext changed in one coefficient.
///
/// # Panics
///
/// If `tfhe-zk-pok` rejects the parameters.
#[must_use]
pub fn run<G: Curve + Send + Sync>(
    curve: &'static str,
    p: &PkeParams,
    load: ComputeLoad,
    seed: u64,
) -> Run {
    let mut rng = StdRng::seed_from_u64(seed);
    let t = Instant::now();
    let crs = pke_v2::crs_gen::<G>(
        p.d,
        p.k,
        p.b,
        p.q,
        p.t,
        p.msbs_zero_padding_bit_count,
        &mut rng,
    );
    let crs_millis = t.elapsed().as_millis();
    let enc = encrypt(p, &mut rng);
    let (public, private) = pke_v2::commit::<G>(
        enc.a.clone(),
        enc.b.clone(),
        enc.c1.clone(),
        enc.c2.clone(),
        enc.r,
        enc.e1,
        enc.m,
        enc.e2,
        &crs,
    );
    let metadata: [u8; 32] = rng.r#gen();
    let seed_bytes: [u8; 16] = rng.r#gen();
    let t = Instant::now();
    let proof = pke_v2::prove::<G>((&crs, &public), &private, &metadata, load, &seed_bytes);
    let prove_millis = t.elapsed().as_millis();
    let t = Instant::now();
    let ok_batched = pke_v2::verify::<G>(
        &proof,
        (&crs, &public),
        &metadata,
        VerificationPairingMode::Batched,
    )
    .is_ok();
    let verify_batched_millis = t.elapsed().as_millis();
    let t = Instant::now();
    let ok_two = pke_v2::verify::<G>(
        &proof,
        (&crs, &public),
        &metadata,
        VerificationPairingMode::TwoSteps,
    )
    .is_ok();
    let verify_two_steps_millis = t.elapsed().as_millis();
    let (mut c2, mut c1) = (enc.c2.clone(), enc.c1);
    c2[0] = c2[0].wrapping_add(1 << 40);
    c1[0] = c1[0].wrapping_add(1);
    let (tampered, _) = pke_v2::commit::<G>(
        enc.a,
        enc.b,
        c1,
        c2,
        vec![0; p.d],
        vec![0; p.d],
        vec![0; p.k],
        vec![0; p.k],
        &crs,
    );
    let tampered_refused = pke_v2::verify::<G>(
        &proof,
        (&crs, &tampered),
        &metadata,
        VerificationPairingMode::Batched,
    )
    .is_err();
    let with_load = matches!(load, ComputeLoad::Proof);
    let (g1_points, g2_points) = (8, if with_load { 5 } else { 3 });
    Run {
        curve,
        d: crs.d,
        k: crs.k,
        n: crs.n,
        load: if with_load { "proof" } else { "verify" },
        g1_points,
        g2_points,
        evm_proof_bytes: 128 * g1_points + 256 * g2_points,
        crs_millis,
        prove_millis,
        verify_batched_millis,
        verify_two_steps_millis,
        verified: ok_batched && ok_two,
        tampered_refused,
    }
}
