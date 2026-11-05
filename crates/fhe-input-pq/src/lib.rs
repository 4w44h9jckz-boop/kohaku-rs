//! A TFHE compact public-key ciphertext's well-formedness, proved by one leanVM program
//! (`programs/fhe_input.py`) and checked as one EIP-8288 leanSTARK dependency: `exp-frames`
//! experiment 41's post-quantum run. It is a port of the relation tfhe-zk-pok's proof covers,
//! not that proof.
//!
//! leanVM's words are elements of GF(2^192) and it has no integers, so the program sums in the
//! exponent of its generator `g`: each 64-bit coefficient is two 32-bit halves held as `g^x`, and
//! the carries are hinted. This crate builds the program's witness streams and its public digest
//! from a `kohaku_fhe_input::Encryption`.
//!
//! leanVM has no zero knowledge at `3cbac04`: a proof hides nothing it was given, the plaintext
//! included.

pub mod v2;

use std::collections::BTreeMap;

use kohaku_fhe_input::{Encryption, PkeParams};
use primitives::field::{F192, g_pow};
use sha3::{Digest, Keccak256};

/// A primitive element of GF(2^192)^*, whose powers carry coefficient sums (pinned by
/// `tests/generator.rs`).
pub const H: F192 = F192::new(7, 8, 0);

/// The program's source.
pub const PROGRAM: &str = include_str!("../programs/fhe_input.py");
/// `g`'s multiplicative order: exponents are taken modulo it.
const ORDER: u128 = (1u128 << 64) - 1;
/// The noise bound, `TUniform(17)`.
pub const NOISE: i64 = 1 << 17;
/// The carries' offset: a carry `kappa` is hinted as `g^(kappa + 2^12)`.
const CARRY_OFFSET: i128 = 1 << 12;

/// The program's key: keccak256 of its source bytes.
#[must_use]
pub fn program_key() -> [u8; 32] {
    Keccak256::digest(PROGRAM.as_bytes()).into()
}

/// `g^e` for any integer `e`, as a cell.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn gp(e: i128) -> F192 {
    let r = e.rem_euclid(ORDER.cast_signed()) as u128;
    F192::new(g_pow(r as usize).0, 0, 0)
}

/// A 32-byte value as its two cells: bytes 0..16 then 16..32, each two little-endian limbs.
///
/// # Panics
///
/// Never: the slices are 8 bytes.
#[must_use]
pub fn cells_of(b: &[u8; 32]) -> [F192; 2] {
    let limb = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"));
    [
        F192::new(limb(0), limb(8), 0),
        F192::new(limb(16), limb(24), 0),
    ]
}

#[allow(clippy::cast_sign_loss)]
fn pair_cells(coefs: &[i64]) -> Vec<F192> {
    coefs
        .chunks(2)
        .map(|c| F192::new(c[0] as u64, c.get(1).copied().unwrap_or(0) as u64, 0))
        .collect()
}

#[allow(clippy::cast_sign_loss)]
fn bytes_of(coefs: &[i64], cells: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 * cells);
    for c in coefs {
        out.extend_from_slice(&(*c as u64).to_le_bytes());
    }
    out.resize(16 * cells, 0);
    out
}

/// What both versions hash and publish: the key and the ciphertext as cells and bytes, and the
/// digest `H(H(H(pk), H(ct)), mu)`.
#[derive(Debug, Clone)]
pub struct Public {
    pub pk_coefs: Vec<i64>,
    pub ct_coefs: Vec<i64>,
    pub pk_cells: Vec<F192>,
    pub ct_cells: Vec<F192>,
    pub pk_bytes: Vec<u8>,
    pub ct_bytes: Vec<u8>,
    pub digest: [u8; 32],
}

impl Public {
    /// For `enc`'s key, the ciphertext `c1` with `enc.c2`, and `mu`.
    #[must_use]
    pub fn of(enc: &Encryption, c1: &[i64], mu: [u8; 32]) -> Self {
        let ct_coefs: Vec<i64> = c1.iter().chain(&enc.c2).copied().collect();
        let pk_coefs: Vec<i64> = enc.a.iter().chain(&enc.b).copied().collect();
        let pk_cells = pair_cells(&pk_coefs);
        let ct_cells = pair_cells(&ct_coefs);
        let pk_bytes = bytes_of(&pk_coefs, pk_cells.len());
        let ct_bytes = bytes_of(&ct_coefs, ct_cells.len());
        let hpk: [u8; 32] = Keccak256::digest(&pk_bytes).into();
        let hct: [u8; 32] = Keccak256::digest(&ct_bytes).into();
        let inner: [u8; 32] = Keccak256::digest([hpk, hct].concat()).into();
        let digest: [u8; 32] = Keccak256::digest([inner, mu].concat()).into();
        Self {
            pk_coefs,
            ct_coefs,
            pk_cells,
            ct_cells,
            pk_bytes,
            ct_bytes,
            digest,
        }
    }
}

/// What the program reads, and what it publishes.
#[derive(Debug)]
pub struct Instance {
    pub replacements: BTreeMap<String, String>,
    pub streams: Vec<(String, Vec<Vec<F192>>)>,
    /// The key's and the ciphertext's bytes, as the contract hashes them.
    pub pk_bytes: Vec<u8>,
    pub ct_bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub public: [F192; 2],
}

/// How a witness is spoiled, for the refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spoil {
    None,
    /// One noise coefficient one past its bound, the ciphertext changed to match.
    NoiseOutOfBound,
}

fn halves(x: i64) -> (i128, i128) {
    #[allow(clippy::cast_sign_loss)]
    let u = x as u64;
    (i128::from(u & 0xffff_ffff), i128::from(u >> 32))
}

/// The instance for `enc` under `p`, with the request's message `mu`.
///
/// # Panics
///
/// If `enc` does not satisfy the relation, which `encrypt` guarantees.
#[must_use]
#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
pub fn instance(p: &PkeParams, enc: &Encryption, mu: [u8; 32], spoil: Spoil) -> Instance {
    let (d, k) = (p.d, p.k);
    let mut c1 = enc.c1.clone();
    let mut e1 = enc.e1.clone();
    if spoil == Spoil::NoiseOutOfBound {
        // e1_0 = 2^17: one past the bound. c1_0 moves by the same amount, so only the bound breaks.
        let delta = NOISE - e1[0];
        e1[0] = NOISE;
        c1[0] = c1[0].wrapping_add(delta);
    }
    let pub_ = Public::of(enc, &c1, mu);
    let ct_cells = pub_.ct_cells.len();
    let pk_coefs = pub_.pk_coefs.clone();
    let digest = pub_.digest;

    // s: r reversed; J its support.
    let s: Vec<i64> = (0..d).map(|j| enc.r[d - 1 - j]).collect();
    let jset: Vec<usize> = (0..d).filter(|&j| s[j] == 1).collect();
    let blocks = jset.len().div_ceil(8).max(1);
    let mut jp: Vec<Vec<F192>> = jset.iter().map(|&j| vec![gp(j as i128)]).collect();
    jp.resize(8 * blocks, vec![gp(-(d as i128))]);
    let mut gaps = Vec::new();
    let mut prev: i128 = -1;
    for &j in &jset {
        gaps.push(vec![gp(j as i128 - prev - 1)]);
        prev = j as i128;
    }

    let mut e_stream = Vec::new();
    let mut carry = Vec::new();
    let push_noise = |e: i64, e_stream: &mut Vec<Vec<F192>>| {
        let x = e + NOISE;
        assert!(
            (0..4 * 65_536).contains(&x) || spoil != Spoil::None,
            "noise out of bound"
        );
        let (u, v) = (x & 0xffff, x >> 16);
        e_stream.push(vec![
            gp(i128::from(u)),
            F192::new((v & 1) as u64, 0, 0),
            F192::new(((v >> 1) & 1) as u64, 0, 0),
        ]);
    };
    let carries = |sl: i128, sh: i128, e: i128, c: i64, extra_hi: i128| -> Vec<F192> {
        let (cl, ch) = halves(c);
        let lo = sl + e - cl;
        let kappa = lo.div_euclid(1 << 32);
        let hi = sh + extra_hi + kappa - ch;
        let tau = hi.div_euclid(1 << 32);
        vec![gp(kappa + CARRY_OFFSET), gp(tau + CARRY_OFFSET)]
    };

    // c1: row n sums a_{n-j} for j <= n and -a_{n-j+d} for j > n, over J.
    for n in 0..d {
        let (mut sl, mut sh) = (0i128, 0i128);
        for &j in &jset {
            let (l, h) = if j <= n {
                halves(enc.a[n - j])
            } else {
                let (l, h) = halves(enc.a[n + d - j]);
                (-l, -h)
            };
            sl += l;
            sh += h;
        }
        push_noise(e1[n], &mut e_stream);
        carry.push(carries(sl, sh, i128::from(e1[n]), c1[n], 0));
    }
    // c2_i: sum over J of B(i + j).
    let mut m_stream = Vec::new();
    for i in 0..k {
        let (mut sl, mut sh) = (0i128, 0i128);
        for &j in &jset {
            let u = i + j;
            let (l, h) = if u < d {
                halves(enc.b[d - 1 - u])
            } else {
                let (l, h) = halves(enc.b[2 * d - 1 - u]);
                (-l, -h)
            };
            sl += l;
            sh += h;
        }
        push_noise(enc.e2[i], &mut e_stream);
        let m = enc.m[i];
        m_stream.push(
            (0..4)
                .map(|b| F192::new(((m >> b) & 1) as u64, 0, 0))
                .collect(),
        );
        carry.push(carries(
            sl,
            sh,
            i128::from(enc.e2[i]),
            enc.c2[i],
            i128::from(m) << 27,
        ));
    }

    let y = F192::new(0, 1, 0);
    let yi = y.inv();
    let replacements: BTreeMap<String, String> = [
        ("D_PLACEHOLDER", d.to_string()),
        ("K_PLACEHOLDER", k.to_string()),
        ("CT_PLACEHOLDER", ct_cells.to_string()),
        (
            "Y_TOWER_PLACEHOLDER",
            (u128::from(y.c0) | (u128::from(y.c1) << 64)).to_string(),
        ),
        (
            "Y_INV_PLACEHOLDER",
            format!("f192({},{},{})", yi.c0, yi.c1, yi.c2),
        ),
    ]
    .into_iter()
    .map(|(a, b)| (a.to_owned(), b))
    .collect();
    let streams = vec![
        (
            "pk".to_owned(),
            pub_.pk_cells.iter().map(|&c| vec![c]).collect(),
        ),
        (
            "ct".to_owned(),
            pub_.ct_cells.iter().map(|&c| vec![c]).collect(),
        ),
        ("mu".to_owned(), vec![cells_of(&mu).to_vec()]),
        ("nj".to_owned(), vec![vec![gp(jset.len() as i128)]]),
        ("nb".to_owned(), vec![vec![gp(blocks as i128)]]),
        ("jp".to_owned(), jp),
        ("gap".to_owned(), gaps),
        ("e".to_owned(), e_stream),
        ("carry".to_owned(), carry),
        ("m".to_owned(), m_stream),
    ];
    let _ = &pk_coefs;
    Instance {
        replacements,
        streams,
        pk_bytes: pub_.pk_bytes,
        ct_bytes: pub_.ct_bytes,
        digest,
        public: cells_of(&digest),
    }
}
