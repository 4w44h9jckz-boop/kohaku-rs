//! Version 2 of the program (`programs/fhe_input_v2.py`, experiment 41's amendment 1): each
//! integer is an exponent of [`H`], a primitive element of GF(2^192)^*, coefficients are read a
//! byte at a time, and the product is tiled sixteen by sixteen.
//!
//! The chain's verifier compiles a program file as it is, so the program is the instantiated
//! source, with the sizes and the table written in; its key is keccak256 of that text.

use std::collections::BTreeMap;

use kohaku_fhe_input::{Encryption, PkeParams};
use primitives::field::F192;
use sha3::{Digest, Keccak256};

use crate::{H, NOISE, Public, Spoil, cells_of, gp};

/// The template.
pub const TEMPLATE: &str = include_str!("../programs/fhe_input_v2.py");

fn hpow(e: u128) -> F192 {
    let (mut r, mut b, mut e) = (F192::ONE, H, e);
    while e > 0 {
        if e & 1 == 1 {
            r *= b;
        }
        b = b * b;
        e >>= 1;
    }
    r
}

fn lit(f: F192) -> String {
    format!("f192({},{},{})", f.c0, f.c1, f.c2)
}

/// The instantiated program for `d` and `k`.
#[must_use]
pub fn program(d: usize, k: usize) -> String {
    let ct = (d + k).div_ceil(2);
    let yi = F192::new(0, 1, 0).inv();
    let table: Vec<String> = (0..10u32)
        .flat_map(|p| (0..256u128).map(move |v| lit(hpow(v << (8 * p)))))
        .collect();
    let reps: BTreeMap<&str, String> = [
        ("D_PLACEHOLDER", d.to_string()),
        ("K_PLACEHOLDER", k.to_string()),
        ("CT_PLACEHOLDER", ct.to_string()),
        ("Y_INV_PLACEHOLDER", lit(yi)),
        ("H17_PLACEHOLDER", lit(hpow(1 << 17))),
        ("H76_PLACEHOLDER", lit(hpow(1 << 76))),
        ("HPOW_PLACEHOLDER", format!("[{}]", table.join(", "))),
    ]
    .into_iter()
    .collect();
    let mut out = String::with_capacity(TEMPLATE.len() + 200_000);
    for line in TEMPLATE.lines() {
        let mut l = line.to_owned();
        if !l.trim_start().starts_with('#') {
            for (from, to) in &reps {
                l = l.replace(from, to);
            }
        }
        out.push_str(&l);
        out.push('\n');
    }
    out
}

/// keccak256 of the instantiated program: its key.
#[must_use]
pub fn key(source: &str) -> [u8; 32] {
    Keccak256::digest(source.as_bytes()).into()
}

/// What version 2 reads and publishes.
#[derive(Debug)]
pub struct Instance2 {
    pub source: String,
    pub streams: Vec<(String, Vec<Vec<F192>>)>,
    pub pk_bytes: Vec<u8>,
    pub ct_bytes: Vec<u8>,
    pub digest: [u8; 32],
    pub public: [F192; 2],
}

#[allow(clippy::cast_sign_loss)]
fn bytes_entry(x: i64) -> Vec<F192> {
    let u = x as u64;
    (0..8)
        .map(|p| gp(i128::from((u >> (8 * p)) & 0xff)))
        .collect()
}

#[allow(clippy::cast_sign_loss)]
fn unsigned(x: i64) -> i128 {
    i128::from(x as u64)
}

/// The instance for `enc` under `p`, with the request's message `mu`.
///
/// # Panics
///
/// If a carry falls outside what the program allows, which a well-formed encryption never does.
#[must_use]
#[allow(
    clippy::too_many_lines,
    clippy::many_single_char_names,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation
)]
pub fn instance(p: &PkeParams, enc: &Encryption, mu: [u8; 32], spoil: Spoil) -> Instance2 {
    let (d, k) = (p.d, p.k);
    let mut c1 = enc.c1.clone();
    let mut e1 = enc.e1.clone();
    if spoil == Spoil::NoiseOutOfBound {
        let delta = NOISE - e1[0];
        e1[0] = NOISE;
        c1[0] = c1[0].wrapping_add(delta);
    }
    let public = Public::of(enc, &c1, mu);
    let mut limbs: Vec<i64> = public.pk_coefs.clone();
    limbs.extend(&public.ct_coefs);
    if (d + k) % 2 == 1 {
        limbs.push(0);
    }

    let s: Vec<i64> = (0..d).map(|j| enc.r[d - 1 - j]).collect();
    let jset: Vec<usize> = (0..d).filter(|&j| s[j] == 1).collect();
    let blocks = jset.len().div_ceil(16).max(1);
    let mut jp: Vec<Vec<F192>> = jset.iter().map(|&j| vec![gp(j as i128)]).collect();
    jp.resize(16 * blocks, vec![gp(-(d as i128))]);
    let mut gaps = Vec::new();
    let mut prev: i128 = -1;
    for &j in &jset {
        gaps.push(vec![gp(j as i128 - prev - 1)]);
        prev = j as i128;
    }

    let entry = |sum: i128, e: i64, extra: i128, c: i64| -> Vec<F192> {
        let x = i128::from(e) + i128::from(NOISE);
        let lhs = sum + i128::from(e) + extra - unsigned(c);
        let tau = lhs.div_euclid(1 << 64);
        assert!(
            lhs.rem_euclid(1 << 64) == 0 || spoil != Spoil::None,
            "not a multiple of 2^64"
        );
        let t = tau + (1 << 12);
        vec![
            gp(x & 0xff),
            gp((x >> 8) & 0xff),
            gp(x >> 16),
            gp(t & 0xff),
            gp(t >> 8),
        ]
    };
    let mut e_stream = Vec::new();
    for n in 0..d {
        let mut sum = 0i128;
        for &j in &jset {
            sum += if j <= n {
                unsigned(enc.a[n - j])
            } else {
                -unsigned(enc.a[n + d - j])
            };
        }
        e_stream.push(entry(sum, e1[n], 0, c1[n]));
    }
    let mut m_stream = Vec::new();
    for i in 0..k {
        let mut sum = 0i128;
        for &j in &jset {
            let u = i + j;
            sum += if u < d {
                unsigned(enc.b[d - 1 - u])
            } else {
                -unsigned(enc.b[2 * d - 1 - u])
            };
        }
        e_stream.push(entry(sum, enc.e2[i], i128::from(enc.m[i]) << 59, enc.c2[i]));
        m_stream.push(vec![gp(i128::from(enc.m[i]))]);
    }
    let streams = vec![
        (
            "pk".to_owned(),
            public.pk_cells.iter().map(|&c| vec![c]).collect(),
        ),
        (
            "ct".to_owned(),
            public.ct_cells.iter().map(|&c| vec![c]).collect(),
        ),
        (
            "bytes".to_owned(),
            limbs.iter().map(|&x| bytes_entry(x)).collect(),
        ),
        ("mu".to_owned(), vec![cells_of(&mu).to_vec()]),
        ("nj".to_owned(), vec![vec![gp(jset.len() as i128)]]),
        ("nb".to_owned(), vec![vec![gp(blocks as i128)]]),
        ("jp".to_owned(), jp),
        ("gap".to_owned(), gaps),
        ("e".to_owned(), e_stream),
        ("m".to_owned(), m_stream),
    ];
    Instance2 {
        source: program(d, k),
        streams,
        public: cells_of(&public.digest),
        digest: public.digest,
        pk_bytes: public.pk_bytes,
        ct_bytes: public.ct_bytes,
    }
}
