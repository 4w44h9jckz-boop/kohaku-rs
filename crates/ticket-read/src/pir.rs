//! Single-server private information retrieval in the style of `SimplePIR` (Henzinger, Hong,
//! Corrigan-Gibbs, Meiklejohn, Vaikuntanathan, USENIX Security 2023), with its parameters.
//!
//! The database is a matrix `D` of `rows x cols` bytes. A client that wants column `j` sends
//! `q = A s + e + delta u_j` (mod 2^32): an LWE encryption of the unit vector `u_j`, under a
//! public matrix `A` both sides expand from a seed, a secret `s` and a small error `e`. The
//! server answers `D q` without learning `j`: it multiplies the whole matrix by the query, so its
//! work is one pass over the database. Having downloaded the hint `H = D A` once, the client
//! computes `D q - H s = D e + delta D u_j` and rounds each entry to a byte: column `j`.
//!
//! This is an experiment's implementation, not an audited one. Its parameters are `SimplePIR`'s
//! (LWE dimension 1024, modulus 2^32, error width 6.4), and its plaintext modulus is 2^8, so
//! each entry of `D` is one byte.

use rand::{CryptoRng, Rng, RngExt, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// LWE dimension.
pub const N: usize = 1024;
/// Plaintext modulus: one byte per entry.
pub const P: u32 = 256;
/// `2^32 / P`.
pub const DELTA: u32 = 1 << 24;
/// Standard deviation of the error.
pub const SIGMA: f64 = 6.4;

/// The public matrix `A`: `cols x N`, expanded from `seed` with `ChaCha20`.
#[must_use]
pub fn public_matrix(seed: [u8; 32], cols: usize) -> Vec<u32> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    (0..cols * N).map(|_| rng.random::<u32>()).collect()
}

/// A rounded Gaussian of standard deviation [`SIGMA`], as a residue mod 2^32.
fn error(rng: &mut impl Rng) -> u32 {
    // Box-Muller from two uniform samples in (0, 1].
    let u1 = 1.0 - rng.random::<f64>();
    let u2 = rng.random::<f64>();
    let z = (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos();
    // Small and integral by construction; the cast keeps its residue mod 2^32.
    #[allow(clippy::cast_possible_wrap, clippy::cast_sign_loss)]
    let e = (z * SIGMA).round() as i64 as u32;
    e
}

/// The database: `rows x cols` bytes, column-major, so a column is contiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Database {
    pub rows: usize,
    pub cols: usize,
    /// `data[col * rows + row]`.
    pub data: Vec<u8>,
}

impl Database {
    /// The hint `H = D A`: `rows x N`, row-major.
    #[must_use]
    pub fn hint(&self, a: &[u32]) -> Vec<u32> {
        let mut h = vec![0u32; self.rows * N];
        for col in 0..self.cols {
            let a_row = &a[col * N..(col + 1) * N];
            let column = &self.data[col * self.rows..(col + 1) * self.rows];
            for (row, &d) in column.iter().enumerate() {
                if d == 0 {
                    continue;
                }
                let d = u32::from(d);
                let h_row = &mut h[row * N..(row + 1) * N];
                for (x, &y) in h_row.iter_mut().zip(a_row) {
                    *x = x.wrapping_add(d.wrapping_mul(y));
                }
            }
        }
        h
    }

    /// The server's answer: `D q`, one entry per row.
    ///
    /// # Panics
    ///
    /// If the query does not have one entry per column.
    #[must_use]
    pub fn answer(&self, query: &[u32]) -> Vec<u32> {
        assert_eq!(query.len(), self.cols, "one query entry per column");
        let mut out = vec![0u32; self.rows];
        for (col, &q) in query.iter().enumerate() {
            let column = &self.data[col * self.rows..(col + 1) * self.rows];
            for (o, &d) in out.iter_mut().zip(column) {
                *o = o.wrapping_add(u32::from(d).wrapping_mul(q));
            }
        }
        out
    }
}

/// What the client keeps to decode its answer.
pub struct Secret {
    s: Vec<u32>,
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// A query for column `col` of a `cols`-column database under the public matrix `a`.
#[must_use]
pub fn query(rng: &mut impl CryptoRng, a: &[u32], cols: usize, col: usize) -> (Vec<u32>, Secret) {
    let s: Vec<u32> = (0..N).map(|_| rng.random()).collect();
    let q = (0..cols)
        .map(|j| {
            let a_row = &a[j * N..(j + 1) * N];
            let mut v = a_row
                .iter()
                .zip(&s)
                .fold(0u32, |acc, (&x, &y)| acc.wrapping_add(x.wrapping_mul(y)))
                .wrapping_add(error(rng));
            if j == col {
                v = v.wrapping_add(DELTA);
            }
            v
        })
        .collect();
    (q, Secret { s })
}

/// Decode an answer into the queried column, with the hint.
///
/// # Panics
///
/// If the answer and hint do not have the same number of rows.
#[must_use]
pub fn decode(hint: &[u32], answer: &[u32], secret: &Secret) -> Vec<u8> {
    assert_eq!(
        hint.len(),
        answer.len() * N,
        "the hint has N entries per row"
    );
    answer
        .iter()
        .enumerate()
        .map(|(row, &v)| {
            let hs = hint[row * N..(row + 1) * N]
                .iter()
                .zip(&secret.s)
                .fold(0u32, |acc, (&x, &y)| acc.wrapping_add(x.wrapping_mul(y)));
            // Round (v - H s) / delta to the nearest byte.
            let noisy = v.wrapping_sub(hs).wrapping_add(DELTA / 2);
            (noisy >> 24) as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;

    use super::*;

    #[test]
    fn a_query_returns_its_column_and_only_that() {
        let mut rng = StdRng::seed_from_u64(3);
        let (rows, cols) = (120, 150);
        let db = Database {
            rows,
            cols,
            data: (0..rows * cols).map(|_| rng.random()).collect(),
        };
        let a = public_matrix([9; 32], cols);
        let hint = db.hint(&a);
        for col in [0, 77, cols - 1] {
            let (q, secret) = query(&mut rng, &a, cols, col);
            let got = decode(&hint, &db.answer(&q), &secret);
            assert_eq!(got, db.data[col * rows..(col + 1) * rows]);
        }
    }
}
