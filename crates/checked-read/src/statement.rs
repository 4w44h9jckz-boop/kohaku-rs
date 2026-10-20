//! What the server signs for each answer, and the commitment to its hint.
//!
//! ```text
//! commitment = keccak256("kohaku-checked-read-v1" || server (32) || block (8) || state_root (32)
//!                        || seed (32) || salt (32) || rows (4) || cols (4) || capacity (4)
//!                        || record (4) || hint_root (32))
//! digest     = keccak256(commitment || keccak256(query) || keccak256(answer))
//! ```
//!
//! Integers are big-endian; `query` and `answer` are their `u32`s little-endian, as they travel.
//! The server signs `digest` itself with secp256k1, and its identity, the one a read ticket names,
//! is its address left-padded to 32 bytes. `hint_root` is a binary keccak tree over the hint's rows
//! (`keccak256` of each row's 1024 `u32`s, little-endian), padded with zero leaves to a power of
//! two. So one signed answer commits the server to the snapshot, the table's shape, the hint, the
//! query it was asked and the answer it gave, and to nothing a reader chose.

use alloy::primitives::{Address, B256, keccak256};

use crate::server::Manifest;

pub const DOMAIN: &[u8] = b"kohaku-checked-read-v1";

/// A server's identity: its signing address, left-padded.
#[must_use]
pub fn identity(signer: Address) -> B256 {
    B256::left_padding_from(signer.as_slice())
}

#[must_use]
pub fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|x| x.to_le_bytes()).collect()
}

#[must_use]
pub fn commitment(m: &Manifest) -> B256 {
    let n = |x: usize| u32::try_from(x).unwrap_or(u32::MAX).to_be_bytes();
    keccak256(
        [
            DOMAIN,
            m.server.as_slice(),
            &m.block.to_be_bytes(),
            m.state_root.as_slice(),
            m.seed.as_slice(),
            m.salt.as_slice(),
            &n(m.rows),
            &n(m.cols),
            &n(m.capacity),
            &n(m.record),
            m.hint_root.as_slice(),
        ]
        .concat(),
    )
}

#[must_use]
pub fn digest(commitment: B256, query: &[u32], answer: &[u32]) -> B256 {
    keccak256(
        [
            commitment.as_slice(),
            keccak256(words(query)).as_slice(),
            keccak256(words(answer)).as_slice(),
        ]
        .concat(),
    )
}

/// The tree's levels, leaves first.
fn levels(hint: &[u32], width: usize) -> Vec<Vec<B256>> {
    let mut level: Vec<B256> = hint.chunks_exact(width).map(|r| keccak256(words(r))).collect();
    level.resize(level.len().next_power_of_two(), B256::ZERO);
    let mut out = vec![level];
    while out.last().is_some_and(|l| l.len() > 1) {
        let up = out[out.len() - 1]
            .chunks_exact(2)
            .map(|p| keccak256([p[0].as_slice(), p[1].as_slice()].concat()))
            .collect();
        out.push(up);
    }
    out
}

/// The root over the hint's rows of `width` words.
#[must_use]
pub fn hint_root(hint: &[u32], width: usize) -> B256 {
    levels(hint, width).last().map_or(B256::ZERO, |l| l[0])
}

/// The siblings of each of `rows`, from the leaf up.
#[must_use]
pub fn hint_paths(hint: &[u32], width: usize, rows: impl IntoIterator<Item = usize>) -> Vec<Vec<B256>> {
    let levels = levels(hint, width);
    rows.into_iter()
        .map(|mut i| {
            levels[..levels.len() - 1]
                .iter()
                .map(|l| {
                    let s = l[i ^ 1];
                    i >>= 1;
                    s
                })
                .collect()
        })
        .collect()
}

/// Whether `row`, at `index`, is under `root` by `path`.
#[must_use]
pub fn row_under(root: B256, row: &[u32], mut index: usize, path: &[B256]) -> bool {
    let mut h = keccak256(words(row));
    for s in path {
        h = if index & 1 == 0 {
            keccak256([h.as_slice(), s.as_slice()].concat())
        } else {
            keccak256([s.as_slice(), h.as_slice()].concat())
        };
        index >>= 1;
    }
    index == 0 && h == root
}
