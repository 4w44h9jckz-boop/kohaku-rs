//! The account table with each account's branch in its record.
//!
//! A record is experiment 37's `address (20) || value (40)`, followed by the branch's lower part:
//!
//! ```text
//! address (20) || delegate (20) || balance (12) || nonce (8) || n (2, big-endian) || nodes (n) || zeros
//! ```
//!
//! `nodes` are the branch's nodes at depth `split` and below, each RLP-encoded as `eth_getProof`
//! returns it, laid end to end. The nodes above `split` are the trie's top, the same for every
//! reader: the union over the table's accounts goes into [`CheckedTable::top`], which a reader
//! downloads once. `split = 0` puts the whole branch in each record. Every record is padded to the
//! longest, so a column is `capacity * record` bytes and buckets are placed as in experiment 37.

use std::collections::{BTreeMap, BTreeSet};

use alloy::primitives::{Address, B256, Bytes, keccak256};
use kohaku_ticket_read::{
    Account,
    pir::Database,
    table::{KEY, bucket},
};

pub use kohaku_ticket_read::table::VALUE;

/// `address || value`: what a record claims.
pub const CLAIM: usize = KEY + VALUE;

/// An account and its `eth_getProof` branch, from the root down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub account: Account,
    pub proof: Vec<Bytes>,
}

#[derive(Debug, Clone)]
pub struct CheckedTable {
    pub salt: B256,
    pub capacity: usize,
    /// Bytes per record.
    pub record: usize,
    pub split: usize,
    /// The nodes above `split` on every account's branch, each once, ordered by hash.
    pub top: Vec<Bytes>,
    pub db: Database,
    pub entries: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum TableError {
    #[error("no salt in {0} tries fits every bucket in its capacity")]
    Overfull(usize),
    #[error("a branch longer than 65535 bytes")]
    Long,
}

/// `entry`'s record, unpadded.
fn record(address: Address, entry: &Entry, split: usize) -> Result<Vec<u8>, TableError> {
    let nodes: Vec<u8> = entry.proof.iter().skip(split).flatten().copied().collect();
    let n = u16::try_from(nodes.len()).map_err(|_| TableError::Long)?;
    Ok([
        address.as_slice(),
        &entry.account.value(),
        &n.to_be_bytes(),
        &nodes,
    ]
    .concat())
}

impl CheckedTable {
    /// Lay `entries` out in buckets of `capacity` records, about one third full on average, with
    /// the first salt from `salts` that overflows no bucket; the branch split at depth `split`.
    pub fn build(
        entries: &BTreeMap<Address, Entry>,
        capacity: usize,
        split: usize,
        salts: impl IntoIterator<Item = B256>,
    ) -> Result<Self, TableError> {
        let records = entries
            .iter()
            .map(|(a, e)| Ok((*a, record(*a, e, split)?)))
            .collect::<Result<Vec<_>, TableError>>()?;
        let len = records.iter().map(|(_, r)| r.len()).max().unwrap_or(CLAIM + 2);
        let top: BTreeSet<(B256, Bytes)> = entries
            .values()
            .flat_map(|e| e.proof.iter().take(split))
            .map(|n| (keccak256(n), n.clone()))
            .collect();
        let cols = (entries.len() * 3).div_ceil(capacity).max(1);
        let rows = capacity * len;
        let mut tries = 0;
        for salt in salts {
            tries += 1;
            let mut fill = vec![0usize; cols];
            let mut data = vec![0u8; rows * cols];
            let mut fits = true;
            for (address, r) in &records {
                let b = bucket(salt, address.as_slice(), cols);
                if fill[b] == capacity {
                    fits = false;
                    break;
                }
                let at = b * rows + fill[b] * len;
                data[at..at + r.len()].copy_from_slice(r);
                fill[b] += 1;
            }
            if fits {
                return Ok(Self {
                    salt,
                    capacity,
                    record: len,
                    split,
                    top: top.into_iter().map(|(_, n)| n).collect(),
                    db: Database { rows, cols, data },
                    entries: entries.len(),
                });
            }
        }
        Err(TableError::Overfull(tries))
    }

    /// The bytes every reader downloads once: the trie's top.
    #[must_use]
    pub fn top_bytes(&self) -> usize {
        self.top.iter().map(|n| n.len()).sum()
    }
}

/// A record found in a fetched bucket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// Its place in the bucket.
    pub slot: usize,
    pub value: [u8; VALUE],
    /// The branch's lower part, as the record carries it.
    pub nodes: Vec<u8>,
}

/// `key`'s record in a fetched bucket of `record`-byte records, if it is there.
#[must_use]
pub fn find(column: &[u8], record: usize, key: &[u8]) -> Option<Found> {
    if key.iter().all(|&b| b == 0) || record < CLAIM + 2 {
        return None;
    }
    column
        .chunks_exact(record)
        .enumerate()
        .find(|(_, r)| &r[..KEY] == key)
        .and_then(|(slot, r)| {
            let n = usize::from(u16::from_be_bytes([r[CLAIM], r[CLAIM + 1]]));
            Some(Found {
                slot,
                value: r[KEY..CLAIM].try_into().ok()?,
                nodes: r.get(CLAIM + 2..CLAIM + 2 + n)?.to_vec(),
            })
        })
}
