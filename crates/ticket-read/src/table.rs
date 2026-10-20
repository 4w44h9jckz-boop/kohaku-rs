//! The account table, laid out for [`crate::pir`]: hashed buckets as columns.
//!
//! A record is `address (20) || value (40)`, the value as `kohaku-pir-rpc` decodes an account:
//! `delegate (20) || balance (12) || nonce (8)`. A key goes to bucket
//! `keccak256(salt || address) mod cols`, and a bucket holds up to `capacity` records, so a
//! column is `60 * capacity` bytes. A reader fetches its key's whole bucket and looks for its
//! record in it, so the server learns neither the key nor the bucket.

use std::collections::BTreeMap;

use alloy::primitives::{Address, B256, U256, keccak256};

use crate::pir::Database;

pub const KEY: usize = 20;
pub const VALUE: usize = 40;
pub const RECORD: usize = KEY + VALUE;

/// An account as the table holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Account {
    /// The EIP-7702 delegate, or zero.
    pub delegate: Address,
    /// At most 2^96 - 1 wei.
    pub balance: U256,
    pub nonce: u64,
}

impl Account {
    /// `delegate || balance (12 bytes) || nonce (8 bytes)`.
    ///
    /// # Panics
    ///
    /// If the balance does not fit in 96 bits.
    #[must_use]
    pub fn value(&self) -> [u8; VALUE] {
        let mut v = [0u8; VALUE];
        v[..20].copy_from_slice(self.delegate.as_slice());
        let b = self.balance.to_be_bytes::<32>();
        assert!(b[..20].iter().all(|&x| x == 0), "a balance over 96 bits");
        v[20..32].copy_from_slice(&b[20..]);
        v[32..].copy_from_slice(&self.nonce.to_be_bytes());
        v
    }
}

/// The table and how its keys are placed.
#[derive(Debug, Clone)]
pub struct Table {
    pub salt: B256,
    pub capacity: usize,
    pub db: Database,
    pub entries: usize,
}

#[derive(Debug, thiserror::Error)]
#[error("no salt in {0} tries fits every bucket in its capacity")]
pub struct Overfull(pub usize);

/// The bucket `key` goes to.
#[must_use]
pub fn bucket(salt: B256, key: &[u8], cols: usize) -> usize {
    let h = keccak256([salt.as_slice(), key].concat());
    let n = U256::from_be_slice(h.as_slice()) % U256::from(cols);
    n.to::<usize>()
}

impl Table {
    /// Lay `accounts` out in buckets of `capacity` records, about one third full on average,
    /// with the first salt from `salts` that overflows no bucket.
    pub fn build(
        accounts: &BTreeMap<Address, Account>,
        capacity: usize,
        salts: impl IntoIterator<Item = B256>,
    ) -> Result<Self, Overfull> {
        let cols = (accounts.len() * 3).div_ceil(capacity).max(1);
        let rows = capacity * RECORD;
        let mut tries = 0;
        for salt in salts {
            tries += 1;
            let mut fill = vec![0usize; cols];
            let mut data = vec![0u8; rows * cols];
            let mut fits = true;
            for (address, account) in accounts {
                let b = bucket(salt, address.as_slice(), cols);
                if fill[b] == capacity {
                    fits = false;
                    break;
                }
                let at = b * rows + fill[b] * RECORD;
                data[at..at + KEY].copy_from_slice(address.as_slice());
                data[at + KEY..at + RECORD].copy_from_slice(&account.value());
                fill[b] += 1;
            }
            if fits {
                return Ok(Self {
                    salt,
                    capacity,
                    db: Database { rows, cols, data },
                    entries: accounts.len(),
                });
            }
        }
        Err(Overfull(tries))
    }
}

/// The value for `key` in a fetched bucket, if it is there.
#[must_use]
pub fn find(column: &[u8], key: &[u8]) -> Option<[u8; VALUE]> {
    column
        .chunks_exact(RECORD)
        .find(|r| &r[..KEY] == key && key.iter().any(|&b| b != 0))
        .and_then(|r| r[KEY..].try_into().ok())
}
