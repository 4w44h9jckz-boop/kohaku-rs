//! A signed wrong answer, made evidence, and the third party who judges it.
//!
//! A PIR answer is encrypted for the reader: no one else can read it. To show it wrong, the reader
//! opens its query, disclosing the LWE secret, and with it which bucket it read. The evidence is:
//!
//! - the server's manifest, the query, the answer and the server's signature on them;
//! - the query's secret and the column it was for;
//! - the slot of the disputed record in the bucket, and the hint rows that decode its
//!   `address || value`, each with its path to the manifest's hint root.
//!
//! [`judge`] holds nothing else of the reader's or the server's. It checks the signature, the
//! hint rows and the query, decodes the record, and compares it with the account as the chain
//! holds it: a branch the third party fetched itself, against a header it fetched itself.
//!
//! The query check stops a reader from framing an honest server. Decoding row `r` gives
//! `D[r][j] + sum_c D[r][c] e_c` before rounding, so when `255 * sum_c |e_c| < 2^23`, half of
//! `2^32 / 256`, an honest server's record decodes exactly, whatever the table holds.

use alloy::primitives::{Address, B256, Bytes, Signature};
use kohaku_ticket_read::{
    pir::{self, DELTA, N},
    server::hex_to_words,
};
use serde::{Deserialize, Serialize};

use crate::{
    header::Header,
    server::Manifest,
    statement,
    table::{CLAIM, VALUE},
    trie::{self, AccountState, Nodes},
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub manifest: Manifest,
    /// `u32`s, little-endian, as they travelled.
    pub query: String,
    pub answer: String,
    pub signature: String,
    /// The query's opened secret, `N` `u32`s, little-endian.
    pub secret: String,
    pub column: usize,
    pub slot: usize,
    /// Rows `slot * record` to `slot * record + CLAIM` of the hint, `N` `u32`s each.
    pub hint_rows: Vec<String>,
    pub hint_paths: Vec<Vec<B256>>,
    /// What the reader says the server answered: `address || value`.
    pub claimed: Bytes,
}

/// What the third party finds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The server signed `signed` for `address`, and the chain holds `chain`.
    Wrong {
        address: Address,
        signed: [u8; VALUE],
        chain: Option<AccountState>,
    },
    /// The signed answer is the chain's.
    Correct { address: Address },
}

/// Why evidence is dismissed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Dismissed {
    #[error("malformed evidence: {0}")]
    Malformed(&'static str),
    #[error("the signature is not the server's")]
    Signature,
    #[error("the header is not the snapshot's: block {0}, or another state root")]
    Header(u64),
    #[error("hint row {0} is not under the hint root")]
    HintRow(usize),
    #[error("the query is not well formed: its error sums to {0}")]
    Query(u64),
    #[error("the record decodes to something other than what is claimed")]
    Claim,
    #[error("the chain's branch does not settle it: {0}")]
    Chain(trie::TrieError),
}

fn inner(a: &[u32], b: &[u32]) -> u32 {
    a.iter()
        .zip(b)
        .fold(0u32, |acc, (&x, &y)| acc.wrapping_add(x.wrapping_mul(y)))
}

/// Judge `e` against `header`, fetched by the judge, and `chain`, the nodes of the disputed
/// account's branch at the header's block, fetched by the judge.
pub fn judge(e: &Evidence, header: &Header, chain: &Nodes) -> Result<Verdict, Dismissed> {
    let m = &e.manifest;
    let query = hex_to_words(&e.query).ok_or(Dismissed::Malformed("query"))?;
    let answer = hex_to_words(&e.answer).ok_or(Dismissed::Malformed("answer"))?;
    let secret = hex_to_words(&e.secret).ok_or(Dismissed::Malformed("secret"))?;
    if query.len() != m.cols || answer.len() != m.rows || secret.len() != N || e.column >= m.cols {
        return Err(Dismissed::Malformed("sizes"));
    }

    // 1. The server's signature, under its identity.
    let raw = hex::decode(e.signature.trim_start_matches("0x"))
        .map_err(|_| Dismissed::Malformed("signature"))?;
    let sig = Signature::try_from(raw.as_slice()).map_err(|_| Dismissed::Signature)?;
    let digest = statement::digest(statement::commitment(m), &query, &answer);
    if sig.recover_address_from_prehash(&digest).ok() != Some(m.signer)
        || statement::identity(m.signer) != m.server
    {
        return Err(Dismissed::Signature);
    }

    // 2. The snapshot is the chain's.
    if header.number != m.block || header.state_root != m.state_root {
        return Err(Dismissed::Header(header.number));
    }

    // 3. The query is well formed: an encryption of column `column` with small error.
    let a = pir::public_matrix(m.seed.0, m.cols);
    let noise: u64 = (0..m.cols)
        .map(|c| {
            let mut v = query[c].wrapping_sub(inner(&a[c * N..(c + 1) * N], &secret));
            if c == e.column {
                v = v.wrapping_sub(DELTA);
            }
            // The residue, centred.
            #[allow(clippy::cast_possible_wrap)]
            u64::from((v as i32).unsigned_abs())
        })
        .sum();
    if noise * 255 >= u64::from(DELTA / 2) {
        return Err(Dismissed::Query(noise));
    }

    // 4. The hint rows, and the record they decode.
    if e.hint_rows.len() != CLAIM || e.hint_paths.len() != CLAIM || e.slot >= m.capacity {
        return Err(Dismissed::Malformed("hint rows"));
    }
    let mut record = [0u8; CLAIM];
    for (k, (row, path)) in e.hint_rows.iter().zip(&e.hint_paths).enumerate() {
        let index = e.slot * m.record + k;
        let row = hex_to_words(row)
            .filter(|r| r.len() == N)
            .ok_or(Dismissed::Malformed("hint row"))?;
        if !statement::row_under(m.hint_root, &row, index, path) {
            return Err(Dismissed::HintRow(index));
        }
        let v = answer[index]
            .wrapping_sub(inner(&row, &secret))
            .wrapping_add(DELTA / 2);
        record[k] = (v >> 24) as u8;
    }
    if record[..] != e.claimed[..] {
        return Err(Dismissed::Claim);
    }
    let address = Address::from_slice(&record[..20]);
    let mut signed = [0u8; VALUE];
    signed.copy_from_slice(&record[20..]);

    // 5. The chain.
    let chain = trie::account(header.state_root, address, chain).map_err(Dismissed::Chain)?;
    Ok(match chain {
        Some(st) if st.is(&signed) => Verdict::Correct { address },
        _ => Verdict::Wrong {
            address,
            signed,
            chain,
        },
    })
}
