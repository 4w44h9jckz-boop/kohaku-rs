//! The reader that checks: one ticket per read, a branch checked against a header it fetched
//! itself, and evidence kept for every answer it refuses.
//!
//! On connecting, the reader downloads the hint and the trie's top once, checks the hint against
//! the root the server commits to, and fetches the snapshot's header from its own node, hashing
//! it again ([`Header::fetch`]). A read then:
//!
//! 1. spends a ticket on a PIR query for the key's bucket, as experiment 37's reader does;
//! 2. refuses the answer unless the server's signature on it recovers to the manifest's signer;
//! 3. decodes the bucket and finds the key's record. No record is no answer: there is no branch to
//!    check, so the reader does not read it as an empty account;
//! 4. walks from its own header's state root to the key's account, taking nodes from the trie's
//!    top and the record's branch by their hashes, and accepts the record's value only if the
//!    account it reaches is that value.
//!
//! An answer refused at step 4 is signed, so the reader keeps it as [`Evidence`].

use std::sync::{Mutex, PoisonError};

use alloy::primitives::{Address, B256, Bytes, Signature};
use commonware_codec::Encode;
use kohaku_pir_rpc::{LookupBackend, PirProviderError};
use kohaku_ticket_read::{
    ReadTicket, pir,
    server::{ReadRequest, WireTicket, hex_to_words, words_to_hex},
    table::bucket,
};

use crate::{
    evidence::Evidence,
    header::{Header, HeaderError},
    server::{Manifest, SignedResponse},
    statement,
    table::{CLAIM, VALUE, find},
    trie::{self, Nodes},
};

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Header(#[from] HeaderError),
    #[error("the server's snapshot is not the chain's: state root {0} at its block")]
    Snapshot(B256),
    #[error("the hint is not the one the server commits to")]
    Hint,
    #[error("no ticket left")]
    NoTicket,
    #[error("refused: {0}")]
    Refused(String),
    #[error("a malformed answer")]
    Malformed,
    #[error("an answer the server did not sign")]
    Unsigned,
    #[error("no record for the key in its bucket, so no branch: unanswered")]
    Unanswered,
    #[error("a wrong answer: {0}")]
    Wrong(String),
}

/// A read the reader checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Checked {
    /// The record's value, proven by its branch against the reader's header.
    Proven { value: [u8; VALUE], slot: usize },
    /// The record's value, refused, and the evidence for it.
    Refused {
        why: String,
        evidence: Box<Evidence>,
    },
}

pub struct CheckedReader {
    base: String,
    http: reqwest::Client,
    pub manifest: Manifest,
    /// The header the reader trusts, from its own node.
    pub header: Header,
    a: Vec<u32>,
    hint: Vec<u32>,
    top: Vec<Bytes>,
    tickets: Mutex<Vec<ReadTicket>>,
    refused: Mutex<Vec<Evidence>>,
}

impl std::fmt::Debug for CheckedReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CheckedReader")
            .field("base", &self.base)
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl CheckedReader {
    /// Fetch the server's manifest, hint and trie top from `base`, and the snapshot's header
    /// from the node at `rpc`.
    pub async fn connect(base: &str, rpc: &str) -> Result<Self, ReadError> {
        let http = reqwest::Client::new();
        let manifest: Manifest = http
            .get(format!("{base}/manifest"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let header = Header::fetch(rpc, manifest.block).await?;
        Self::with_header(base, manifest, header).await
    }

    /// As [`Self::connect`], with a header the caller fetched itself.
    pub async fn with_header(
        base: &str,
        manifest: Manifest,
        header: Header,
    ) -> Result<Self, ReadError> {
        if header.number != manifest.block || header.state_root != manifest.state_root {
            return Err(ReadError::Snapshot(manifest.state_root));
        }
        let http = reqwest::Client::new();
        let raw = http
            .get(format!("{base}/hint"))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        if raw.len() != manifest.rows * pir::N * 4 {
            return Err(ReadError::Malformed);
        }
        let hint: Vec<u32> = raw
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        if statement::hint_root(&hint, pir::N) != manifest.hint_root {
            return Err(ReadError::Hint);
        }
        let top: Vec<Bytes> = http
            .get(format!("{base}/top"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        Ok(Self {
            base: base.to_owned(),
            http,
            a: pir::public_matrix(manifest.seed.0, manifest.cols),
            manifest,
            header,
            hint,
            top,
            tickets: Mutex::new(Vec::new()),
            refused: Mutex::new(Vec::new()),
        })
    }

    /// What a reader downloads once: the hint and the trie's top, in bytes.
    #[must_use]
    pub fn once_bytes(&self) -> (usize, usize) {
        (self.hint.len() * 4, self.top.iter().map(|n| n.len()).sum())
    }

    pub fn add_tickets(&self, tickets: impl IntoIterator<Item = ReadTicket>) {
        self.tickets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(tickets);
    }

    /// Evidence for every answer refused so far.
    #[must_use]
    pub fn refused(&self) -> Vec<Evidence> {
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Send `query` with `ticket`: the answer, and the signature, checked.
    pub async fn send(
        &self,
        query: &[u32],
        ticket: &ReadTicket,
    ) -> Result<(Vec<u32>, String), ReadError> {
        let resp = self
            .http
            .post(format!("{}/read", self.base))
            .json(&ReadRequest {
                query: words_to_hex(query),
                ticket: WireTicket {
                    serial: ticket.claim.serial,
                    signature: format!("0x{}", hex::encode(ticket.signature.encode())),
                },
            })
            .send()
            .await?;
        if !resp.status().is_success() {
            return Err(ReadError::Refused(resp.text().await.unwrap_or_default()));
        }
        let r: SignedResponse = resp.json().await?;
        let answer = hex_to_words(&r.answer)
            .filter(|a| a.len() == self.manifest.rows)
            .ok_or(ReadError::Malformed)?;
        let raw = hex::decode(r.signature.trim_start_matches("0x")).map_err(|_| ReadError::Unsigned)?;
        let digest = statement::digest(statement::commitment(&self.manifest), query, &answer);
        let signer = Signature::try_from(raw.as_slice())
            .ok()
            .and_then(|s| s.recover_address_from_prehash(&digest).ok());
        if signer != Some(self.manifest.signer) {
            return Err(ReadError::Unsigned);
        }
        Ok((answer, r.signature))
    }

    /// Read `address`'s account privately, spending one ticket, and check it.
    pub async fn read(&self, address: Address) -> Result<Checked, ReadError> {
        let ticket = self
            .tickets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .ok_or(ReadError::NoTicket)?;
        let m = &self.manifest;
        let col = bucket(m.salt, address.as_slice(), m.cols);
        let (query, secret) = pir::query(&mut rand::rng(), &self.a, m.cols, col);
        let (answer, signature) = self.send(&query, &ticket).await?;
        let column = pir::decode(&self.hint, &answer, &secret);
        let found = find(&column, m.record, address.as_slice()).ok_or(ReadError::Unanswered)?;

        let why = match trie::split_nodes(&found.nodes) {
            Err(e) => format!("the record's branch is malformed: {e}"),
            Ok(lower) => {
                let nodes: Nodes = self.top.iter().chain(&lower).collect();
                match trie::account(self.header.state_root, address, &nodes) {
                    Ok(Some(st)) if st.is(&found.value) => {
                        return Ok(Checked::Proven {
                            value: found.value,
                            slot: found.slot,
                        });
                    }
                    Ok(Some(_)) => "the branch proves another account".to_owned(),
                    Ok(None) => "the branch proves the account absent".to_owned(),
                    Err(e) => format!("the branch does not reach the header's state root: {e}"),
                }
            }
        };
        let rows: Vec<usize> = (0..CLAIM).map(|k| found.slot * m.record + k).collect();
        let evidence = Evidence {
            manifest: m.clone(),
            query: words_to_hex(&query),
            answer: words_to_hex(&answer),
            signature,
            secret: words_to_hex(secret.open()),
            column: col,
            slot: found.slot,
            hint_rows: rows
                .iter()
                .map(|&r| words_to_hex(&self.hint[r * pir::N..(r + 1) * pir::N]))
                .collect(),
            hint_paths: statement::hint_paths(&self.hint, pir::N, rows.iter().copied()),
            claimed: Bytes::from([address.as_slice(), &found.value].concat()),
        };
        self.refused
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(evidence.clone());
        Ok(Checked::Refused {
            why,
            evidence: Box::new(evidence),
        })
    }
}

/// [`CheckedReader`] as `kohaku-pir-rpc`'s account backend: a value only when its branch proves
/// it, and an error otherwise, never an empty account in its place.
pub struct CheckedLookup {
    pub reader: std::sync::Arc<CheckedReader>,
    pub runtime: tokio::runtime::Handle,
}

impl LookupBackend for CheckedLookup {
    fn lookup(&self, key: &[u8]) -> Result<Option<Vec<u8>>, PirProviderError> {
        let address = Address::try_from(key).map_err(|e| PirProviderError::Client(e.to_string()))?;
        match self.runtime.block_on(self.reader.read(address)) {
            Ok(Checked::Proven { value, .. }) => Ok(Some(value.to_vec())),
            Ok(Checked::Refused { why, .. }) => Err(PirProviderError::Client(
                ReadError::Wrong(why).to_string(),
            )),
            Err(e) => Err(PirProviderError::Client(e.to_string())),
        }
    }
}
