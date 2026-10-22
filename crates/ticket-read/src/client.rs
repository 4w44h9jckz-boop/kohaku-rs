//! The reader: one ticket per read, and a `LookupBackend` for `kohaku-pir-rpc`'s router.
//!
//! `kohaku-pir-rpc` (upstream kohaku-rs, branch `experiments/pir-v1`) routes `eth_getBalance`,
//! `eth_getTransactionCount` and `eth_getCode` to a [`LookupBackend`] and leaves the PIR scheme
//! to it. [`TicketLookup`] is one: each lookup spends a ticket and sends the server an LWE query
//! for the key's bucket, so the server sees a ticket and a query, and no address.

use std::sync::{Mutex, PoisonError};

use alloy::primitives::B256;
use commonware_codec::Encode;
use kohaku_pir_rpc::{LookupBackend, PirProviderError};

use crate::{
    pir,
    server::{Manifest, ReadRequest, ReadResponse, WireTicket, hex_to_words, words_to_hex},
    table::{self, VALUE},
    ticket::ReadTicket,
};

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("no ticket left")]
    NoTicket,
    #[error("refused: {0}")]
    Refused(String),
    #[error("a malformed answer")]
    Malformed,
}

/// A reader of one server.
pub struct Reader {
    base: String,
    http: reqwest::Client,
    pub manifest: Manifest,
    a: Vec<u32>,
    hint: Vec<u32>,
    tickets: Mutex<Vec<ReadTicket>>,
}

impl std::fmt::Debug for Reader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reader")
            .field("base", &self.base)
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl Reader {
    /// Fetch the server's manifest and hint.
    pub async fn connect(base: &str) -> Result<Self, ReadError> {
        let http = reqwest::Client::new();
        let manifest: Manifest = http
            .get(format!("{base}/manifest"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let hint_bytes = http
            .get(format!("{base}/hint"))
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        if hint_bytes.len() != manifest.rows * pir::N * 4 {
            return Err(ReadError::Malformed);
        }
        let hint = hint_bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        Ok(Self {
            base: base.to_owned(),
            http,
            a: pir::public_matrix(manifest.seed.0, manifest.cols),
            manifest,
            hint,
            tickets: Mutex::new(Vec::new()),
        })
    }

    /// The hint's size in bytes: what a reader downloads once.
    #[must_use]
    pub fn hint_bytes(&self) -> usize {
        self.hint.len() * 4
    }

    /// Hold `tickets` for later reads.
    pub fn add_tickets(&self, tickets: impl IntoIterator<Item = ReadTicket>) {
        self.tickets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend(tickets);
    }

    /// Send `query` with `ticket` and return the server's answer.
    pub async fn send(&self, query: &[u32], ticket: &ReadTicket) -> Result<Vec<u32>, ReadError> {
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
        let r: ReadResponse = resp.json().await?;
        hex_to_words(&r.answer)
            .filter(|a| a.len() == self.manifest.rows)
            .ok_or(ReadError::Malformed)
    }

    /// Read `key`'s value privately, spending one ticket.
    pub async fn read(&self, key: &[u8]) -> Result<Option<[u8; VALUE]>, ReadError> {
        let ticket = self
            .tickets
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
            .ok_or(ReadError::NoTicket)?;
        let col = table::bucket(self.manifest.salt, key, self.manifest.cols);
        let (query, secret) = pir::query(&mut rand::rng(), &self.a, self.manifest.cols, col);
        let answer = self.send(&query, &ticket).await?;
        let column = pir::decode(&self.hint, &answer, &secret);
        Ok(table::find(&column, key))
    }

    /// The server's identity, which a read ticket must name.
    #[must_use]
    pub fn server(&self) -> B256 {
        self.manifest.server
    }
}

/// [`Reader`] as `kohaku-pir-rpc`'s account backend. The router calls it from a blocking thread
/// of the runtime, so it drives the async read on the runtime's handle.
pub struct TicketLookup {
    pub reader: std::sync::Arc<Reader>,
    pub runtime: tokio::runtime::Handle,
}

impl LookupBackend for TicketLookup {
    fn lookup(&self, key: &[u8]) -> Result<Option<Vec<u8>>, PirProviderError> {
        self.runtime
            .block_on(self.reader.read(key))
            .map(|v| v.map(|v| v.to_vec()))
            .map_err(|e| PirProviderError::Client(e.to_string()))
    }
}
