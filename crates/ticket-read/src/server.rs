//! The read server: a ticket checked before any work, then one PIR answer.
//!
//! ```text
//! GET  /manifest   the server's identity, the table's shape, the seed of A, the committee's key
//! GET  /hint       H = D A, little-endian u32s, once per reader
//! POST /read       {"query": <u32s, little-endian, hex>, "ticket": {"serial", "signature"}}
//!                  -> {"answer": <u32s, little-endian, hex>}
//! GET  /log        what the server saw of each request
//! ```
//!
//! A request carries a query and a ticket, nothing else. The server checks the ticket's
//! signature and its own spent set first, and only then multiplies the table by the query. It
//! logs, per request, the serial, the verdict, the time each step took and the sizes, which is
//! everything it learns.

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use alloy::primitives::B256;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::bls12381::primitives::group::{G1, G2};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    pir,
    table::{RECORD, Table},
    ticket::{READ_NAMESPACE, ReadClaim, ReadTicket},
};

/// What a reader needs to query the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub server: B256,
    /// The committee's key, Commonware's compressed G2.
    pub key: String,
    pub namespace: String,
    pub seed: B256,
    pub rows: usize,
    pub cols: usize,
    pub capacity: usize,
    pub record: usize,
    pub salt: B256,
    pub entries: usize,
}

/// A ticket as a request carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireTicket {
    pub serial: B256,
    /// Commonware's compressed G1.
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadRequest {
    pub query: String,
    pub ticket: WireTicket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadResponse {
    pub answer: String,
}

pub struct Server {
    pub manifest: Manifest,
    key: G2,
    table: Table,
    hint: Vec<u8>,
    spent: Mutex<HashSet<B256>>,
    log: Mutex<Vec<Value>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn words_to_hex(words: &[u32]) -> String {
    let bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
    format!("0x{}", hex::encode(bytes))
}

#[must_use]
pub fn hex_to_words(s: &str) -> Option<Vec<u32>> {
    let bytes = hex::decode(s.strip_prefix("0x").unwrap_or(s)).ok()?;
    if bytes.len() % 4 != 0 {
        return None;
    }
    Some(
        bytes
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect(),
    )
}

impl Server {
    /// A server for `table`, with the committee's `key`, under identity `server` and the seed
    /// of its public matrix.
    #[must_use]
    pub fn new(table: Table, key: G2, server: B256, seed: B256) -> Self {
        let a = pir::public_matrix(seed.0, table.db.cols);
        let hint: Vec<u8> = table
            .db
            .hint(&a)
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        let manifest = Manifest {
            server,
            key: format!("0x{}", hex::encode(key.encode())),
            namespace: String::from_utf8_lossy(READ_NAMESPACE).into_owned(),
            seed,
            rows: table.db.rows,
            cols: table.db.cols,
            capacity: table.capacity,
            record: RECORD,
            salt: table.salt,
            entries: table.entries,
        };
        Self {
            manifest,
            key,
            table,
            hint,
            spent: Mutex::new(HashSet::new()),
            log: Mutex::new(Vec::new()),
        }
    }

    /// The routes.
    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route(
                "/manifest",
                get(|State(s): State<Arc<Self>>| async move { Json(s.manifest.clone()) }),
            )
            .route(
                "/hint",
                get(|State(s): State<Arc<Self>>| async move { s.hint.clone() }),
            )
            .route("/read", post(read))
            .route(
                "/log",
                get(|State(s): State<Arc<Self>>| async move {
                    Json(s.log.lock().unwrap_or_else(PoisonError::into_inner).clone())
                }),
            )
            .with_state(self)
    }

    /// Check a ticket: its signature, then the spent set, which it joins if it passes.
    fn admit(&self, ticket: &WireTicket) -> Result<(), &'static str> {
        let raw = hex::decode(ticket.signature.trim_start_matches("0x"))
            .map_err(|_| "a signature that is not hex")?;
        let signature =
            G1::read(&mut raw.as_slice()).map_err(|_| "a signature that is no point")?;
        let t = ReadTicket {
            claim: ReadClaim {
                server: self.manifest.server,
                serial: ticket.serial,
            },
            signature,
        };
        t.verify(&self.key)
            .map_err(|_| "no ticket for this server")?;
        if !self
            .spent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(ticket.serial)
        {
            return Err("a spent ticket");
        }
        Ok(())
    }
}

async fn read(
    State(s): State<Arc<Server>>,
    Json(req): Json<ReadRequest>,
) -> Result<Json<ReadResponse>, (StatusCode, String)> {
    let started = Instant::now();
    let verdict = s.admit(&req.ticket);
    let check_us = started.elapsed().as_micros();
    let mut entry = json!({
        "serial": req.ticket.serial,
        "queryBytes": req.query.len().saturating_sub(2) / 2,
        "ticketCheckMicros": check_us,
    });
    let out = match verdict {
        Err(why) => {
            entry["refused"] = json!(why);
            Err((StatusCode::PAYMENT_REQUIRED, why.to_owned()))
        }
        Ok(()) => match hex_to_words(&req.query).filter(|q| q.len() == s.table.db.cols) {
            None => {
                entry["refused"] = json!("a malformed query");
                Err((StatusCode::BAD_REQUEST, "a malformed query".to_owned()))
            }
            Some(q) => {
                let t = Instant::now();
                let answer = s.table.db.answer(&q);
                entry["answerMicros"] = json!(t.elapsed().as_micros());
                entry["bytesScanned"] = json!(s.table.db.data.len());
                let answer = words_to_hex(&answer);
                entry["answerBytes"] = json!(answer.len().saturating_sub(2) / 2);
                Ok(Json(ReadResponse { answer }))
            }
        },
    };
    s.log
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(entry);
    out
}
