//! The read server of experiment 37, with branches in its table and a signature on each answer.
//!
//! ```text
//! GET  /manifest   identity and signing address, snapshot block and state root, table shape,
//!                  seed of A, hint root, the committee's key
//! GET  /hint       H = D A, little-endian u32s, once per reader
//! GET  /top        the trie's top: the nodes above the split, once per reader
//! POST /read       {"query", "ticket": {"serial", "signature"}}
//!                  -> {"answer", "signature"}: D q, and the server's signature on the statement
//! GET  /log        what the server saw of each request
//! ```
//!
//! The ticket is checked first, as in experiment 37. The server signs only what it computed: it
//! cannot know which bucket it answered, so it signs the query and the answer, under the
//! commitment to its snapshot and hint ([`crate::statement`]).

use std::{
    collections::HashSet,
    sync::{Arc, Mutex, PoisonError},
    time::Instant,
};

use alloy::{
    primitives::{Address, B256, Bytes},
    signers::{SignerSync, local::PrivateKeySigner},
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use commonware_codec::{Encode, ReadExt};
use commonware_cryptography::bls12381::primitives::group::{G1, G2};
use kohaku_ticket_read::{
    ReadClaim, ReadTicket, pir,
    server::{ReadRequest, WireTicket, hex_to_words, words_to_hex},
    ticket::READ_NAMESPACE,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{statement, table::CheckedTable};

/// What a reader needs to query the server and check its answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    /// The identity a read ticket names: `signer`, left-padded.
    pub server: B256,
    pub signer: Address,
    /// The committee's key, Commonware's compressed G2.
    pub key: String,
    pub namespace: String,
    pub block: u64,
    pub state_root: B256,
    pub seed: B256,
    pub salt: B256,
    pub rows: usize,
    pub cols: usize,
    pub capacity: usize,
    pub record: usize,
    pub split: usize,
    pub entries: usize,
    pub hint_root: B256,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedResponse {
    pub answer: String,
    /// 65 bytes, `r || s || v`.
    pub signature: String,
}

pub struct Server {
    pub manifest: Manifest,
    key: G2,
    signer: PrivateKeySigner,
    commitment: B256,
    table: CheckedTable,
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

impl Server {
    /// A server for `table`, a snapshot of `block` under `state_root`, with the committee's
    /// `key`, signing with `signer`, and the seed of its public matrix.
    #[must_use]
    pub fn new(
        table: CheckedTable,
        key: G2,
        signer: PrivateKeySigner,
        seed: B256,
        block: u64,
        state_root: B256,
    ) -> Self {
        let a = pir::public_matrix(seed.0, table.db.cols);
        let hint = table.db.hint(&a);
        let manifest = Manifest {
            server: statement::identity(signer.address()),
            signer: signer.address(),
            key: format!("0x{}", hex::encode(key.encode())),
            namespace: String::from_utf8_lossy(READ_NAMESPACE).into_owned(),
            block,
            state_root,
            seed,
            salt: table.salt,
            rows: table.db.rows,
            cols: table.db.cols,
            capacity: table.capacity,
            record: table.record,
            split: table.split,
            entries: table.entries,
            hint_root: statement::hint_root(&hint, pir::N),
        };
        Self {
            commitment: statement::commitment(&manifest),
            manifest,
            key,
            signer,
            table,
            hint: statement::words(&hint),
            spent: Mutex::new(HashSet::new()),
            log: Mutex::new(Vec::new()),
        }
    }

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
            .route(
                "/top",
                get(|State(s): State<Arc<Self>>| async move {
                    Json::<Vec<Bytes>>(s.table.top.clone())
                }),
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

    /// The signature on `query`'s `answer`, as the server sends it.
    ///
    /// # Panics
    ///
    /// Never: a local key signs any digest.
    #[must_use]
    pub fn sign(&self, query: &[u32], answer: &[u32]) -> String {
        let digest = statement::digest(self.commitment, query, answer);
        let sig = self
            .signer
            .sign_hash_sync(&digest)
            .expect("a local key signs any digest");
        format!("0x{}", hex::encode(sig.as_bytes()))
    }

    fn admit(&self, ticket: &WireTicket) -> Result<(), &'static str> {
        let raw = hex::decode(ticket.signature.trim_start_matches("0x"))
            .map_err(|_| "a signature that is not hex")?;
        let signature =
            G1::read(&mut raw.as_slice()).map_err(|_| "a signature that is no point")?;
        ReadTicket {
            claim: ReadClaim {
                server: self.manifest.server,
                serial: ticket.serial,
            },
            signature,
        }
        .verify(&self.key)
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
) -> Result<Json<SignedResponse>, (StatusCode, String)> {
    let started = Instant::now();
    let verdict = s.admit(&req.ticket);
    let mut entry = json!({
        "serial": req.ticket.serial,
        "queryBytes": req.query.len().saturating_sub(2) / 2,
        "ticketCheckMicros": started.elapsed().as_micros(),
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
                let t = Instant::now();
                let signature = s.sign(&q, &answer);
                entry["signMicros"] = json!(t.elapsed().as_micros());
                entry["bytesScanned"] = json!(s.table.db.data.len());
                let answer = words_to_hex(&answer);
                entry["answerBytes"] = json!(answer.len().saturating_sub(2) / 2);
                Ok(Json(SignedResponse { answer, signature }))
            }
        },
    };
    s.log
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(entry);
    out
}
