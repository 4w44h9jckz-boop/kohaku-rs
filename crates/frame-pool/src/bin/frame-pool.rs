//! JSON helper for driving a frame-native pool from another language.
//!
//! ```text
//! frame-pool note [<hex>]    -> { note, commitment, nullifierHash }
//! frame-pool zeros           -> [ zeros(0) .. zeros(20) ]
//! frame-pool prove < req     -> FramePoolProof
//! ```
//!
//! `note` draws a fresh note, or describes the one given. `prove` reads
//! `{ note, leaves, recipient, relayer, fee, refund }` on standard input, where `note` is the
//! 62-byte preimage `nullifier || secret` in hex and `leaves` are the pool's commitments in
//! insertion order. Notes are secrets: the caller keeps them.

use std::io::Read;

use alloy::primitives::{Address, B256, U256};
use anyhow::{Context, bail};
use kohaku_frame_pool::{prove, zeros};
use kohaku_tornadocash::{Field, Note, Nullifier, Payer, Secret};
use rand::RngExt;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProveRequest {
    note: String,
    leaves: Vec<B256>,
    recipient: Address,
    relayer: Address,
    fee: U256,
    refund: U256,
}

fn parse_note(hex_note: &str) -> anyhow::Result<Note> {
    let bytes = hex::decode(hex_note.trim_start_matches("0x")).context("note is not hex")?;
    if bytes.len() != 62 {
        bail!(
            "note must be 62 bytes (nullifier || secret), got {}",
            bytes.len()
        );
    }
    let nullifier = Nullifier::try_from(&bytes[..31])?;
    let secret = Secret::try_from(&bytes[31..])?;
    Ok(Note::new(nullifier, secret))
}

fn describe(note: &Note) -> Value {
    json!({
        "note": format!("0x{}", hex::encode(note.preimage())),
        "commitment": B256::from(note.commitment()),
        "nullifierHash": B256::from(note.nullifier_hash()),
    })
}

fn main() -> anyhow::Result<()> {
    let out = match std::env::args().nth(1).as_deref() {
        Some("note") => match std::env::args().nth(2) {
            Some(hex_note) => describe(&parse_note(&hex_note)?),
            None => describe(&rand::rng().random::<Note>()),
        },
        Some("zeros") => json!(zeros().iter().map(|z| B256::from(*z)).collect::<Vec<_>>()),
        Some("prove") => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            let req: ProveRequest = serde_json::from_str(&input)?;
            let leaves = req
                .leaves
                .iter()
                .map(|l| Field::try_from(*l).map_err(|e| anyhow::anyhow!("leaf {l}: {e}")))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let payer = Payer {
                address: req.relayer,
                fee: req.fee,
                refund: req.refund,
            };
            let proof = prove(
                parse_note(&req.note)?,
                &leaves,
                req.recipient,
                payer,
                &mut rand::rng(),
            )?;
            serde_json::to_value(proof)?
        }
        _ => bail!("usage: frame-pool <note [hex] | zeros | prove < request.json>"),
    };
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
