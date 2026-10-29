//! Runner step "check", on the owner's device: the owner finds its latest opening in the vault,
//! assembles it, and checks it against the commitment at its leaf.
//!
//! ```text
//! SEED_FILE=... VAULT=0x... O=0 J=0 RPC_URL=... \
//!   cargo run --release -p kohaku-frame-exit --example exit_check
//! ```
//!
//! Prints the verdict, where the note sits and the vault's mode; never the nullifier, the secret
//! or a part. A garbage opening newer than the owner's last good one exits with code 2, and the
//! line names each one's kind; no opening for the key at all exits with code 3.

mod common;

use common::{chain, fail, load_seed, number, print, vault};
use kohaku_frame_exit::{
    note::note_secret,
    opening_key,
    vault::{latest_note, mode},
};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let seed = load_seed()?;
    let vault = vault()?;
    let o: u32 = number("o", 0)?;
    let j: u32 = number("j", 0)?;
    let chain = chain()?;
    let key = opening_key(&seed, vault, o)?;
    let found = latest_note(&chain, vault, &key, &note_secret(&seed, vault, j)).await?;
    let garbage: Vec<_> = found
        .garbage
        .iter()
        .map(|(update, g)| json!({ "update": update, "kind": g.kind(), "reason": g.to_string() }))
        .collect();
    let mut line = json!({
        "step": "check",
        "vault": vault,
        "o": o,
        "j": j,
        "mode": mode(&chain, vault).await?,
        "garbage": garbage,
    });
    if let Some((note, opening)) = &found.note {
        line["verdict"] = json!("ok");
        line["leaf"] = json!(opening.leaf);
        line["update"] = json!(opening.update);
        line["commitment"] = json!(alloy::primitives::B256::from(note.commitment()));
    }
    match (&found.note, found.garbage.first()) {
        (_, Some(g)) => {
            line["verdict"] = json!("garbage");
            line["kind"] = json!(g.1.kind());
            fail(&line, 2)
        }
        (None, None) => {
            line["verdict"] = json!("none");
            fail(&line, 3)
        }
        (Some(_), None) => print(&line),
    }
    Ok(())
}
