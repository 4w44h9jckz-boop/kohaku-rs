//! Runner step "receive", on the owner's device: the receiving address of the owner's j-th note in
//! a vault, under opening key `o`, written for the note's holder.
//!
//! ```text
//! SEED_FILE=... VAULT=0x... O=0 J=0 RECEIVE_FILE=receive.json \
//!   cargo run --release -p kohaku-frame-exit --example exit_receive
//! ```
//!
//! The address is the opening key and the secret's point `B(s)`. It opens and spends nothing, but
//! the intent seals it so that it never appears on chain, so it goes to `RECEIVE_FILE` (mode
//! 0600), which the owner hands the holder off the chain, and the line printed holds its digest
//! only. Every flag may be given as `--name value` instead.

mod common;

use std::{fs, io::Write, os::unix::fs::OpenOptionsExt};

use common::{digest, hex, load_seed, number, print, required, vault};
use kohaku_frame_exit::{note::receive, recipient};
use serde_json::json;

fn main() -> anyhow::Result<()> {
    let seed = load_seed()?;
    let vault = vault()?;
    let o: u32 = number("o", 0)?;
    let j: u32 = number("j", 0)?;
    let address = receive(&seed, vault, o, j)?;
    let out = json!({
        "vault": vault,
        "openingKey": hex(&address.key),
        "secretPoint": hex(&address.secret_point),
    })
    .to_string();
    let path = required("receive-file")?;
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?
        .write_all(out.as_bytes())?;
    print(&json!({
        "step": "receive",
        "vault": vault,
        "o": o,
        "j": j,
        "address": digest(&[address.key.as_slice(), &address.secret_point].concat()),
        "recipient": recipient(&seed, vault, o)?,
    }));
    Ok(())
}
