//! Runner step "redeem", on the owner's device: the owner redeems its latest note alone. The
//! redemption is proved here, over experiment 01's circuit, against the vault's latest root; the
//! vault is its sender and pays its gas out of the note's fee; it goes to the node at
//! `SEND_RPC_URL` alone.
//!
//! ```text
//! SEED_FILE=... VAULT=0x... SALT=0x... O=0 J=0 SEQ=0 SEND_RPC_URL=... RPC_URL=... \
//!   cargo run --release -p kohaku-frame-exit --example exit_redeem
//! ```
//!
//! `SALT` is the vault's EIP-8272 salt, checked against its `sourceId()`. `SEQ` is the note's
//! nonce sequence, 0 to 2: a redemption before escape mode is mined with its `withdraw` reverted
//! (`PaidNothing`), and the next sequence may try again. The line holds the transaction's hash,
//! the nullifier hash it spends and the Outcome (`Paid`, `PaidNothing` or `Refused`); never the
//! note, the opening or a key. It exits with code 2 on a garbage opening, 3 with none, and 1
//! when the node refuses.

mod common;

use alloy::{primitives::B256, providers::Provider};
use anyhow::{Context as _, ensure};
use common::{chain, fail, load_seed, node, number, print, required, vault};
use kohaku_frame_exit::{
    note::note_secret,
    opening_key, recipient,
    vault::{
        Outcome, all_leaves, last_root, latest_note, mode, pool, redeem, redemption, root_slot,
    },
};
use kohaku_frame_pool::{chain::WALLET_FEES, withdrawal::WithdrawalOpts};
use serde_json::json;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let seed = load_seed()?;
    let vault = vault()?;
    let salt: B256 = required("salt")?.parse()?;
    let o: u32 = number("o", 0)?;
    let j: u32 = number("j", 0)?;
    let sequence: u64 = number("seq", 0)?;
    let chain = chain()?;
    let sender = node()?;

    let mut line = json!({ "step": "redeem", "vault": vault, "o": o, "j": j, "seq": sequence });
    let key = opening_key(&seed, vault, o)?;
    let found = latest_note(&chain, vault, &key, &note_secret(&seed, vault, j)).await?;
    if let Some((update, g)) = found.garbage.first() {
        line["verdict"] = json!("garbage");
        line["kind"] = json!(g.kind());
        line["update"] = json!(update);
        fail(&line, 2);
    }
    let Some((note, opening)) = found.note else {
        line["verdict"] = json!("none");
        fail(&line, 3);
    };
    line["verdict"] = json!("ok");
    line["leaf"] = json!(opening.leaf);
    line["update"] = json!(opening.update);

    let pool = pool(&chain, vault, salt).await?;
    let leaves = all_leaves(&chain, vault).await?;
    let root = last_root(&chain, vault).await?;
    let opts = WithdrawalOpts {
        root_slot: Some(root_slot(&chain, vault, root).await?),
        fees: WALLET_FEES,
        ..WithdrawalOpts::new(chain.get_chain_id().await?)
    };
    let to = recipient(&seed, vault, o)?;
    let (tx, proof) = redemption(&pool, &note, &leaves, to, &opts, sequence, &mut rand::rng())?;
    ensure!(
        proof.inputs.root == root,
        "the tree moved while proving: run again"
    );
    line["recipient"] = json!(to);
    line["nullifierHash"] = json!(proof.inputs.nullifier_hash);
    line["fee"] = json!(proof.inputs.fee.to_string());
    line["leaves"] = json!(leaves.len());
    line["hash"] = json!(tx.hash());
    line["modeBefore"] = json!(mode(&chain, vault).await?);
    let outcome = redeem(&sender, &chain, &tx)
        .await
        .context("awaiting the redemption")?;
    line["modeAfter"] = json!(mode(&chain, vault).await?);
    match outcome {
        Outcome::Paid { block, .. } => {
            line["outcome"] = json!("Paid");
            line["block"] = json!(block);
            line["balance"] = json!(chain.get_balance(to).await?.to_string());
        }
        Outcome::PaidNothing { block, .. } => {
            line["outcome"] = json!("PaidNothing");
            line["block"] = json!(block);
        }
        Outcome::Refused(reason) => {
            line["outcome"] = json!("Refused");
            line["node"] = json!(reason);
            fail(&line, 1);
        }
    }
    print(&line);
    Ok(())
}
