//! `exp-frames` experiment 38: every shape the request names, reviewed as a device would.
//!
//! - experiment 27's cases, both EIP-8250 revisions, as the owner's entry, from the transaction
//!   and, for the accepted ones, from the typed data alone;
//! - experiment 28's twelve batches, as the user's entry;
//! - experiment 12's session grant, both redemptions and the revocation, experiment 02's deploy
//!   frame and its follow-up, and experiment 12's setup, which deploys an account for someone else.
//!
//! Each is rendered three times: with every descriptor, without the account descriptors (and the
//! wallet's account list), and with none at all, the transaction alone.
//!
//! ```bash
//! RECORD=record.json cargo run -p kohaku-frame-display --example clear_signing
//! ```

use std::{fs, path::Path};

use alloy::primitives::{B256, hex};
use anyhow::{Context, Result, bail};
use kohaku_frame_display::{
    Registry, Review, Rules, render, render_typed,
    typed::{execution_typed_data, parse_execution},
};
use kohaku_frame_kit::{FrameTx, digest::execution_digest, json::FrameTxJson};
use serde::Deserialize;
use serde_json::{Value, json};

const CHAIN: &[(&str, &str, &str)] = &[
    (
        "0x32eb0bc5",
        "experiment 28, B: approve and swap, atomic, self-paid (wallet.ts)",
        "atomic batch",
    ),
    (
        "0x9688c1f8",
        "experiment 28, C: approve and swap, atomic, sponsored (wallet.ts)",
        "sponsored atomic batch",
    ),
    (
        "0x78564f0a",
        "experiment 28, D: three independent calls (wallet.ts)",
        "independent calls",
    ),
    (
        "0x3fc65c1d",
        "experiment 28, E: approve and swap, atomic, the swap fails (wallet.ts)",
        "atomic batch",
    ),
    (
        "0x9489899e",
        "experiment 28, rails r1 self-paid (wallet.ts)",
        "atomic batch",
    ),
    (
        "0x57135ff7",
        "experiment 28, rails r1 sponsored (wallet.ts)",
        "sponsored atomic batch",
    ),
    (
        "0x644424fe",
        "experiment 28, rails r2 self-paid (wallet.ts)",
        "atomic batch",
    ),
    (
        "0xd3c04b29",
        "experiment 28, rails r2 sponsored (wallet.ts)",
        "sponsored atomic batch",
    ),
    ("0x28885722", "experiment 28, B (kohaku-rs)", "atomic batch"),
    (
        "0x0cd8150d",
        "experiment 28, C (kohaku-rs)",
        "sponsored atomic batch",
    ),
    (
        "0x6c5d0038",
        "experiment 28, D (kohaku-rs)",
        "independent calls",
    ),
    ("0xf00c9f2c", "experiment 28, E (kohaku-rs)", "atomic batch"),
    (
        "0x3650463d",
        "experiment 12, 1: the owner grants a session",
        "session grant",
    ),
    (
        "0x1d381c94",
        "experiment 12, A: the session key pays the merchant",
        "session redemption",
    ),
    (
        "0x84d4a91f",
        "experiment 12, B: two payments in one session transaction",
        "session redemption",
    ),
    (
        "0x822694c8",
        "experiment 12, D: the owner revokes the session",
        "session revocation",
    ),
    (
        "0x9882637a",
        "experiment 02, 1b: deploy the account at the sender, verify, send",
        "deploy frame",
    ),
    (
        "0x68fc041a",
        "experiment 02: the follow-up, no deploy frame",
        "after deployment",
    ),
    (
        "0x922d2f82",
        "experiment 12, setup: the funder deploys the session account",
        "deploy for another",
    ),
];

fn shape_of_case(name: &str) -> &'static str {
    match name {
        "sponsored-transfer" | "payer-replaced" | "target-written-out" => "sponsored transfer",
        "atomic-approve-swap" => "atomic batch",
        "deploy-first" => "deploy frame",
        "with-expiry" => "expiry",
        "keyed-nonces" | "legacy-nonce-7" | "key-zero" => "nonce keys",
        "value-and-default" => "value and DEFAULT frame",
        "blobs" => "blobs",
        "many-frames" => "many frames",
        _ => "refused by the account",
    }
}

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
}

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
}

fn chain_tx(prefix: &str) -> Result<(String, FrameTx)> {
    for e in fs::read_dir(fixtures().join("chain"))? {
        let path = e?.path();
        let file = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if file.starts_with(prefix) {
            let f: Fixture = serde_json::from_slice(&fs::read(&path)?)?;
            return Ok((
                file.trim_end_matches(".json").to_owned(),
                FrameTx::try_from(&f.tx)?,
            ));
        }
    }
    bail!("no fixture {prefix}")
}

struct Case {
    name: String,
    expect: String,
    raw: Vec<u8>,
}

fn cases(file: &str) -> Result<Vec<Case>> {
    let text = fs::read_to_string(fixtures().join("exp27").join(file))?;
    text.lines()
        .filter(|l| l.starts_with("case "))
        .map(|l| {
            let mut w = l.split_whitespace().skip(1);
            let (name, expect, raw) = (w.next(), w.next(), w.next());
            let (Some(name), Some(expect), Some(raw)) = (name, expect, raw) else {
                bail!("bad case line")
            };
            Ok(Case {
                name: name.to_owned(),
                expect: expect.to_owned(),
                raw: hex::decode(raw)?,
            })
        })
        .collect()
}

/// The full registry, the one without account descriptors, and an empty one.
fn registries() -> Result<[(&'static str, Registry); 3]> {
    let full = Registry::load(&fixtures().join("descriptors"))?;
    let mut no_accounts = full.clone();
    no_accounts.accounts.clear();
    no_accounts.wallet.accounts.clear();
    Ok([
        ("full", full),
        ("withoutAccountDescriptors", no_accounts),
        ("transactionAlone", Registry::default()),
    ])
}

fn summary(r: &Review) -> Value {
    json!({ "intent": r.intent, "gaps": r.gaps, "blind": r.blind().count() })
}

fn print(title: &str, r: &Review, others: &[(&str, Review)]) {
    println!("== {title}");
    print!("{}", r.to_text());
    for (name, o) in others {
        let kinds: Vec<String> = o
            .gaps
            .iter()
            .map(|g| format!("{:?}{}", g.kind, if g.blind { " (blind)" } else { "" }))
            .collect();
        println!(
            "  {name}: {} blind; gaps [{}]",
            o.blind().count(),
            kinds.join(", ")
        );
    }
    println!();
}

fn record_tx(
    id: &str,
    label: &str,
    shape: &str,
    tx: &FrameTx,
    rules: Rules,
    regs: &[(&str, Registry); 3],
) -> Result<Value> {
    let full = render(tx, 0, &regs[0].1, rules)?;
    let others = [
        (regs[1].0, render(tx, 0, &regs[1].1, rules)?),
        (regs[2].0, render(tx, 0, &regs[2].1, rules)?),
    ];
    print(&format!("{id}: {label}"), &full, &others);
    Ok(json!({
        "id": id,
        "label": label,
        "shape": shape,
        "input": "transaction",
        "eip8250": format!("{:?}", rules.eip8250),
        "txHash": tx.hash(),
        "sigHash": tx.sig_hash(),
        "executionDigest": execution_digest(tx),
        "entry": 0,
        "review": full,
        "without": { others[0].0: summary(&others[0].1), others[1].0: summary(&others[1].1) },
    }))
}

fn record_typed(
    id: &str,
    shape: &str,
    tx: &FrameTx,
    rules: Rules,
    regs: &[(&str, Registry); 3],
) -> Result<Value> {
    let typed = execution_typed_data(tx);
    let message = parse_execution(&typed)?;
    let digest: B256 = execution_digest(tx);
    if message.digest != digest {
        bail!(
            "{id}: the typed data's digest {} is not E {digest}",
            message.digest
        );
    }
    let full = render_typed(&message, &regs[0].1, rules);
    let others = [
        (regs[1].0, render_typed(&message, &regs[1].1, rules)),
        (regs[2].0, render_typed(&message, &regs[2].1, rules)),
    ];
    print(&format!("{id} (typed data alone)"), &full, &others);
    Ok(json!({
        "id": format!("{id}/typed"),
        "shape": shape,
        "input": "typed data",
        "eip8250": format!("{:?}", rules.eip8250),
        "executionDigest": digest,
        "typedData": typed,
        "review": full,
        "without": { others[0].0: summary(&others[0].1), others[1].0: summary(&others[1].1) },
    }))
}

fn main() -> Result<()> {
    let regs = registries()?;
    let mut renders = Vec::new();

    for (file, rules, set) in [
        (
            "cases-eip8250-f3079a0.txt",
            Rules::HEGOTA_TESTNET,
            "exp27-f3079a0",
        ),
        (
            "cases-eip8250-master.txt",
            Rules::EIP8250_MASTER,
            "exp27-master",
        ),
    ] {
        for c in cases(file)? {
            let tx = FrameTx::decode_with(&c.raw, rules.eip8250)
                .with_context(|| format!("{set}/{}", c.name))?;
            let id = format!("{set}/{}", c.name);
            let shape = shape_of_case(&c.name);
            let mut r = record_tx(
                &id,
                &format!("experiment 27, case {}, expected {}", c.name, c.expect),
                shape,
                &tx,
                rules,
                &regs,
            )?;
            r["expected"] = json!(c.expect);
            renders.push(r);
            if c.expect == "valid" {
                renders.push(record_typed(&id, shape, &tx, rules, &regs)?);
            }
        }
    }
    // The same bytes under the other revision: key 0 at master is the account nonce at f3079a0.
    let zero = cases("cases-eip8250-master.txt")?
        .into_iter()
        .find(|c| c.name == "key-zero")
        .context("key-zero")?;
    let tx = FrameTx::decode_with(&zero.raw, Rules::HEGOTA_TESTNET.eip8250)?;
    let id = "exp27-master/key-zero, read under f3079a0";
    renders.push(record_tx(
        id,
        "experiment 27's master key-zero case, its bytes read under EIP-8250 at f3079a09e8",
        "nonce keys",
        &tx,
        Rules::HEGOTA_TESTNET,
        &regs,
    )?);
    renders.push(record_typed(
        id,
        "nonce keys",
        &tx,
        Rules::HEGOTA_TESTNET,
        &regs,
    )?);

    for (prefix, label, shape) in CHAIN {
        let (hash, tx) = chain_tx(prefix)?;
        if tx.hash().to_string() != hash {
            bail!(
                "{prefix}: the fixture's transaction hashes to {}",
                tx.hash()
            );
        }
        renders.push(record_tx(
            &format!("chain/{prefix}"),
            label,
            shape,
            &tx,
            Rules::HEGOTA_TESTNET,
            &regs,
        )?);
    }

    let record = json!({
        "eip8250": { "F3079a0": "f3079a09e8c606afcb0e5e1a309ff228b88dc067", "Master": "1a086d5c67cdcf3a134cc571eb4bb4b9bed6fb02" },
        "descriptors": regs[0].1.files.iter().map(|(p, h)| json!({ "path": p, "keccak256": h })).collect::<Vec<_>>(),
        "renders": renders,
    });
    if let Ok(path) = std::env::var("RECORD") {
        fs::write(&path, serde_json::to_string_pretty(&record)? + "\n")?;
        println!("wrote {path}");
    }
    Ok(())
}
