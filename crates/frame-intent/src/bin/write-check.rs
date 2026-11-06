//! `write-check`: the verdict of experiment 58's exact list of writes on one frame transaction.
//!
//! ```text
//! write-check --raw <0x06...> --layouts <registry.json> --template <name> [--param k=v ...]
//!             (--rpc <url> | --sim <simulation.json> [--fee-recipient <address>])
//!             [--rules f3079a0|master] [--sign]
//! ```
//!
//! - `--rpc` simulates through `ethrex_simulateFrameTransaction` (it must return `writes`, as the
//!   local chain's patched ethrex does), takes the fee recipient from the latest block, and checks
//!   each layout the intent uses against the chain: the slot's stored value must equal its getter.
//! - `--sim` reads a saved simulation result instead; the fee recipient defaults to the zero address,
//!   the local chain's.
//! - `--sign` (on a pass) replaces the transaction's final `assert(Q)` frame with the compiled Q,
//!   makes the body one atomic batch, and signs every entry again with the key in `SIGNER_KEY`.
//!
//! It prints one JSON object: the verdict, the intent, and on a pass both encodings of Q.

use std::collections::HashMap;

use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, bail};
use kohaku_frame_intent::{
    Registry, Simulation, check,
    encode::{assert_named, assert_writes, sign_batch},
    expand,
    writes::Field,
};
use kohaku_frame_kit::{Eip8250, FrameSigner, FrameTx};
use serde_json::{Value, json};

struct Args {
    rpc: Option<String>,
    sim: Option<String>,
    raw: String,
    layouts: String,
    template: String,
    params: HashMap<String, String>,
    fee_recipient: Option<Address>,
    rules: Eip8250,
    sign: bool,
}

fn args() -> anyhow::Result<Args> {
    let mut it = std::env::args().skip(1);
    let (mut rpc, mut sim, mut raw, mut layouts, mut template, mut fee_recipient, mut sign) =
        (None, None, None, None, None, None, false);
    let mut rules = Eip8250::F3079a0;
    let mut params = HashMap::new();
    while let Some(a) = it.next() {
        let mut val = || it.next().with_context(|| format!("{a} needs a value"));
        match a.as_str() {
            "--rpc" => rpc = Some(val()?),
            "--sim" => sim = Some(val()?),
            "--raw" => raw = Some(val()?),
            "--raw-file" => raw = Some(std::fs::read_to_string(val()?)?.trim().to_owned()),
            "--layouts" => layouts = Some(val()?),
            "--template" => template = Some(val()?),
            "--fee-recipient" => fee_recipient = Some(val()?.parse()?),
            "--rules" => {
                rules = match val()?.as_str() {
                    "f3079a0" => Eip8250::F3079a0,
                    "master" => Eip8250::Master,
                    r => bail!("--rules: {r}: f3079a0 or master"),
                }
            }
            "--param" => {
                let kv = val()?;
                let (k, v) = kv
                    .split_once('=')
                    .with_context(|| format!("--param {kv}: k=v"))?;
                params.insert(k.to_owned(), v.to_owned());
            }
            "--sign" => sign = true,
            "-h" | "--help" => {
                println!(
                    "{}",
                    include_str!("write-check.rs")
                        .lines()
                        .take_while(|l| l.starts_with("//!"))
                        .map(|l| l.trim_start_matches("//!").trim_start_matches(' '))
                        .collect::<Vec<_>>()
                        .join("\n")
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument {other}"),
        }
    }
    if rpc.is_some() == sim.is_some() {
        bail!("give exactly one of --rpc and --sim");
    }
    Ok(Args {
        rpc,
        sim,
        raw: raw.context("--raw or --raw-file is required")?,
        layouts: layouts.context("--layouts is required")?,
        template: template.context("--template is required")?,
        params,
        fee_recipient,
        rules,
        sign,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let a = args()?;
    let raw: Bytes = a.raw.parse().context("--raw")?;
    let tx = FrameTx::decode_with(&raw, a.rules)
        .map_err(|e| anyhow::anyhow!("decoding the transaction: {e:?}"))?;
    let registry: Registry =
        serde_json::from_str(&std::fs::read_to_string(&a.layouts)?).context("--layouts")?;
    let intent = expand(&a.template, &a.params, tx.sender, &registry)?;

    let mut layout_checks = Vec::new();
    let (sim, fee_recipient) = if let Some(url) = &a.rpc {
        let provider = ProviderBuilder::new().connect_http(url.parse()?);
        let sim: Simulation = provider
            .raw_request(
                "ethrex_simulateFrameTransaction".into(),
                (raw.clone(), "latest"),
            )
            .await?;
        let block: Value = provider
            .raw_request("eth_getBlockByNumber".into(), ("latest", false))
            .await?;
        let miner: Address = block["miner"]
            .as_str()
            .context("latest block has no miner")?
            .parse()?;
        // Each layout the intent uses, against the chain.
        for al in &intent.allowed {
            let (Field::Storage(slot), Some((target, call))) = (al.field, &al.getter) else {
                continue;
            };
            let stored: U256 = provider.get_storage_at(al.address, slot.into()).await?;
            let req = alloy::rpc::types::TransactionRequest::default()
                .to(*target)
                .input(call.clone().into());
            let got = provider.call(req).await?;
            let read = U256::from_be_slice(got.get(..32).unwrap_or_default());
            if stored != read {
                bail!(
                    "layout: {} slot {slot} holds {stored}, its getter says {read}: the registry is wrong for {}",
                    al.address,
                    al.address
                );
            }
            layout_checks.push(json!({ "address": al.address, "slot": slot, "value": stored }));
        }
        (sim, a.fee_recipient.unwrap_or(miner))
    } else {
        let path = a.sim.as_deref().unwrap_or_default();
        let v: Value = serde_json::from_str(&std::fs::read_to_string(path)?)
            .with_context(|| format!("--sim {path}"))?;
        // A saved JSON-RPC response or the bare result.
        let sim: Simulation = serde_json::from_value(v.get("result").cloned().unwrap_or(v))?;
        (sim, a.fee_recipient.unwrap_or(Address::ZERO))
    };

    let verdict = check(&tx, &sim, &intent, fee_recipient);
    let payer = sim.payer.unwrap_or(tx.sender);
    let writes_q = assert_writes(&verdict, payer);
    let named_q = assert_named(&verdict, &intent);
    let mut out = json!({
        "transaction": tx.hash(),
        "sender": tx.sender,
        "feeRecipient": fee_recipient,
        "intent": intent,
        "layoutChecks": layout_checks,
        "verdict": verdict,
        "q": { "assertWrites": writes_q, "assertNamed": named_q },
    });
    if a.sign {
        let Some(q) = &named_q else {
            bail!("--sign: the verdict is not a pass, so nothing is signed")
        };
        let key: PrivateKeySigner = std::env::var("SIGNER_KEY")
            .context("--sign needs SIGNER_KEY")?
            .parse()?;
        let signed = sign_batch(&tx, q, &FrameSigner::Secp256k1(key))?;
        out["signed"] = json!({ "raw": signed.encode(), "hash": signed.hash() });
    }
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
