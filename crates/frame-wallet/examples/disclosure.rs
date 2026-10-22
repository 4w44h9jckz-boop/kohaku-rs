//! The crowd behind a statement, shown before the wallet proves it, from mainnet data alone:
//! `exp-frames` experiment 35, in Rust.
//!
//! ```text
//! cargo run --release -p kohaku-frame-wallet --example disclosure [snapshot block]
//! ```
//!
//! `MAINNET_RPC_URL` defaults to Tenderly's public gateway and `IPFS_GATEWAY` to Pinata's; the
//! snapshot defaults to the latest finalized block. At experiment 35's snapshot, block
//! 26,231,840, every count must equal that experiment's `results.md`.

use std::env;

use alloy::{
    eips::BlockNumberOrTag,
    primitives::{Address, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use anyhow::Context;
use kohaku_frame_wallet::disclosure::{
    AssociationSet, Crowd, TORNADO_ETH, abi::Deposited, deposits_before, latest_association_root,
    unspent_at_least,
};

const ENTRYPOINT: Address = address!("0x6818809eefce719e480a7526d76bd3e561526b46");
const PP_ETH_POOL: Address = address!("0xf241d57c6debae225c0f2e6ea1529373c9a9c9fb");
/// The first block with the Privacy Pools ETH pool's code.
const PP_DEPLOYED: u64 = 22_153_714;
const LABELS: [&str; 4] = ["0.1 ETH", "1 ETH", "10 ETH", "100 ETH"];
const DATES: [(&str, u64); 4] = [
    ("2021-01-01", 1_609_459_200),
    ("2023-01-01", 1_672_531_200),
    ("2025-01-01", 1_735_689_600),
    ("2026-01-01", 1_767_225_600),
];

fn show(statement: &str, count: u64) {
    println!("  {statement}: {}", Crowd::of(count).warning(count));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("MAINNET_RPC_URL")
        .unwrap_or_else(|_| "https://mainnet.gateway.tenderly.co".to_owned());
    let gateway = env::var("IPFS_GATEWAY")
        .unwrap_or_else(|_| "https://gateway.pinata.cloud/ipfs/".to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let snapshot = match env::args().nth(1) {
        Some(b) => b.parse()?,
        None => {
            provider
                .get_block_by_number(BlockNumberOrTag::Finalized)
                .await?
                .context("no finalized block")?
                .header
                .number
        }
    };
    println!("snapshot: block {snapshot}");

    println!("1. \"I deposited into this pool before date D\"");
    for (date, t) in DATES {
        for (pool, label) in TORNADO_ETH.iter().zip(LABELS) {
            let (block, n) = deposits_before(&provider, pool.address, t, snapshot).await?;
            show(&format!("Tornado {label} before {date} (block {block})"), n);
        }
    }

    println!("2. \"I hold an unspent note worth at least T\"");
    for (pool, label) in TORNADO_ETH.iter().zip(LABELS) {
        let n = unspent_at_least(&provider, &TORNADO_ETH, pool.denomination, snapshot).await?;
        show(&format!("a Tornado note of at least {label}"), n);
    }

    println!("3. \"My deposit is in the association set\"");
    let (root, cid, at) =
        latest_association_root(&provider, ENTRYPOINT, snapshot - 20_000, snapshot)
            .await?
            .context("no association-set root in the last 20,000 blocks")?;
    let export = reqwest::get(format!("{gateway}{cid}"))
        .await?
        .error_for_status()?
        .bytes()
        .await?;
    let set = AssociationSet::verify(&export, root)?;
    println!(
        "  root {root:#x} of block {at}, CID {cid}: the tree hashes to it, {} levels",
        set.levels.len()
    );
    show(
        "a deposit in the association set",
        set.labels().len() as u64,
    );
    let mut deposits = vec![];
    for from in (PP_DEPLOYED..=snapshot).step_by(50_000) {
        let to = (from + 49_999).min(snapshot);
        let filter = Filter::new()
            .address(PP_ETH_POOL)
            .event_signature(Deposited::SIGNATURE_HASH)
            .from_block(from)
            .to_block(to);
        // The public gateway rate-limits a scan; back off and try again, as viem's client does.
        let mut attempt = 0;
        let logs = loop {
            match provider.get_logs(&filter).await {
                Ok(logs) => break logs,
                Err(e) if attempt < 6 => {
                    attempt += 1;
                    eprintln!("  blocks {from}..={to}: {e}; retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(attempt)).await;
                }
                Err(e) => return Err(e.into()),
            }
        };
        deposits.extend(
            logs.iter()
                .filter_map(|l| Deposited::decode_log_data(l.data()).ok()),
        );
    }
    let approved: std::collections::HashSet<U256> = set.labels().iter().copied().collect();
    let eth = deposits
        .iter()
        .filter(|d| approved.contains(&d._label))
        .count() as u64;
    show("an approved deposit into the ETH pool", eth);
    for (pool, label) in TORNADO_ETH.iter().zip(LABELS) {
        let n = deposits
            .iter()
            .filter(|d| approved.contains(&d._label) && d._value >= pool.denomination)
            .count() as u64;
        show(
            &format!("an approved ETH-pool deposit of at least {label}"),
            n,
        );
    }
    Ok(())
}
