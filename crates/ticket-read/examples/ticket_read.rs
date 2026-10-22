//! Private reads of testnet accounts, paid with blind tickets: `exp-frames` experiment 37.
//!
//! ```text
//! PRIVATE_KEY=0x... RECORD=record.json \
//!   cargo run --release -p kohaku-ticket-read --example ticket_read
//! ```
//!
//! 1. Four issuers run Commonware's DKG. The funder deploys a `TicketPaymaster` for their key
//!    as the ticket shop, and buys four tickets.
//! 2. The account table: every account without code that sent or received a transaction in the
//!    last `BLOCKS` blocks, at a snapshot block, laid out in buckets for PIR. A read server for
//!    it listens on a local port.
//! 3. The issuers sign four blinded read tickets: three for the server, one for another.
//! 4. Through `kohaku-pir-rpc`'s router, three private reads, one ticket each: experiment 36's
//!    second buyer's balance and nonce, and the balance of an address the table does not hold.
//! 5. Three requests the server must refuse before any work: a spent ticket, a ticket for
//!    another server, and a signature that is no ticket.
//! 6. The cost: the server's time per answer on this table and on a 64 MiB one, beside the time
//!    to check a ticket.
//!
//! The experiment, not the reader, checks each answer against the node at the snapshot.
//! `RECORD` names a JSON file for all of it. No key, blinding factor or LWE secret is recorded.

use std::{collections::BTreeMap, env, fs, sync::Arc, time::Instant};

use alloy::{
    eips::BlockId,
    primitives::{Address, B256, U256, address},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::group::{G1, Scalar};
use commonware_math::algebra::{CryptoGroup, Random};
use kohaku_frame_accounts::{
    account::{Eoa, Signer},
    builder::{Envelope, TxPlan},
};
use kohaku_frame_kit::{FrameSigner, rpc, sign_all};
use kohaku_frame_ticket::{
    Committee, TicketPaymaster, blind,
    issuers::{Count, Ledger, request_id},
};
use kohaku_pir_rpc::PirRouter;
use kohaku_ticket_read::{
    Account, ReadClaim, ReadTicket, Reader, Server, Table, TicketLookup, pir,
    ticket::READ_NAMESPACE,
};
use rand::RngExt;
use serde_json::{Value, json};

/// 0.001 ETH a ticket.
const DENOMINATION: U256 = U256::from_limbs([1_000_000_000_000_000, 0, 0, 0]);
const TIP: u128 = 1_000_000_000;
const ISSUERS: usize = 4;
const TICKETS: u64 = 4;
const BLOCKS: u64 = 3_000;
const CAPACITY: usize = 8;
/// Experiment 36's second buyer: its key was never kept, so its account no longer changes.
const TARGET: Address = address!("0x35be31B0dE16d67106F5cf0FA113dB6617B51FAf");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let funder: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY buys the tickets")?
        .parse()?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let mut rng = rand::rng();

    // 1. The committee, the shop, the purchase.
    let mut committee = Committee::dkg(&mut rng, ISSUERS)?;
    let shop = TicketPaymaster {
        key: *committee.sharing.public(),
        denomination: DENOMINATION,
        salt: B256::from(rng.random::<[u8; 32]>()),
    };
    let bought = buy(&provider, &funder, &shop).await?;
    println!(
        "shop {}: bought {TICKETS} in {} (block {})",
        shop.address(),
        bought.hash,
        bought.receipt.block_number
    );

    // 2. The table and the server.
    let snapshot = provider.get_block_number().await?;
    let accounts = accounts(&provider, snapshot).await?;
    let salts: Vec<B256> = (0..256)
        .map(|_| B256::from(rng.random::<[u8; 32]>()))
        .collect();
    let table = Table::build(&accounts, CAPACITY, salts)?;
    println!(
        "table at block {snapshot}: {} accounts, {} x {} bytes",
        accounts.len(),
        table.db.rows,
        table.db.cols
    );
    let server_id = B256::from(rng.random::<[u8; 32]>());
    let server = Arc::new(Server::new(
        table.clone(),
        *committee.sharing.public(),
        server_id,
        B256::from(rng.random::<[u8; 32]>()),
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let base = format!("http://{}", listener.local_addr()?);
    tokio::spawn(axum::serve(listener, server.clone().router()).into_future());

    // 3. Issuance against what the funder bought.
    let (tickets, transcript) = issue(&mut committee, funder.address(), server_id)?;

    // 4. Three private reads through the router, one ticket each.
    let reader = Arc::new(Reader::connect(&base).await?);
    reader.add_tickets(tickets[..3].iter().rev().copied());
    let router = PirRouter::with_rpc(
        Arc::new(TicketLookup {
            reader: reader.clone(),
            runtime: tokio::runtime::Handle::current(),
        }),
        &url,
        vec![],
    )?;
    let reads = private_reads(&router, &provider, &accounts, snapshot).await?;

    // 5. Refusals, sent straight to the server.
    let refusals = refusals(&reader, &tickets, server_id).await?;
    let log: Vec<Value> = reqwest::get(format!("{base}/log")).await?.json().await?;

    // 6. The cost.
    let cost = cost(&committee, &tickets[0], &table);
    println!("cost: {cost}");

    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "shop": shop.address(),
            "denomination": DENOMINATION,
            "bought": { "hash": bought.hash, "block": bought.receipt.block_number, "count": TICKETS },
            "committee": { "issuers": ISSUERS, "quorum": committee.quorum(), "key": hex(&committee.sharing.public().encode()) },
            "issuance": transcript,
            "tickets": tickets.iter().map(|t| json!({
                "server": t.claim.server, "serial": t.claim.serial,
                "signature": hex(&t.signature.encode()),
            })).collect::<Vec<_>>(),
            "snapshot": snapshot,
            "blocks": BLOCKS,
            "table": {
                "entries": table.entries, "rows": table.db.rows, "cols": table.db.cols,
                "capacity": table.capacity, "bytes": table.db.data.len(),
            },
            "manifest": reader.manifest,
            "hintBytes": reader.hint_bytes(),
            "queryBytes": reader.manifest.cols * 4,
            "answerBytes": reader.manifest.rows * 4,
            "reads": reads,
            "refusals": refusals,
            "serverLog": log,
            "cost": cost,
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    Ok(())
}

/// Deploy the shop and buy [`TICKETS`] in one transaction.
async fn buy<P: Provider>(
    provider: &P,
    funder: &PrivateKeySigner,
    shop: &TicketPaymaster,
) -> anyhow::Result<rpc::Executed> {
    let account = Eoa::new(Signer::secp256k1(funder.address()));
    let envelope = Envelope::fetch(provider, funder.address(), vec![U256::ZERO], TIP).await?;
    let mut tx = TxPlan::new(&account)
        .calls([shop.deploy_frame(), shop.buy_frame(TICKETS)])
        .build(&envelope)?;
    sign_all(&mut tx, &[FrameSigner::Secp256k1(funder.clone())])?;
    Ok(rpc::execute(provider, &tx, true).await?)
}

/// Four read tickets for `buyer`, against what it bought: three for `server`, one for another.
/// Each request goes to every issuer but one, in turn. The issuers' transcript: what each saw.
fn issue(
    committee: &mut Committee,
    buyer: Address,
    server: B256,
) -> anyhow::Result<(Vec<ReadTicket>, Vec<Value>)> {
    let mut rng = rand::rng();
    let mut ledger = Ledger::new([(buyer, TICKETS)].into_iter().collect());
    let mut transcript = vec![];
    let mut tickets = vec![];
    for (k, to) in [server, server, server, B256::ZERO].into_iter().enumerate() {
        let claim = ReadClaim {
            server: to,
            serial: B256::from(rng.random::<[u8; 32]>()),
        };
        let (b, r) = blind::blind(&mut rng, READ_NAMESPACE, &claim.message());
        let mut answers = vec![];
        for (i, issuer) in committee.issuers.iter_mut().enumerate() {
            if i == k % ISSUERS {
                continue;
            }
            ledger.admit(Count::Shared, i, buyer, request_id(&b))?;
            answers.push(issuer.answer(&b));
            transcript.push(json!({ "issuer": issuer.index(), "blinded": hex(&b.encode()) }));
        }
        let signature = blind::unblind(&committee.sharing, &answers, &r)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let ticket = ReadTicket { claim, signature };
        ticket
            .verify(committee.sharing.public())
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        tickets.push(ticket);
    }
    Ok((tickets, transcript))
}

/// Three private reads through the router, each checked against the node at the snapshot: the
/// experiment's check, not the reader's.
async fn private_reads<P: Provider>(
    router: &PirRouter,
    provider: &P,
    accounts: &BTreeMap<Address, Account>,
    snapshot: u64,
) -> anyhow::Result<Vec<Value>> {
    let absent = Address::from(rand::rng().random::<[u8; 20]>());
    let mut reads = vec![];
    for (method, who) in [
        ("eth_getBalance", TARGET),
        ("eth_getTransactionCount", TARGET),
        ("eth_getBalance", absent),
    ] {
        let (value, path) = router
            .request_with_path(method, json!([who, "latest"]))
            .await?;
        let node: Value = provider
            .raw_request(method.into(), (who, BlockId::number(snapshot)))
            .await?;
        println!("{method}({who}): {value} by {path:?}; the node at {snapshot}: {node}");
        ensure!(value == node, "the private read disagrees with the node");
        reads.push(json!({
            "method": method, "address": who, "inTable": accounts.contains_key(&who),
            "value": value, "path": format!("{path:?}"), "node": node,
        }));
    }
    Ok(reads)
}

/// Requests the server must refuse before any work, sent straight to it.
async fn refusals(
    reader: &Reader,
    tickets: &[ReadTicket],
    server: B256,
) -> anyhow::Result<Vec<Value>> {
    let mut rng = rand::rng();
    let q = vec![0u32; reader.manifest.cols];
    let junk = ReadTicket {
        claim: ReadClaim {
            server,
            serial: B256::from(rng.random::<[u8; 32]>()),
        },
        signature: G1::generator() * &Scalar::random(&mut rng),
    };
    let mut out = vec![];
    for (what, t) in [
        ("a spent ticket", &tickets[0]),
        ("a ticket for another server", &tickets[3]),
        ("a signature that is no ticket", &junk),
    ] {
        let err = reader
            .send(&q, t)
            .await
            .err()
            .context("the server answered")?
            .to_string();
        println!("{what}: {err}");
        out.push(json!({ "what": what, "answer": err }));
    }
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

/// Every account without code, or with an EIP-7702 delegation, that sent or received a
/// transaction in the last [`BLOCKS`] blocks, as it stood at `snapshot`.
async fn accounts<P: Provider>(
    provider: &P,
    snapshot: u64,
) -> anyhow::Result<BTreeMap<Address, Account>> {
    let mut seen = std::collections::BTreeSet::new();
    for n in snapshot.saturating_sub(BLOCKS)..=snapshot {
        let block: Value = provider
            .raw_request("eth_getBlockByNumber".into(), (format!("{n:#x}"), true))
            .await?;
        for tx in block["transactions"].as_array().into_iter().flatten() {
            for field in ["from", "to", "sender"] {
                if let Some(a) = tx[field].as_str().and_then(|a| a.parse::<Address>().ok()) {
                    seen.insert(a);
                }
            }
        }
    }
    seen.insert(TARGET);
    let at = BlockId::number(snapshot);
    let mut out = BTreeMap::new();
    for a in seen {
        let code = provider.get_code_at(a).block_id(at).await?;
        let delegate = match code.len() {
            0 => Address::ZERO,
            23 if code.starts_with(&[0xef, 0x01, 0x00]) => Address::from_slice(&code[3..]),
            _ => continue,
        };
        out.insert(
            a,
            Account {
                delegate,
                balance: provider.get_balance(a).block_id(at).await?,
                nonce: provider.get_transaction_count(a).block_id(at).await?,
            },
        );
    }
    Ok(out)
}

/// The server's time per answer, on this table and on a 64 MiB one, beside a ticket check:
/// medians of repeated runs on one core.
fn cost(committee: &Committee, ticket: &ReadTicket, table: &Table) -> Value {
    let median = |mut v: Vec<u128>| {
        v.sort_unstable();
        v[v.len() / 2]
    };
    let time = |f: &mut dyn FnMut(), runs: usize| {
        median(
            (0..runs)
                .map(|_| {
                    let t = Instant::now();
                    f();
                    t.elapsed().as_nanos()
                })
                .collect(),
        )
    };
    let key = *committee.sharing.public();
    let check = time(&mut || assert!(ticket.verify(&key).is_ok()), 101);
    let q: Vec<u32> = (0..table.db.cols).map(|i| i as u32).collect();
    let here = time(&mut || drop(std::hint::black_box(table.db.answer(&q))), 101);
    let big = pir::Database {
        rows: 8_192,
        cols: 8_192,
        data: (0..8_192 * 8_192_usize).map(|i| (i % 251) as u8).collect(),
    };
    let qb: Vec<u32> = (0..big.cols).map(|i| i as u32).collect();
    let large = time(&mut || drop(std::hint::black_box(big.answer(&qb))), 11);
    json!({
        "ticketCheckNanos": check,
        "answerNanos": { "table": here, "tableBytes": table.db.data.len(),
                         "large": large, "largeBytes": big.data.len() },
        "bytesPerSecond": (big.data.len() as u128) * 1_000_000_000 / large,
    })
}
