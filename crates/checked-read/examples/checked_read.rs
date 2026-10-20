//! Checked private reads of testnet accounts: `exp-frames` experiment 39.
//!
//! ```text
//! PRIVATE_KEY=0x... RECORD=record.json EVIDENCE=evidence.json \
//!   cargo run --release -p kohaku-checked-read --example checked_read
//! ```
//!
//! 1. Four issuers run Commonware's DKG. The funder deploys a `TicketPaymaster` for their key as
//!    the ticket shop and buys [`TICKETS`] tickets, as in experiment 37.
//! 2. The table: experiment 37's accounts (every account without code, or with an EIP-7702
//!    delegation, that sent or received a transaction in the last [`BLOCKS`] blocks), each with
//!    its `eth_getProof` branch, at a snapshot block taken after the scan, while the node still
//!    serves branches for it.
//! 3. Four servers, each with its own signing key: two honest ones, one with the whole branch in
//!    each record and one with the trie's top split off, and two liars, whose table changes the
//!    target's balance, with its true branch kept or with its leaf forged to match.
//! 4. The reader fetches the snapshot's header itself, from the testnet's RPC, and checks every
//!    answer against it: a balance and a nonce through `kohaku-pir-rpc`'s router, one read of the
//!    whole-branch server, an address the table does not hold, and one read of each liar.
//! 5. A third party judges the first liar's evidence, holding only it: it fetches the header and
//!    the target's branch itself, from the testnet's RPC.
//! 6. The cost: the bytes a branch adds per read and once per reader, and the server's time per
//!    answer and per signature beside the ticket check.
//!
//! No key, blinding factor or LWE secret but the opened one in the evidence is recorded.

use std::{collections::BTreeMap, env, fs, sync::Arc, time::Instant};

use alloy::{
    eips::BlockId,
    primitives::{Address, B256, KECCAK256_EMPTY, U256, address},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::group::{G1, Scalar};
use commonware_math::algebra::{CryptoGroup, Random};
use kohaku_checked_read::{
    Checked, CheckedLookup, CheckedReader, CheckedTable, Entry, Evidence, Header, Server,
    Verdict, judge,
    trie::{self, AccountState, Nodes},
};
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
use kohaku_ticket_read::{Account, ReadClaim, ReadTicket, Table, pir, ticket::READ_NAMESPACE};
use rand::RngExt;
use serde_json::{Value, json};

/// 0.001 ETH a ticket.
const DENOMINATION: U256 = U256::from_limbs([1_000_000_000_000_000, 0, 0, 0]);
const TIP: u128 = 1_000_000_000;
const ISSUERS: usize = 4;
const TICKETS: u64 = 8;
const BLOCKS: u64 = 3_000;
const CAPACITY: usize = 8;
/// Experiment 36's second buyer: its key was never kept, so its account no longer changes.
const TARGET: Address = address!("0x35be31B0dE16d67106F5cf0FA113dB6617B51FAf");
/// What each liar adds to the target's balance: 1 ETH.
const LIE: U256 = U256::from_limbs([1_000_000_000_000_000_000, 0, 0, 0]);

// The run, in the order of the steps above.
#[allow(clippy::too_many_lines)]
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

    // 2. The accounts, then the snapshot and every branch at it.
    let scanned = provider.get_block_number().await?;
    let seen = active(&provider, scanned).await?;
    let snapshot = provider.get_block_number().await?;
    let state_root = server_state_root(&provider, snapshot).await?;
    let entries = branches(&provider, &seen, snapshot).await?;
    let depths: Vec<usize> = entries.values().map(|e| e.proof.len()).collect();
    println!(
        "snapshot {snapshot}: {} accounts, branches of {} to {} nodes",
        entries.len(),
        depths.iter().min().unwrap_or(&0),
        depths.iter().max().unwrap_or(&0)
    );

    // The layouts: each split's sizes, and the split that downloads least once per reader.
    let salts: Vec<B256> = (0..256)
        .map(|_| B256::from(rng.random::<[u8; 32]>()))
        .collect();
    let max_depth = depths.iter().copied().max().unwrap_or(0);
    let mut layouts = vec![];
    for split in 0..max_depth {
        let t = CheckedTable::build(&entries, CAPACITY, split, salts.clone())?;
        layouts.push(json!({
            "split": split, "record": t.record, "rows": t.db.rows, "cols": t.db.cols,
            "tableBytes": t.db.data.len(), "answerBytes": t.db.rows * 4,
            "hintBytes": t.db.rows * pir::N * 4, "topBytes": t.top_bytes(), "topNodes": t.top.len(),
        }));
    }
    let split = (0..max_depth)
        .min_by_key(|&s| {
            let l = &layouts[s];
            l["hintBytes"].as_u64().unwrap_or(u64::MAX) + l["topBytes"].as_u64().unwrap_or(0)
        })
        .unwrap_or(0);
    println!("split at depth {split}");

    // 3. The servers.
    let mut lied = entries.clone();
    lied.get_mut(&TARGET)
        .context("the target is in the table")?
        .account
        .balance += LIE;
    let mut forged = lied.clone();
    {
        let e = forged.get_mut(&TARGET).context("the target")?;
        let leaf = e.proof.pop().context("a branch")?;
        let account = chain_state(&e.account);
        e.proof.push(trie::reencode_leaf(&leaf, &account)?.into());
    }
    let mut servers = vec![];
    for (name, table_of, split) in [
        ("honest, split", &entries, split),
        ("honest, whole branch", &entries, 0),
        ("liar, balance changed, true branch", &lied, split),
        ("liar, balance changed, leaf forged", &forged, split),
    ] {
        let table = CheckedTable::build(table_of, CAPACITY, split, salts.clone())?;
        let server = Arc::new(Server::new(
            table,
            *committee.sharing.public(),
            PrivateKeySigner::random(),
            B256::from(rng.random::<[u8; 32]>()),
            snapshot,
            state_root,
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let base = format!("http://{}", listener.local_addr()?);
        tokio::spawn(axum::serve(listener, server.clone().router()).into_future());
        servers.push((name, server, base));
    }

    // Issuance against what the funder bought: 4, 1, 1 and 1 tickets, and one for another server.
    let ids: Vec<B256> = servers.iter().map(|(_, s, _)| s.manifest.server).collect();
    let plan = [ids[0], ids[0], ids[0], ids[0], ids[1], ids[2], ids[3], B256::ZERO];
    let (tickets, transcript) = issue(&mut committee, funder.address(), &plan)?;

    // 4. The reader: its own header, then the reads.
    let t = Instant::now();
    let header = Header::fetch(&url, snapshot).await?;
    println!(
        "the reader's header {snapshot}: {} (hashed again), state root {}",
        header.hash, header.state_root
    );
    let mut readers = vec![];
    for (_, server, base) in &servers {
        readers.push(Arc::new(
            CheckedReader::with_header(base, server.manifest.clone(), header.clone()).await?,
        ));
    }
    let connect_ms = t.elapsed().as_millis();
    readers[0].add_tickets(tickets[..4].iter().rev().copied());
    for (k, r) in readers.iter().enumerate().skip(1) {
        r.add_tickets([tickets[3 + k]]);
    }

    let router = PirRouter::with_rpc(
        Arc::new(CheckedLookup {
            reader: readers[0].clone(),
            runtime: tokio::runtime::Handle::current(),
        }),
        &url,
        vec![],
    )?;
    let mut reads = vec![];
    for method in ["eth_getBalance", "eth_getTransactionCount"] {
        let (value, path) = router
            .request_with_path(method, json!([TARGET, "latest"]))
            .await?;
        let node: Value = provider
            .raw_request(method.into(), (TARGET, BlockId::number(snapshot)))
            .await?;
        println!("{method}({TARGET}): {value} by {path:?}, checked; the node at {snapshot}: {node}");
        ensure!(value == node, "the checked read disagrees with the node");
        reads.push(json!({ "server": servers[0].0, "method": method, "address": TARGET,
                           "value": value, "path": format!("{path:?}"), "node": node }));
    }
    let absent = Address::from(rng.random::<[u8; 20]>());
    let unanswered = readers[0].read(absent).await.err().context("an answer")?;
    println!("{absent}, not in the table: {unanswered}");
    reads.push(json!({ "server": servers[0].0, "address": absent, "outcome": unanswered.to_string() }));

    let mut checks = vec![];
    for (k, reader) in readers.iter().enumerate().skip(1) {
        let t = Instant::now();
        let out = reader.read(TARGET).await?;
        let micros = t.elapsed().as_micros();
        let (outcome, why) = match &out {
            Checked::Proven { value, .. } => ("proven", format!("0x{}", hex::encode(value))),
            Checked::Refused { why, .. } => ("refused", why.clone()),
        };
        println!("{}: {outcome}: {why}", servers[k].0);
        checks.push(json!({ "server": servers[k].0, "address": TARGET, "outcome": outcome,
                            "detail": why, "readMicros": micros }));
    }
    ensure!(checks[0]["outcome"] == "proven", "the honest whole-branch read was refused");
    ensure!(
        checks[1]["outcome"] == "refused" && checks[2]["outcome"] == "refused",
        "a lie passed the reader's check"
    );

    // The ticket check still comes first.
    let q = vec![0u32; readers[0].manifest.cols];
    let junk = ReadTicket {
        claim: ReadClaim {
            server: ids[0],
            serial: B256::from(rng.random::<[u8; 32]>()),
        },
        signature: G1::generator() * &Scalar::random(&mut rng),
    };
    let mut refusals = vec![];
    for (what, t) in [
        ("a spent ticket", &tickets[0]),
        ("a ticket for another server", &tickets[7]),
        ("a signature that is no ticket", &junk),
    ] {
        let err = readers[0].send(&q, t).await.err().context("answered")?.to_string();
        println!("{what}: {err}");
        refusals.push(json!({ "what": what, "answer": err }));
    }

    // 5. The third party, from the published evidence alone.
    let evidence = readers[2].refused().pop().context("evidence")?;
    let published = serde_json::to_string_pretty(&evidence)?;
    let (verdict, third) = third_party(&published, &url).await?;
    println!("the third party: {verdict}");
    let second = readers[3].refused().pop().context("evidence")?;
    let (verdict2, _) = third_party(&serde_json::to_string(&second)?, &url).await?;
    println!("the third party, on the forged leaf: {verdict2}");

    // 6. The cost.
    let logs = [
        reqwest::get(format!("{}/log", servers[0].2)).await?.json::<Value>().await?,
        reqwest::get(format!("{}/log", servers[1].2)).await?.json::<Value>().await?,
        reqwest::get(format!("{}/log", servers[2].2)).await?.json::<Value>().await?,
        reqwest::get(format!("{}/log", servers[3].2)).await?.json::<Value>().await?,
    ];
    let accounts: BTreeMap<Address, Account> =
        entries.iter().map(|(a, e)| (*a, e.account)).collect();
    let cost = cost(&committee, &tickets[0], &accounts, &entries, split, &salts, &servers[0].1)?;
    println!("cost: {cost}");

    if let Ok(path) = env::var("EVIDENCE") {
        fs::write(&path, format!("{published}\n"))?;
        println!("evidence in {path}");
    }
    if let Ok(path) = env::var("RECORD") {
        let (hint0, top0) = readers[0].once_bytes();
        let (hint1, top1) = readers[1].once_bytes();
        let record = json!({
            "shop": shop.address(),
            "denomination": DENOMINATION,
            "bought": { "hash": bought.hash, "block": bought.receipt.block_number, "count": TICKETS },
            "committee": { "issuers": ISSUERS, "quorum": committee.quorum(),
                           "key": hex(&committee.sharing.public().encode()) },
            "issuance": transcript,
            "tickets": tickets.iter().map(|t| json!({
                "server": t.claim.server, "serial": t.claim.serial,
                "signature": hex(&t.signature.encode()),
            })).collect::<Vec<_>>(),
            "scanned": { "from": scanned.saturating_sub(BLOCKS), "to": scanned },
            "snapshot": snapshot,
            "header": { "number": header.number, "hash": header.hash,
                        "stateRoot": header.state_root, "rlp": header.rlp },
            "entries": entries.len(),
            "depths": depths,
            "layouts": layouts,
            "split": split,
            "servers": servers.iter().map(|(name, s, _)| json!({ "name": name, "manifest": s.manifest }))
                .collect::<Vec<_>>(),
            "once": { "split": { "hintBytes": hint0, "topBytes": top0 },
                      "whole": { "hintBytes": hint1, "topBytes": top1 } },
            "readerConnectMillis": connect_ms,
            "reads": reads,
            "checks": checks,
            "refusals": refusals,
            "thirdParty": third,
            "thirdPartyForged": verdict2,
            "serverLogs": logs,
            "cost": cost,
        });
        fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&record)?))?;
        println!("recorded in {path}");
    }
    Ok(())
}

/// The third party: it holds the published evidence and nothing else, and fetches the header
/// and the disputed account's branch itself.
async fn third_party(published: &str, url: &str) -> anyhow::Result<(String, Value)> {
    let evidence: Evidence = serde_json::from_str(published)?;
    let block = evidence.manifest.block;
    let address = Address::from_slice(evidence.claimed.get(..20).context("a claim")?);
    let header = Header::fetch(url, block).await?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let proof = provider
        .get_proof(address, vec![])
        .block_id(BlockId::number(block))
        .await?;
    ensure!(
        !proof.account_proof.is_empty(),
        "the node no longer serves a branch at block {block}"
    );
    let chain: Nodes = proof.account_proof.iter().collect();
    let t = Instant::now();
    let verdict = judge(&evidence, &header, &chain)?;
    let micros = t.elapsed().as_micros();
    let said = match &verdict {
        Verdict::Wrong { address, signed, chain } => format!(
            "wrong: the server signed balance {} for {address}, the chain holds {}",
            U256::from_be_slice(&signed[20..32]),
            chain.map_or_else(|| "no account".to_owned(), |c| c.balance.to_string())
        ),
        Verdict::Correct { address } => format!("correct for {address}"),
    };
    Ok((
        said.clone(),
        json!({
            "verdict": said,
            "judgeMicros": micros,
            "evidenceBytes": published.len(),
            "chainProof": { "address": address, "block": block, "accountProof": proof.account_proof },
        }),
    ))
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

/// A read ticket for `buyer` per entry of `servers`, against what it bought. Each request goes
/// to every issuer but one, in turn. The issuers' transcript: what each saw.
fn issue(
    committee: &mut Committee,
    buyer: Address,
    servers: &[B256],
) -> anyhow::Result<(Vec<ReadTicket>, Vec<Value>)> {
    let mut rng = rand::rng();
    let mut ledger = Ledger::new([(buyer, TICKETS)].into_iter().collect());
    let mut transcript = vec![];
    let mut tickets = vec![];
    for (k, to) in servers.iter().enumerate() {
        let claim = ReadClaim {
            server: *to,
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

fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

/// Every address that sent or received a transaction in the [`BLOCKS`] blocks up to `to`, and
/// the target.
async fn active<P: Provider>(
    provider: &P,
    to: u64,
) -> anyhow::Result<std::collections::BTreeSet<Address>> {
    let mut seen = std::collections::BTreeSet::new();
    for n in to.saturating_sub(BLOCKS)..=to {
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
    Ok(seen)
}

/// The server's own view of the snapshot's state root, from its own request to the node.
async fn server_state_root<P: Provider>(provider: &P, n: u64) -> anyhow::Result<B256> {
    let block: Value = provider
        .raw_request("eth_getBlockByNumber".into(), (format!("{n:#x}"), false))
        .await?;
    Ok(block["stateRoot"].as_str().context("a state root")?.parse()?)
}

/// Each of `seen` without code, or with an EIP-7702 delegation, with its branch at `snapshot`.
async fn branches<P: Provider>(
    provider: &P,
    seen: &std::collections::BTreeSet<Address>,
    snapshot: u64,
) -> anyhow::Result<BTreeMap<Address, Entry>> {
    let at = BlockId::number(snapshot);
    let mut out = BTreeMap::new();
    for &a in seen {
        let p = provider.get_proof(a, vec![]).block_id(at).await?;
        ensure!(!p.account_proof.is_empty(), "no branch for {a} at {snapshot}");
        let delegate = if p.code_hash == KECCAK256_EMPTY || p.code_hash.is_zero() {
            Address::ZERO
        } else {
            let code = provider.get_code_at(a).block_id(at).await?;
            match code.len() {
                23 if code.starts_with(&[0xef, 0x01, 0x00]) => Address::from_slice(&code[3..]),
                _ => continue,
            }
        };
        out.insert(
            a,
            Entry {
                account: Account {
                    delegate,
                    balance: p.balance,
                    nonce: p.nonce,
                },
                proof: p.account_proof,
            },
        );
    }
    Ok(out)
}

/// The account a table entry stands for, as the trie holds it: no storage, and the code its
/// delegate implies.
fn chain_state(a: &Account) -> AccountState {
    let code_hash = if a.delegate.is_zero() {
        KECCAK256_EMPTY
    } else {
        alloy::primitives::keccak256([&[0xef, 0x01, 0x00][..], a.delegate.as_slice()].concat())
    };
    AccountState {
        nonce: a.nonce,
        balance: a.balance,
        storage_root: alloy::trie::EMPTY_ROOT_HASH,
        code_hash,
    }
}

/// Medians of repeated runs on one core: the ticket check, the signature, the reader's walk, and
/// the answer on experiment 37's table (no branch) and on this run's two layouts.
fn cost(
    committee: &Committee,
    ticket: &ReadTicket,
    accounts: &BTreeMap<Address, Account>,
    entries: &BTreeMap<Address, Entry>,
    split: usize,
    salts: &[B256],
    server: &Server,
) -> anyhow::Result<Value> {
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
    let mut answers = vec![];
    let bare = Table::build(accounts, CAPACITY, salts.iter().copied())?;
    let q: Vec<u32> = (0..bare.db.cols).map(|i| i as u32).collect();
    let bare_ns = time(&mut || drop(std::hint::black_box(bare.db.answer(&q))), 101);
    answers.push(json!({ "layout": "no branch (experiment 37)", "tableBytes": bare.db.data.len(),
                         "answerBytes": bare.db.rows * 4, "answerNanos": bare_ns }));
    let mut signed_answer = vec![];
    for (layout, s) in [("split", split), ("whole branch", 0)] {
        let t = CheckedTable::build(entries, CAPACITY, s, salts.iter().copied())?;
        let q: Vec<u32> = (0..t.db.cols).map(|i| i as u32).collect();
        let ns = time(&mut || drop(std::hint::black_box(t.db.answer(&q))), 101);
        if s == split {
            signed_answer = t.db.answer(&q);
        }
        answers.push(json!({ "layout": layout, "split": s, "tableBytes": t.db.data.len(),
                             "answerBytes": t.db.rows * 4, "answerNanos": ns }));
    }
    let q: Vec<u32> = (0..server.manifest.cols).map(|i| i as u32).collect();
    let sign = time(&mut || drop(std::hint::black_box(server.sign(&q, &signed_answer))), 101);
    let e = &entries[&TARGET];
    let nodes: Nodes = e.proof.iter().collect();
    let root = server.manifest.state_root;
    let walk = time(
        &mut || drop(std::hint::black_box(trie::account(root, TARGET, &nodes))),
        101,
    );
    Ok(json!({
        "ticketCheckNanos": check,
        "signNanos": sign,
        "readerWalkNanos": walk,
        "answers": answers,
    }))
}
