//! An encrypted backup that anyone can store: `exp-frames` experiment 47, on the ethrex Hegota
//! testnet, after experiments 45 and 46.
//!
//! ```text
//! SEED_FILE=... STATE_DIR=... PUBLIC45=public45.json PUBLIC46=public46.json \
//!   HISTORY=build45.json,restore45.json,setup46.json,recover46.json RECORD=write.json \
//!   MODE=write cargo run --release -p kohaku-frame-secrets --example backup
//! STATE_DIR=... RECORD=reopen.json MODE=reopen \
//!   cargo run --release -p kohaku-frame-secrets --example backup
//! ```
//!
//! `MODE=write`, on the device that holds the seed: owner 0 buys two tickets from a new
//! committee; the wallet's state is written as backup version 0 and posted from ticket 5's fresh
//! sender; the state changes (that ticket is spent, the post joins the history); version 1 is
//! posted from ticket 6's.
//!
//! `MODE=reopen`, on a fresh device with the phrase and nothing else of the wallet's: guardians 7
//! and 9, experiment 46's current set, hand it their shares off the chain. It joins `R2`, opens
//! the envelope from the board, and has the seed; it finds and opens every backup version, and
//! checks what they say against the chain. Then it measures what each leaked key opens.
//!
//! No key, share, phrase, word or plaintext is printed or recorded; the record keeps each
//! plaintext's SHA-256.

mod common;

use std::{env, fs, path::PathBuf};

use alloy::{
    primitives::{Address, B256, U256, address},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use anyhow::{Context, ensure};
use common::{BOARD, account, buy_tickets, executed, hex, load_seed, rebuild_ticket, spend, unhex};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::bls12381::primitives::{
    group::{G1, G2},
    ops,
    variant::MinSig,
};
use kohaku_frame_kit::rpc;
use kohaku_frame_registry::{
    announce::{self, board_messages},
    custody::{self, abi as registry_abi},
    note::{Secrets, field},
};
use kohaku_frame_secrets::{
    Seed,
    backup::{self, BUCKET, OVERHEAD},
    guardians::{self, ENVELOPE_LEN, ENVELOPE_TAG, Share, locator},
};
use kohaku_frame_ticket::{paymaster::Bought, ticket::NAMESPACE};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const T: usize = 2;
/// The seed's tickets this run uses: 45 used 0 and 1, 46 used 2 to 4.
const FIRST_TICKET: u32 = 5;
const TIP: u128 = common::TIP;
const REGISTRY: Address = address!("0x246FBf1ca115E6f9993658e0e46F24E4C9054Df6");
/// Experiment 46's current set, and the two who help.
const SET: u32 = 2;
const HELPERS: [usize; 2] = [7, 9];
const OLD_SET: [usize; 2] = [1, 2];

fn state(name: &str) -> anyhow::Result<PathBuf> {
    Ok(PathBuf::from(env::var("STATE_DIR").context("STATE_DIR")?).join(name))
}

fn read_json(var: &str) -> anyhow::Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(
        env::var(var).with_context(|| var.to_owned())?,
    )?)?)
}

/// A guardian's share, as it hands it over.
fn share_of(g: usize) -> anyhow::Result<Share> {
    let v: Value =
        serde_json::from_str(&fs::read_to_string(state(&format!("guardian-{g}.json"))?)?)?;
    Ok(Share::decode(&unhex(
        v["share"].as_str().context("share")?,
    )?)?)
}

fn guardian_address(g: usize) -> anyhow::Result<Address> {
    let k: PrivateKeySigner = fs::read_to_string(state(&format!("guardian-{g}.key"))?)?
        .trim()
        .parse()?;
    Ok(k.address())
}

fn sha(b: &[u8]) -> String {
    hex(&Sha256::digest(b))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    match env::var("MODE").as_deref() {
        Ok("write") => write(&provider).await,
        Ok("reopen") => reopen(&provider).await,
        _ => anyhow::bail!("MODE is write or reopen"),
    }
}

/// The opening of a vault note sealed to the viewing key, as experiment 45's funder sealed it.
fn received(seed: &Seed, board: &[announce::Posted]) -> anyhow::Result<Vec<Value>> {
    let view = seed.view()?;
    Ok(announce::scan(view.secret, board)
        .into_iter()
        .filter(|(_, p)| p.len() == 92)
        .map(|(posted, p)| {
            json!({
                "vault": Address::from_slice(&p[..20]),
                "nullifierSecret": hex(&p[20..52]),
                "secret": hex(&p[52..84]),
                "state": u64::from_be_bytes(p[84..92].try_into().unwrap_or_default()),
                "announcement": posted.tx,
            })
        })
        .collect())
}

#[allow(clippy::too_many_lines)]
async fn write<P: Provider>(provider: &P) -> anyhow::Result<()> {
    let seed = load_seed()?;
    let chain_id = provider.get_chain_id().await?;
    let owner = seed.owner(0)?;
    let p45 = read_json("PUBLIC45")?;
    let p46 = read_json("PUBLIC46")?;
    let acct = account(&seed, 0)?;
    let slot0 = provider.get_storage_at(acct.address(), U256::ZERO).await?;
    let holder = Address::from_word(slot0.into());
    let owner_index = (0..3u32)
        .find(|&j| seed.owner(j).is_ok_and(|o| o.address() == holder))
        .context("account 0 is owned by none of the seed's first owners")?;
    let mut history: Vec<String> = vec![];
    for path in env::var("HISTORY").context("HISTORY")?.split(',') {
        let r: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
        for list in ["steps", "spends"] {
            for s in r[list].as_array().into_iter().flatten() {
                if let Some(h) = s["hash"].as_str() {
                    history.push(h.to_owned());
                }
            }
        }
    }

    // Tickets for the two posts.
    let tickets = buy_tickets(provider, &seed, &owner, FIRST_TICKET, 2).await?;
    let mut steps = tickets.steps.clone();
    for s in &steps {
        history.push(s["hash"].as_str().unwrap_or_default().to_owned());
    }
    let board = board_messages(provider, BOARD).await?;
    let key45 = G2::decode(unhex(p45["committeeKey"].as_str().context("key")?)?.as_slice())
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let (t1, _) = rebuild_ticket(&seed, chain_id, 1, &board, &key45)?;
    ensure!(
        provider
            .get_transaction_count(seed.ticket(1)?.sender.address())
            .await?
            == 0,
        "ticket 1 was spent"
    );
    let ticket_json = |k: u32, paymaster: &Value, t: &kohaku_frame_ticket::Ticket| json!({ "k": k, "paymaster": paymaster, "epoch": t.claim.epoch, "signature": hex(&t.signature.encode()) });
    let paymasters = json!([
        { "address": p45["paymaster"], "key": p45["committeeKey"], "first": 0, "count": 2 },
        { "address": p46["paymaster"], "key": p46["committeeKey"], "first": 2, "count": 3 },
        { "address": tickets.paymaster, "key": hex(&tickets.committee_key.encode()), "first": FIRST_TICKET, "count": 2 },
    ]);
    let recv = received(&seed, &board)?;
    let contacts: Vec<Option<Address>> = [7, 8, 9]
        .iter()
        .map(|&g| guardian_address(g).ok())
        .collect();
    let state_v = |v: u32, unspent: Vec<Value>, history: &[String]| {
        json!({
            "v": v,
            "chainId": chain_id,
            "contracts": {
                "pool": p45["pool"], "registry": p45["registry"], "vault": p45["vault"],
                "vaultAmount": p45["vaultAmount"], "board": BOARD,
            },
            "paymasters": paymasters,
            "account": { "index": 0, "address": acct.address(), "owner": owner_index, "delay": common::DELAY },
            "guardians": {
                "set": SET, "t": T, "n": 3,
                "contacts": contacts,
            },
            "cursors": { "keychain": 1, "vault": 1, "ticket": FIRST_TICKET + 2, "recipient": 1, "backup": v + 1 },
            "tickets": unspent,
            "received": recv,
            "history": history,
        })
    };

    let mut posts = vec![];
    let mut rng = rand::rng();
    for v in 0..2u32 {
        let unspent = if v == 0 {
            vec![
                ticket_json(1, &p45["paymaster"], &t1),
                ticket_json(
                    FIRST_TICKET + 1,
                    &json!(tickets.paymaster),
                    &tickets.issued[1],
                ),
            ]
        } else {
            vec![ticket_json(1, &p45["paymaster"], &t1)]
        };
        let plaintext = serde_json::to_vec(&state_v(v, unspent, &history))?;
        let (key, loc) = backup::keys(&seed, v);
        let posted = backup::seal(&key, loc, &plaintext, &mut rng);
        let k = FIRST_TICKET + v;
        let fees = rpc::suggest_fees(provider, TIP).await?;
        let tx = spend(
            chain_id,
            fees,
            &seed.ticket(k)?.sender,
            &tickets.issued[v as usize],
            tickets.paymaster,
            &posted,
        )?;
        let mut done = executed(
            provider,
            &tx,
            &format!("backup version {v}, from ticket {k}'s fresh sender"),
        )
        .await?;
        done["plaintextBytes"] = json!(plaintext.len());
        done["postedBytes"] = json!(posted.len());
        done["plaintextSha256"] = json!(sha(&plaintext));
        done["locator"] = json!(loc);
        history.push(done["hash"].as_str().unwrap_or_default().to_owned());
        posts.push(done.clone());
        steps.push(done);
    }

    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "owner0": owner.address(),
            "account": acct.address(),
            "ticketPaymaster": tickets.paymaster,
            "committeeKey": hex(&tickets.committee_key.encode()),
            "steps": steps,
            "backups": posts,
            "historyLength": history.len(),
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    println!("the device is lost: the user keeps the phrase; guardians 7 to 9 keep their shares");
    Ok(())
}

/// The seed from the envelope for the set `shares` belong to, opened with the phrase.
fn seed_from(
    board: &[announce::Posted],
    shares: &[Share],
    phrase: &str,
) -> anyhow::Result<(Seed, Address, B256)> {
    let r = guardians::join(shares, T)?;
    let found = board
        .iter()
        .find(|p| {
            p.message.len() == ENVELOPE_LEN
                && p.message[0] == ENVELOPE_TAG
                && p.message[1..33] == locator(r.address())[..]
        })
        .context("no envelope for this recovery key")?;
    let words = guardians::open(
        &found.message,
        &r,
        Some(&guardians::stretch(phrase, r.address())),
    )?;
    Ok((Seed::from_mnemonic(&words)?, r.address(), found.tx))
}

/// Every backup version a seed finds on the board, opened, in order.
fn versions(seed: &Seed, board: &[announce::Posted]) -> Vec<(u32, B256, Vec<u8>)> {
    let mut out = vec![];
    for v in 0.. {
        let (key, loc) = backup::keys(seed, v);
        let Some((tx, plain)) = board.iter().find_map(|p| {
            backup::open(&key, loc, &p.message)
                .ok()
                .map(|plain| (p.tx, plain))
        }) else {
            break;
        };
        out.push((v, tx, plain));
    }
    out
}

#[allow(clippy::too_many_lines)]
async fn reopen<P: Provider>(provider: &P) -> anyhow::Result<()> {
    let chain_id = provider.get_chain_id().await?;
    let phrase = fs::read_to_string(state("phrase.txt")?)?;
    let board = board_messages(provider, BOARD).await?;

    // The seed, through the current guardians.
    let helpers: Vec<Share> = HELPERS
        .iter()
        .map(|&g| share_of(g))
        .collect::<Result<_, _>>()?;
    let (seed, r2, envelope_tx) = seed_from(&board, &helpers, &phrase)?;
    println!(
        "guardians 7 and 9 handed over their shares; the envelope in {envelope_tx} gave the seed"
    );

    // Every version.
    let found = versions(&seed, &board);
    ensure!(found.len() == 2, "found {} backup versions", found.len());
    let mut opened = vec![];
    for (v, tx, plain) in &found {
        println!(
            "backup version {v}: posted in {tx}, {} bytes of state",
            plain.len()
        );
        opened.push(json!({ "v": v, "tx": tx, "plaintextBytes": plain.len(), "plaintextSha256": sha(plain) }));
    }
    let latest: Value = serde_json::from_slice(&found.last().context("none")?.2)?;

    // What the latest version says, against the chain.
    let mut checks = vec![];
    for name in ["pool", "registry", "vault", "board"] {
        let a: Address = latest["contracts"][name]
            .as_str()
            .context("contract")?
            .parse()?;
        let has_code = !provider.get_code_at(a).await?.is_empty();
        ensure!(has_code, "{name} has no code");
        checks.push(json!({ "what": format!("{name} has code"), "ok": true }));
    }
    let acct: Address = latest["account"]["address"]
        .as_str()
        .context("account")?
        .parse()?;
    let owner_index = u32::try_from(latest["account"]["owner"].as_u64().context("owner")?)?;
    let slot0 = provider.get_storage_at(acct, U256::ZERO).await?;
    ensure!(Address::from_word(slot0.into()) == seed.owner(owner_index)?.address());
    ensure!(account(&seed, 0)?.address() == acct);
    checks.push(json!({ "what": "the account is the seed's account 0, owned by the owner the backup names", "ok": true }));
    for t in latest["tickets"].as_array().context("tickets")? {
        let k = u32::try_from(t["k"].as_u64().context("k")?)?;
        let pm = &latest["paymasters"]
            .as_array()
            .context("paymasters")?
            .iter()
            .find(|p| p["address"] == t["paymaster"])
            .context("a ticket's paymaster is not listed")?;
        let key = G2::decode(unhex(pm["key"].as_str().context("key")?)?.as_slice())
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let claim = common::claim(&seed, chain_id, k, t["epoch"].as_u64().context("epoch")?)?;
        let sig = G1::decode(unhex(t["signature"].as_str().context("sig")?)?.as_slice())
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        ops::verify_message::<MinSig>(&key, NAMESPACE, &claim.message(), &sig)
            .map_err(|e| anyhow::anyhow!("ticket {k} from the backup does not verify: {e:?}"))?;
        let unspent = provider.get_transaction_count(claim.slot.sender).await? == 0;
        ensure!(unspent, "ticket {k} is spent");
        checks.push(json!({ "what": format!("ticket {k}, from the backup alone, verifies and is unspent"), "ok": true }));
    }
    for r in latest["received"].as_array().context("received")? {
        let s = Secrets {
            nullifier_secret: field(U256::from_be_slice(&unhex(
                r["nullifierSecret"].as_str().context("n")?,
            )?)),
            secret: field(U256::from_be_slice(&unhex(
                r["secret"].as_str().context("s")?,
            )?)),
        };
        let vault: Address = r["vault"].as_str().context("vault")?.parse()?;
        let scope_raw = provider
            .call(
                alloy::rpc::types::TransactionRequest::default()
                    .to(REGISTRY)
                    .input(
                        alloy::primitives::Bytes::from(alloy::sol_types::SolCall::abi_encode(
                            &registry_abi::scopeOfCall { vault },
                        ))
                        .into(),
                    ),
            )
            .await?;
        let scope = field(U256::from_be_slice(&scope_raw));
        let leaf = B256::from(custody::leaf(
            scope,
            s.inner(),
            r["state"].as_u64().context("state")?,
        ));
        let logs = provider
            .get_logs(
                &Filter::new()
                    .address(REGISTRY)
                    .event_signature(registry_abi::Inserted::SIGNATURE_HASH)
                    .topic1(B256::left_padding_from(vault.as_slice()))
                    .from_block(0),
            )
            .await?;
        let inserted = logs
            .iter()
            .filter_map(|l| registry_abi::Inserted::decode_log(&l.inner).ok())
            .any(|e| e.leaf == leaf);
        ensure!(
            inserted,
            "a received note from the backup is not in its vault"
        );
        checks.push(json!({ "what": "the received note's opening, from the backup alone, is a leaf of its vault", "ok": true }));
    }
    println!("{} checks against the chain passed", checks.len());

    // The leak.
    let (k0, l0) = backup::keys(&seed, 0);
    let (_, l1) = backup::keys(&seed, 1);
    let v1_posted = &board
        .iter()
        .find(|p| backup::is_at(&p.message, l1))
        .context("v1")?
        .message;
    let v0_posted = &board
        .iter()
        .find(|p| backup::is_at(&p.message, l0))
        .context("v0")?
        .message;
    let k0_opens_v0 = backup::open(&k0, l0, v0_posted).is_ok();
    let k0_opens_v1 = backup::open(&k0, l1, v1_posted).is_ok();
    let old: Vec<Share> = OLD_SET
        .iter()
        .map(|&g| share_of(g))
        .collect::<Result<_, _>>()?;
    let (old_seed, r0, old_envelope) = seed_from(&board, &old, &phrase)?;
    let old_opens = versions(&old_seed, &board).len();
    let history_in_latest = latest["history"].as_array().map_or(0, Vec::len);
    let leak = json!([
        { "leaked": "version 0's key", "opens": if k0_opens_v0 && !k0_opens_v1 { "version 0 only" } else { "unexpected" },
          "history": "every transaction before version 0 was written" },
        { "leaked": "the seed", "opens": "every version, every note, every ticket's link to its purchase, every announcement" },
        { "leaked": "an old guardian set (R0) and the phrase", "opens": format!("the seed, from its envelope still on the board ({old_envelope}), and so {old_opens} backup version(s)") },
        { "leaked": "the current guardian set and the phrase", "opens": "the same, as this reopening did" },
    ]);
    println!(
        "leak: version 0's key opens version 0 {k0_opens_v0}, version 1 {k0_opens_v1}; the old set R0 and the phrase open {old_opens} version(s); the latest version lists {history_in_latest} past transactions"
    );
    ensure!(k0_opens_v0 && !k0_opens_v1);

    // The metadata an observer has.
    let mut metadata = vec![];
    for (v, tx, _) in &found {
        let sender = rpc::transaction(provider, *tx)
            .await?
            .context("the post")?
            .sender;
        let receipt = rpc::receipt(provider, *tx).await?.context("receipt")?;
        // The wallet's own transaction just before the post, from the history the backup keeps.
        let mut before = None;
        for h in latest["history"].as_array().into_iter().flatten() {
            let Some(h) = h.as_str().and_then(|h| h.parse::<B256>().ok()) else {
                continue;
            };
            if h == *tx {
                continue;
            }
            if let Some(r) = rpc::receipt(provider, h).await?
                && r.block_number < receipt.block_number
                && before.is_none_or(|(b, _)| r.block_number > b)
            {
                before = Some((r.block_number, h));
            }
        }
        let buyers = buyers_of(provider, receipt.payer).await?;
        metadata.push(json!({
            "v": v,
            "tx": tx,
            "block": receipt.block_number,
            "sender": sender,
            "senderNonceNow": provider.get_transaction_count(sender).await?,
            "payer": receipt.payer,
            "payersBuyers": buyers,
            "postedBytes": board.iter().find(|p| p.tx == *tx).map(|p| p.message.len()),
            "walletTxBefore": before.map(|(b, h)| json!({ "block": b, "tx": h })),
        }));
    }
    let _ = (OVERHEAD, BUCKET, r2, r0);

    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "given": ["the phrase", "guardians 7 and 9's shares, off the chain"],
            "envelope": envelope_tx,
            "recoveryKey": r2,
            "versions": opened,
            "checks": checks,
            "leak": leak,
            "metadata": metadata,
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    Ok(())
}

/// Every buyer a ticket paymaster has had, from its `Bought` logs.
async fn buyers_of<P: Provider>(provider: &P, paymaster: Address) -> anyhow::Result<Vec<Address>> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(paymaster)
                .event_signature(Bought::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?;
    let mut out: Vec<Address> = vec![];
    for l in &logs {
        let b = Bought::decode_log(&l.inner)?.buyer;
        if !out.contains(&b) {
            out.push(b);
        }
    }
    Ok(out)
}
