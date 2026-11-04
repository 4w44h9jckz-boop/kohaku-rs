//! `exp-frames` experiment 49: the wallet's keys in leanSPHINCS form, on the ethrex Hegota testnet
//! with EIP-8288 modelled (each account deployed with `Carrier::Modelled`: its triple travels in
//! its own `VERIFY` data, and the signature is checked here, off chain, with leanVM's verifier).
//!
//! ```text
//! SEED_FILE=... MODE=new cargo run --release -p kohaku-frame-pq --example pq_wallet
//! SEED_FILE=... RECORD=signer.json MODE=signer ...
//! SEED_FILE=... PRIVATE_KEY=0x... RECORD=account.json MODE=account ...
//! ```
//!
//! Build with `RUSTFLAGS="-C target-cpu=native"` for comparable times.
//!
//! `MODE=new` writes a fresh mnemonic to `SEED_FILE` (mode 0600). `MODE=signer` (arm 1) times key
//! generation, signing and verification. `MODE=account` (arm 2): the funder deploys account 0
//! with owner `sphincs/account/0/owner/0` and funds it; the account posts to the board under
//! its owner's triple; then a transaction declaring owner 1's key must be refused.
//!
//! No mnemonic, seed, secret key or signature is printed or recorded: the record keeps each
//! signature's keccak256 and whether it verified.

#[path = "../../frame-secrets/examples/common/mod.rs"]
mod common;

use std::{env, fs, time::Instant};

use alloy::{
    primitives::{B256, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use common::{BOARD, TIP, executed, refused, send};
use kohaku_frame_accounts::builder::{Envelope, TxPlan};
use kohaku_frame_kit::{Frame, FrameTx, rpc};
use kohaku_frame_pq::{
    PUBLIC_KEY_LEN, SIGNATURE_LEN, SphincsKey,
    account::{Acting, Carrier, Role, SphincsAccount, Witness, witnesses},
    owner, verify,
};
use kohaku_frame_registry::announce::post_frame;
use kohaku_frame_secrets::Seed;
use serde_json::{Value, json};

const DELAY: u64 = 120;

fn load_seed() -> anyhow::Result<Seed> {
    let path = env::var("SEED_FILE").context("SEED_FILE")?;
    Ok(Seed::from_mnemonic(fs::read_to_string(path)?.trim())?)
}

fn write_record(record: &Value) -> anyhow::Result<()> {
    if let Ok(path) = env::var("RECORD") {
        fs::write(&path, serde_json::to_string_pretty(record)? + "\n")?;
        println!("record: {path}");
    }
    Ok(())
}

/// What a record keeps of a witness: never the signature itself.
fn witness_json(w: &Witness) -> anyhow::Result<Value> {
    Ok(json!({
        "key": w.key,
        "message": w.message,
        "signatureBytes": w.signature.len(),
        "signatureKeccak": keccak256(&w.signature),
        "verified": verify(w.key, w.message, &w.signature)?,
    }))
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

/// Arm 1: the signer on this machine.
fn signer() -> anyhow::Result<()> {
    let seed = load_seed()?;
    let (mut keygen, mut sign, mut check) = (vec![], vec![], vec![]);
    for j in 0..9u32 {
        let t = Instant::now();
        let key = owner(&seed, 9, j);
        keygen.push(t.elapsed().as_secs_f64() * 1e3);
        let m = keccak256(j.to_be_bytes());
        let t = Instant::now();
        let s = key.sign(m)?;
        sign.push(t.elapsed().as_secs_f64() * 1e3);
        let t = Instant::now();
        ensure!(verify(key.public_key(), m, &s)?, "a signature did not verify");
        check.push(t.elapsed().as_secs_f64() * 1e3);
        ensure!(!verify(key.public_key(), keccak256(m), &s)?, "a signature verified another message");
    }
    let threads = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
    let record = json!({
        "arm": 1,
        "leanVM": "3cbac047160f4d1465bfe985521603b0a3418556",
        "threads": threads,
        "publicKeyBytes": PUBLIC_KEY_LEN,
        "signatureBytes": SIGNATURE_LEN,
        "keygenMs": keygen, "signMs": sign, "verifyMs": check,
        "medianMs": { "keygen": median(keygen.clone()), "sign": median(sign.clone()), "verify": median(check.clone()) },
    });
    println!("{}", serde_json::to_string(&record["medianMs"])?);
    write_record(&record)
}

/// [`executed`], and each frame's gas and status.
async fn mined<P: Provider>(provider: &P, tx: &FrameTx, what: &str) -> anyhow::Result<Value> {
    let mut v = executed(provider, tx, what).await?;
    let r = rpc::receipt(provider, tx.hash()).await?.context("no receipt")?;
    v["frames"] = Value::Array(
        r.frame_receipts
            .iter()
            .map(|f| json!({ "gasUsed": f.gas_used, "stateGasUsed": f.state_gas_used, "status": f.status }))
            .collect(),
    );
    Ok(v)
}

/// Account 0, as this experiment deploys it on the test network.
fn account0(seed: &Seed, owner_key: &SphincsKey) -> SphincsAccount {
    SphincsAccount {
        owner: owner_key.public_key(),
        commitment: B256::ZERO,
        delay: DELAY,
        lower_bound: false,
        carrier: Carrier::Modelled,
        salt: B256::from(seed.key("sphincs/account/0/salt")),
    }
}

/// A transaction from `acting`, posting `message`, and its witnesses.
async fn acting_tx<P: Provider>(
    provider: &P,
    acting: &Acting<'_>,
    message: &[u8],
) -> anyhow::Result<(FrameTx, Vec<Witness>)> {
    let envelope = Envelope::fetch(provider, acting.account.address(), vec![U256::ZERO], TIP).await?;
    let tx = TxPlan::new(acting).call(post_frame(BOARD, message)).build(&envelope)?;
    let w = witnesses(&tx, &acting.keys())?;
    Ok((tx, w))
}

/// Arm 2: the account.
async fn account<P: Provider>(provider: &P) -> anyhow::Result<()> {
    let seed = load_seed()?;
    let funder = PrivateKeySigner::from_bytes(&env::var("PRIVATE_KEY").context("PRIVATE_KEY")?.parse()?)?;
    let owner0 = owner(&seed, 0, 0);
    let owner1 = owner(&seed, 0, 1);
    let acct = account0(&seed, &owner0);
    let mut steps = vec![];
    if provider.get_code_at(acct.address()).await?.is_empty() {
        steps.push(
            send(
                provider,
                &funder,
                vec![
                    acct.deploy_frame(),
                    Frame::sender(Some(acct.address()))
                        .with_value(U256::from(10_000_000_000_000_000u64))
                        .with_execution(10_000),
                ],
                "the funder deploys account 0, owner sphincs/account/0/owner/0, and funds it",
            )
            .await?,
        );
    }
    let slot0 = provider.get_storage_at(acct.address(), U256::ZERO).await?;
    ensure!(B256::from(slot0) == owner0.public_key(), "slot 0 is not owner 0's key");

    // The owner's transaction, its triple in the VERIFY data, its signature checked here.
    let by_owner = Acting { account: &acct, role: Role::Owner(&owner0) };
    let (tx, w) = acting_tx(provider, &by_owner, b"account 0, leanSPHINCS owner 0").await?;
    let mut ok = mined(provider, &tx, "account 0, authorised by owner 0's leanSPHINCS triple").await?;
    ok["witnesses"] = Value::Array(w.iter().map(witness_json).collect::<Result<_, _>>()?);
    steps.push(ok);

    // Owner 1's key is not the account's: VERIFY must refuse.
    let by_other = Acting { account: &acct, role: Role::Owner(&owner1) };
    let (tx, _) = acting_tx(provider, &by_other, b"account 0, the wrong key").await?;
    let wrong = refused(provider, &tx, "account 0, a triple naming owner 1's key").await?;

    let record = json!({
        "arm": 2,
        "chain": "ethrex Hegota testnet, EIP-8288 modelled",
        "account": acct.address(),
        "ownerKey": owner0.public_key(),
        "steps": steps,
        "refused": [wrong],
    });
    write_record(&record)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    match env::var("MODE").context("MODE")?.as_str() {
        "new" => {
            use std::os::unix::fs::OpenOptionsExt;
            let path = env::var("SEED_FILE").context("SEED_FILE")?;
            let (words, _) = Seed::generate(&mut rand::rng())?;
            let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path)?;
            std::io::Write::write_all(&mut f, format!("{words}\n").as_bytes())?;
            println!("a fresh mnemonic is in SEED_FILE");
            Ok(())
        }
        "signer" => signer(),
        "account" => account(&provider).await,
        other => anyhow::bail!("MODE {other}?"),
    }
}
