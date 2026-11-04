//! `exp-frames` experiment 49: the wallet's keys in leanSPHINCS form, on the ethrex Hegota testnet
//! with EIP-8288 modelled (each account deployed with `Carrier::Modelled`: its triple travels in
//! its own `VERIFY` data, and the signature is checked here, off chain, with leanVM's verifier).
//!
//! ```text
//! SEED_FILE=... MODE=new cargo run --release -p kohaku-frame-pq --example pq_wallet
//! SEED_FILE=... RECORD=signer.json MODE=signer ...
//! SEED_FILE=... PRIVATE_KEY=0x... RECORD=account.json MODE=account ...
//! SEED_FILE=... PRIVATE_KEY=0x... RECORD=tickets.json MODE=tickets ...
//! ```
//!
//! Build with `RUSTFLAGS="-C target-cpu=native"` for comparable times.
//!
//! `MODE=new` writes a fresh mnemonic to `SEED_FILE` (mode 0600). `MODE=signer` (arm 1) times key
//! generation, signing and verification. `MODE=account` (arm 2): the funder deploys account 0
//! with owner `sphincs/account/0/owner/0` and funds it; the account posts to the board under
//! its owner's triple; then a transaction declaring owner 1's key must be refused.
//! `MODE=tickets` (arms 4 and 5), after `MODE=account`: account 0 deploys a leanSPHINCS bound
//! paymaster for a new committee, buys two tickets and deposits a pool note; the issuers answer
//! two blinded bound claims, each request signed by account 0's owner key; a fresh leanSPHINCS
//! sender deploys itself and posts, paid by one ticket; the note is withdrawn to a leanSPHINCS
//! recipient, the pool its own sender, paid by the other, after three copies are tried; the
//! recipient deploys itself and pays its own gas from what it received. `RUN=<r>` (default 0)
//! picks tickets `2r` and `2r + 1` and recipient `r`.
//!
//! No mnemonic, seed, secret key or signature is printed or recorded: the record keeps each
//! signature's keccak256 and whether it verified.

#[path = "../../frame-secrets/examples/common/mod.rs"]
mod common;

use std::{env, fs, time::Instant};

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use anyhow::{Context, ensure};
use common::{BOARD, TICKET_PRICE, TIP, executed, refused, send};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    group::G1,
    variant::{MinSig, PartialSignature},
};
use kohaku_frame_accounts::{
    builder::{Envelope, TxPlan},
    sponsor::Sponsor,
};
use kohaku_frame_kit::{
    Fees, Frame, FrameTx,
    constants::{STORAGE_SET_STATE_GAS, approve},
    gas::max_cost,
    rpc,
};
use kohaku_frame_pool::{
    prove,
    withdrawal::{
        DENOMINATION, FramePool, PoolMode, WITHDRAW_EXECUTION, abi::depositCall, recent_root_frame,
        withdraw_calldata,
    },
};
use kohaku_frame_pq::{
    PUBLIC_KEY_LEN, SIGNATURE_LEN, SphincsKey,
    account::{Acting, Carrier, Fresh, Role, SphincsAccount, SphincsSender, Witness, witnesses},
    binder, owner, recipient, sender,
    ticket::{PqBoundClaim, PqBoundTicket, PqBoundTicketPaymaster},
    verify,
};
use kohaku_frame_ticket::{
    Claim, Committee, Slot, blind,
    issuers::{Count, Ledger, request_id},
    ticket::{NAMESPACE, epoch_of},
};
use kohaku_frame_wallet::recovery::{pool_events, root_slot};
use kohaku_tornadocash::{Note, Payer, merkle_tree::MerkleTree, syncer::SyncEvent};
use rand::RngExt;
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

/// Experiment 06's keyed pool.
const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");
/// The tip of the withdrawal and its copies, low enough that one ticket covers the max cost.
const WITHDRAWAL_TIP: u128 = 100_000_000;
const POOL_VERIFY: u64 = 260_000;

fn pool() -> FramePool {
    FramePool {
        address: KEYED_POOL,
        mode: PoolMode::Keyed,
        salt: keccak256("exp-frames/06/pool-keyed"),
    }
}

/// Pays with a bound ticket: its pay frame, and no signature entry.
struct PqSponsor(Frame);

impl Sponsor for PqSponsor {
    fn payment_frames(&self) -> Vec<Frame> {
        vec![self.0.clone()]
    }
}

/// A fresh sender or recipient, as this experiment deploys it on the test network.
fn fresh(seed: &Seed, label: &str, key: &SphincsKey) -> SphincsSender {
    SphincsSender {
        key: key.public_key(),
        carrier: Carrier::Modelled,
        salt: B256::from(seed.key(&format!("{label}/salt"))),
    }
}

/// What the issuers do with one blinded point. The request is signed by account 0's owner key
/// with leanSPHINCS; each issuer checks it against the key account 0 holds, and counts the
/// request against account 0's purchases. Three of four answer.
fn issue(
    committee: &mut Committee,
    ledger: &mut Ledger,
    buyer: Address,
    buyer_key: &SphincsKey,
    held: B256,
    blinded: &G1,
    left_out: usize,
) -> anyhow::Result<(Vec<PartialSignature<MinSig>>, Value)> {
    let digest = keccak256([b"kohaku-ticket-request".as_slice(), &blinded.encode()].concat());
    let request = buyer_key.sign(digest)?;
    ensure!(verify(held, digest, &request)?, "the request does not verify under account 0's key");
    let mut answers = vec![];
    for (i, issuer) in committee.issuers.iter_mut().enumerate() {
        if i == left_out {
            continue;
        }
        ledger.admit(Count::Shared, i, buyer, request_id(blinded))?;
        let a = issuer.answer(blinded);
        blind::check_answer(&committee.sharing, blinded, &a)
            .map_err(|e| anyhow::anyhow!("an answer does not check: {e:?}"))?;
        answers.push(a);
    }
    let seen = json!({ "blinded": format!("0x{}", common::hex(&blinded.encode())), "requestKeccak": keccak256(&request) });
    Ok((answers, seen))
}

/// A ticket-paid withdrawal of `note` to `to`, laid out as experiment 48's: the recent root, the
/// pool's `VERIFY`, the paymaster's `VERIFY` with `pay`, and the payout. No one signs it.
#[allow(clippy::too_many_arguments)]
async fn withdrawal<P: Provider>(
    provider: &P,
    chain_id: u64,
    note: Note,
    leaf: usize,
    deposit_block: u64,
    to: Address,
    pay: Frame,
    fees: Fees,
) -> anyhow::Result<FrameTx> {
    let p = pool();
    let leaves = kohaku_frame_pool::chain::leaves(provider, KEYED_POOL, leaf).await?;
    let root = B256::from(MerkleTree::from_leaves(&leaves)?.root()?);
    let slot = root_slot(provider, KEYED_POOL, deposit_block, root)
        .await?
        .context("no EIP-8272 slot for the root")?;
    let payer = Payer { address: pay.target.context("a paymaster")?, fee: U256::ZERO, refund: U256::ZERO };
    let proof = prove(note, &leaves, to, payer, &mut rand::rng())?;
    let tx = FrameTx {
        chain_id,
        nonce_keys: vec![U256::from_be_bytes(proof.inputs.nullifier_hash.0)],
        nonce_seq: 0,
        sender: p.address,
        frames: vec![
            recent_root_frame(p.source_id(), slot, proof.inputs.root),
            Frame::verify(approve::EXECUTION, None).with_execution(POOL_VERIFY),
            pay.with_state(STORAGE_SET_STATE_GAS),
            Frame::sender(Some(p.address))
                .with_execution(WITHDRAW_EXECUTION)
                .with_state(p.withdraw_state_floor(false))
                .with_data(withdraw_calldata(&proof.inputs, &proof.proof)),
        ],
        signatures: vec![],
        fees,
        blob_versioned_hashes: vec![],
    };
    ensure!(max_cost(&tx, 0)? <= TICKET_PRICE, "a withdrawal costs more than a ticket");
    Ok(tx)
}

/// Arms 4 and 5.
#[allow(clippy::too_many_lines)]
#[allow(clippy::many_single_char_names)]
async fn tickets<P: Provider>(provider: &P) -> anyhow::Result<()> {
    let seed = load_seed()?;
    let funder = PrivateKeySigner::from_bytes(&env::var("PRIVATE_KEY").context("PRIVATE_KEY")?.parse()?)?;
    let chain_id = provider.get_chain_id().await?;
    let owner0 = owner(&seed, 0, 0);
    let acct = account0(&seed, &owner0);
    ensure!(!provider.get_code_at(acct.address()).await?.is_empty(), "run MODE=account first");
    let by_owner = Acting { account: &acct, role: Role::Owner(&owner0) };
    // Each run takes its own tickets and recipient: a fresh sender's address is fixed by its label.
    let run: u32 = env::var("RUN").map_or(Ok(0), |r| r.parse())?;
    let (k_fresh, k_pool) = (2 * run, 2 * run + 1);
    let mut rng = rand::rng();
    let mut steps = vec![];

    // 1. A committee, its paymaster, two tickets bought and a note deposited by account 0.
    steps.push(
        send(
            provider,
            &funder,
            vec![Frame::sender(Some(acct.address())).with_value(U256::from(20_000_000_000_000_000u64)).with_execution(10_000)],
            "the funder tops up account 0",
        )
        .await?,
    );
    let mut committee = Committee::dkg(&mut rng, common::ISSUERS)?;
    let pm = PqBoundTicketPaymaster {
        key: *committee.sharing.public(),
        denomination: TICKET_PRICE,
        carrier: Carrier::Modelled,
        salt: B256::from(rng.random::<[u8; 32]>()),
    };
    let note: Note = rng.random();
    let deposit = Frame::sender(Some(KEYED_POOL))
        .with_value(U256::from(DENOMINATION))
        .with_data(depositCall { commitment: B256::from(note.commitment()) }.abi_encode())
        .with_execution(1_500_000)
        .with_state(3_000_000);
    let envelope = Envelope::fetch(provider, acct.address(), vec![U256::ZERO], TIP).await?;
    let tx = TxPlan::new(&by_owner)
        .calls([pm.deploy_frame(), pm.buy_frame(2), deposit])
        .build(&envelope)?;
    let w = witnesses(&tx, &by_owner.keys())?;
    let mut s = mined(provider, &tx, "account 0 deploys the leanSPHINCS bound paymaster, buys 2 tickets and deposits a note").await?;
    s["witnesses"] = Value::Array(w.iter().map(witness_json).collect::<Result<_, _>>()?);
    let block = s["block"].as_str().map_or(Ok(0), |b| u64::from_str_radix(b.trim_start_matches("0x"), 16))?;
    steps.push(s);
    let leaf = pool_events(provider, KEYED_POOL, block)
        .await?
        .into_iter()
        .find_map(|e| match e {
            SyncEvent::Deposit(d) if d.commitment == note.commitment() => Some(d),
            _ => None,
        })
        .context("the deposit's event")?;

    // 2. Issuance: two bound claims, blinded; the issuers see random points and a request.
    let fresh_key = sender(&seed, k_fresh);
    let fresh_acct = fresh(&seed, &format!("sphincs/ticket/{k_fresh}/sender"), &fresh_key);
    let to_key = recipient(&seed, run);
    let to_acct = fresh(&seed, &format!("sphincs/recipient/{run}"), &to_key);
    let head = provider.get_block_by_number(alloy::eips::BlockNumberOrTag::Latest).await?.context("no head")?;
    let epoch = epoch_of(head.header.timestamp);
    let mut ledger = Ledger::new([(acct.address(), 2)].into());
    let slots = [
        Slot { chain_id, sender: fresh_acct.address(), nonce_keys: vec![U256::ZERO], nonce_seq: 0 },
        Slot {
            chain_id,
            sender: KEYED_POOL,
            nonce_keys: vec![U256::from_be_bytes(B256::from(note.nullifier_hash()).0)],
            nonce_seq: 0,
        },
    ];
    let mut tickets = vec![];
    let mut issuers_saw = vec![];
    for (k, slot) in [k_fresh, k_pool].into_iter().zip(slots) {
        let secrets = seed.ticket(k)?;
        let c = PqBoundClaim {
            claim: Claim { slot, epoch, salt: secrets.salt },
            binder: binder(&seed, k).public_key(),
        };
        let (blinded, blinding) = blind::blind_with(secrets.blinding, NAMESPACE, &c.message()).context("zero")?;
        let (answers, request) = issue(&mut committee, &mut ledger, acct.address(), &owner0, owner0.public_key(), &blinded, k as usize % 4)?;
        issuers_saw.push(request);
        let t = PqBoundTicket {
            claim: c,
            signature: blind::unblind(&committee.sharing, &answers, &blinding).map_err(|e| anyhow::anyhow!("{e:?}"))?,
        };
        t.verify(&committee.sharing).map_err(|e| anyhow::anyhow!("{e:?}"))?;
        tickets.push(t);
    }
    println!("two bound tickets issued");

    // 3. The fresh sender: deploys itself, posts, paid by ticket 0.
    let mut spends = vec![];
    {
        let b = binder(&seed, k_fresh);
        let mut sponsor = PqSponsor(pm.pay_frame(&tickets[0], &b, 0));
        let f = Fresh { sender: &fresh_acct, key: &fresh_key, deploy: true };
        let fees = rpc::suggest_fees(provider, TIP).await?;
        let tx = TxPlan::new(&f)
            .sponsored_by(&mut sponsor)
            .call(post_frame(BOARD, b"paid with a leanSPHINCS-bound ticket"))
            .build(&Envelope { chain_id, nonce_keys: vec![U256::ZERO], nonce_seq: 0, fees })?;
        let w = witnesses(&tx, &[&fresh_key, &b])?;
        let mut s = mined(provider, &tx, "a fresh leanSPHINCS sender deploys itself and posts, paid by a bound ticket").await?;
        s["witnesses"] = Value::Array(w.iter().map(witness_json).collect::<Result<_, _>>()?);
        spends.push(s);
    }

    // 4. The withdrawal to the leanSPHINCS recipient, paid by ticket 1; its copies first.
    let pool_binder = binder(&seed, k_pool);
    let wfees = rpc::suggest_fees(provider, WITHDRAWAL_TIP).await?;
    let original = withdrawal(provider, chain_id, note.clone(), leaf.leaf_index as usize, leaf.block_number, to_acct.address(), pm.pay_frame(&tickets[1], &pool_binder, 0), wfees).await?;
    let w = witnesses(&original, &[&pool_binder])?;
    let mut copies = vec![];
    {
        // (a) Fees raised by the replacement bump, the triple kept. Modelled, nothing on chain
        // checks the binder's signature, so the node is expected to accept it: it is simulated
        // only, never sent, and the binder's signature is checked against its hash here.
        let mut c = original.clone();
        c.fees.max_priority_fee_per_gas += c.fees.max_priority_fee_per_gas / 10;
        c.fees.max_fee_per_gas += c.fees.max_fee_per_gas / 10;
        let sim = rpc::simulate(provider, &c, "latest").await?;
        let holds = verify(pool_binder.public_key(), c.sig_hash(), &w[0].signature)?;
        println!("copy (a): simulation valid {}; the binder's signature over its hash verifies: {holds}", sim.valid);
        copies.push(json!({
            "what": "fees raised, the triple kept (simulated only, not sent)",
            "hash": c.hash(), "raw": c.encode(),
            "simulation": { "valid": sim.valid, "violation": sim.violation },
            "binderSignatureVerifiesOverCopy": holds,
        }));
    }
    {
        // (b) The triple removed: 200 bytes of pay data.
        let mut c = original.clone();
        c.frames[2].data = c.frames[2].data.slice(..200);
        copies.push(refused(provider, &c, "copy (b): the binder's triple removed").await?);
    }
    {
        // (c) Another key named and declared, with its own signature.
        let other = binder(&seed, 99);
        let mut c = original.clone();
        let mut data = c.frames[2].data.to_vec();
        data[40..72].copy_from_slice(other.public_key().as_slice());
        data[200..].copy_from_slice(&other.triple());
        c.frames[2].data = data.into();
        let wc = witnesses(&c, &[&other])?;
        let mut r = refused(provider, &c, "copy (c): another key named, declared and signing").await?;
        r["witnesses"] = Value::Array(wc.iter().map(witness_json).collect::<Result<_, _>>()?);
        copies.push(r);
    }
    let mut s = mined(provider, &original, "the withdrawal to a leanSPHINCS recipient, the pool its own sender, paid by a bound ticket").await?;
    s["witnesses"] = Value::Array(w.iter().map(witness_json).collect::<Result<_, _>>()?);
    spends.push(s);

    // 5. The recipient deploys itself and pays its own gas from what it received.
    {
        let deploy = provider.get_code_at(to_acct.address()).await?.is_empty();
        let f = Fresh { sender: &to_acct, key: &to_key, deploy };
        // At the withdrawal's tip: the recipient holds one note, 0.001 ETH, and pays a
        // self-deployment's gas from it before it sends a tenth back.
        let envelope = Envelope::fetch(provider, to_acct.address(), vec![U256::ZERO], WITHDRAWAL_TIP).await?;
        let tx = TxPlan::new(&f)
            .call(Frame::sender(Some(funder.address())).with_value(U256::from(DENOMINATION / 10)).with_execution(10_000))
            .build(&envelope)?;
        let w = witnesses(&tx, &[&to_key])?;
        let mut s = mined(provider, &tx, "the leanSPHINCS recipient deploys itself and sends a tenth back, paying its own gas").await?;
        s["witnesses"] = Value::Array(w.iter().map(witness_json).collect::<Result<_, _>>()?);
        spends.push(s);
    }

    let record = json!({
        "arm": [4, 5],
        "run": run,
        "chain": "ethrex Hegota testnet, EIP-8288 modelled",
        "committeeKey": format!("0x{}", common::hex(&committee.sharing.public().encode())),
        "epoch": epoch,
        "paymaster": pm.address(),
        "account": acct.address(),
        "freshSender": fresh_acct.address(),
        "recipient": to_acct.address(),
        "tickets": tickets.iter().map(|t| json!({ "sender": t.claim.claim.slot.sender, "binder": t.claim.binder, "point": format!("0x{}", common::hex(&t.claim.point().encode())) })).collect::<Vec<_>>(),
        "issuers": issuers_saw,
        "steps": steps,
        "spends": spends,
        "copies": copies,
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
        "tickets" => tickets(&provider).await,
        other => anyhow::bail!("MODE {other}?"),
    }
}
