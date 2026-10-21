//! A blind ticket bound to the transaction it pays for: `exp-frames` experiment 48, on the
//! ethrex Hegota testnet, with experiment 45's seed.
//!
//! ```text
//! SEED_FILE=... PRIVATE_KEY=0x... RECORD=record48.json \
//!   cargo run --release -p kohaku-frame-secrets --example bound_ticket
//! ```
//!
//! 1. A new committee backs two paymasters with one key: experiment 36's, and the bound one.
//!    Owner 0 deploys both, buys two tickets on each, and deposits two notes into experiment 06's
//!    keyed pool.
//! 2. Four tickets are issued blind, every secret from the seed: for fresh senders, one unbound
//!    and one bound; and for the pool's slot of each note, one unbound and one bound. A bound
//!    ticket's one-time key is `ticket/<k>/binder`.
//! 3. The two fresh senders spend, for the gas of the binding.
//! 4. The unbound control: note 1's withdrawal, paid by its unbound ticket, is sent, then a copy
//!    with its fees raised by the replacement bump, which no one needs to sign.
//! 5. The bound withdrawal of note 2 is sent, then three copies: fees raised with the one-time
//!    key's signature kept; the same with that entry removed; and the same re-signed by another
//!    key named in the frame's data. Each must be refused; the original must be mined.
//!
//! The record keeps every transaction, what the issuers saw, and the template's length and
//! keccak256. No key, mnemonic or blinding factor.

mod common;

use std::{env, fs};

use alloy::{
    primitives::{Address, B256, Bytes, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
};
use anyhow::{Context, ensure};
use common::{TICKET_PRICE, executed, hex, load_seed, send};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    group::G1,
    variant::{MinSig, PartialSignature},
};
use kohaku_frame_accounts::{
    account::{Eoa, Signer},
    builder::{Envelope, TxPlan},
};
use kohaku_frame_kit::{
    Fees, Frame, FrameSigner, FrameTx,
    constants::{STORAGE_SET_STATE_GAS, approve},
    gas::max_cost,
    rpc, sign_all,
};
use kohaku_frame_pool::{
    chain, prove,
    withdrawal::{FramePool, PoolMode, WITHDRAW_EXECUTION, recent_root_frame, withdraw_calldata},
};
use kohaku_frame_secrets::Seed;
use kohaku_frame_ticket::{
    Claim, Committee, Slot, Ticket, TicketPaymaster, TicketSponsor, blind,
    bound::{BoundClaim, BoundTicket, BoundTicketPaymaster, BoundTicketSponsor, binder_entry},
    issuers::{Count, Ledger, request_id},
    ticket::{NAMESPACE, epoch_of},
};
use kohaku_frame_wallet::recovery::{keychain_pool, pool_events, root_slot};
use kohaku_tornadocash::{Payer, merkle_tree::MerkleTree};
use kohaku_tornadocash_keychain::{Keychain, recovery::next_nonce};
use rand::RngExt;
use serde_json::{Value, json};

const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");
/// The seed's tickets this run uses: experiments 45 to 47 used 0 to 6.
const FIRST: u32 = 7;
/// Fresh sender, bound; pool slot, bound; fresh sender, unbound; pool slot, unbound.
const K_FRESH_BOUND: u32 = FIRST;
const K_POOL_BOUND: u32 = FIRST + 1;
const K_FRESH_UNBOUND: u32 = FIRST + 2;
const K_POOL_UNBOUND: u32 = FIRST + 3;
const TIP: u128 = common::TIP;
/// A withdrawal's tip: low, so that its max cost stays under one ticket.
const WITHDRAWAL_TIP: u128 = 100_000_000;
/// The pool's `VERIFY` uses 244,808 (experiment 06); the ticket's about 122,000 (experiment 36).
const POOL_VERIFY: u64 = 260_000;
const PAY_VERIFY: u64 = 135_000;
const OWNER_TOP_UP: U256 = U256::from_limbs([50_000_000_000_000_000, 0, 0, 0]);
const BOUND_TAG: &[u8] = b"paid with a bound ticket";
const UNBOUND_TAG: &[u8] = b"paid with an unbound ticket";

fn pool() -> FramePool {
    FramePool {
        address: KEYED_POOL,
        mode: PoolMode::Keyed,
        salt: keccak256("exp-frames/06/pool-keyed"),
    }
}

/// What the issuers do with one blinded point: three answers, each checked.
fn issue(
    committee: &mut Committee,
    ledger: &mut Ledger,
    buyer: &PrivateKeySigner,
    blinded: &G1,
    left_out: usize,
) -> anyhow::Result<Vec<PartialSignature<MinSig>>> {
    let digest = keccak256([b"kohaku-ticket-request".as_slice(), &blinded.encode()].concat());
    let request = buyer.sign_hash_sync(&digest)?;
    let mut answers = vec![];
    for (i, issuer) in committee.issuers.iter_mut().enumerate() {
        if i == left_out {
            continue;
        }
        ledger.admit(
            Count::Shared,
            i,
            request.recover_address_from_prehash(&digest)?,
            request_id(blinded),
        )?;
        let a = issuer.answer(blinded);
        blind::check_answer(&committee.sharing, blinded, &a)
            .map_err(|e| anyhow::anyhow!("an answer does not check: {e:?}"))?;
        answers.push(a);
    }
    Ok(answers)
}

/// A ticket-paid withdrawal of `note`, laid out by hand as frame-pool's sponsored layout: the
/// recent root, the pool's `VERIFY` approving execution, the paymaster's `VERIFY` approving
/// payment with `pay_data`, and the payout. No one signs it; a bound ticket adds its binder.
struct Withdrawal {
    tx: FrameTx,
}

#[allow(clippy::too_many_arguments)]
async fn withdrawal<P: Provider>(
    provider: &P,
    chain_id: u64,
    note: kohaku_tornadocash::Note,
    leaf: usize,
    deposit_block: u64,
    recipient: Address,
    paymaster: Address,
    pay_data: Vec<u8>,
    fees: Fees,
) -> anyhow::Result<Withdrawal> {
    let p = pool();
    let leaves = chain::leaves(provider, KEYED_POOL, leaf).await?;
    let root = B256::from(MerkleTree::from_leaves(&leaves)?.root()?);
    let slot = root_slot(provider, KEYED_POOL, deposit_block, root)
        .await?
        .context("no EIP-8272 slot for the root")?;
    // The paymaster takes no fee from the note: the ticket paid for the gas.
    let payer = Payer {
        address: paymaster,
        fee: U256::ZERO,
        refund: U256::ZERO,
    };
    let proof = prove(note, &leaves, recipient, payer, &mut rand::rng())?;
    let tx = FrameTx {
        chain_id,
        nonce_keys: vec![U256::from_be_bytes(proof.inputs.nullifier_hash.0)],
        nonce_seq: 0,
        sender: p.address,
        frames: vec![
            recent_root_frame(p.source_id(), slot, proof.inputs.root),
            Frame::verify(approve::EXECUTION, None).with_execution(POOL_VERIFY),
            Frame::verify(approve::PAYMENT, Some(paymaster))
                .with_data(pay_data)
                .with_execution(PAY_VERIFY)
                .with_state(STORAGE_SET_STATE_GAS),
            Frame::sender(Some(p.address))
                .with_execution(WITHDRAW_EXECUTION)
                .with_state(p.withdraw_state_floor(false))
                .with_data(withdraw_calldata(&proof.inputs, &proof.proof)),
        ],
        signatures: vec![],
        fees,
        blob_versioned_hashes: vec![],
    };
    ensure!(
        max_cost(&tx, 0)? <= TICKET_PRICE,
        "a withdrawal costs more than a ticket"
    );
    Ok(Withdrawal { tx })
}

/// Simulate, then send: the node's two answers to a transaction.
async fn try_send<P: Provider>(provider: &P, tx: &FrameTx, what: &str) -> anyhow::Result<Value> {
    let simulated = rpc::simulate(provider, tx, "latest").await?;
    let sent = match rpc::send(provider, tx).await {
        Ok(hash) => json!({ "result": hash }),
        Err(e) => json!({ "error": e.to_string() }),
    };
    println!(
        "{what}: simulation valid {}, {:?}; sent: {sent}",
        simulated.valid, simulated.violation
    );
    Ok(json!({
        "what": what,
        "hash": tx.hash(),
        "raw": tx.encode(),
        "simulation": { "valid": simulated.valid, "violation": simulated.violation },
        "sent": sent,
    }))
}

async fn mined<P: Provider>(provider: &P, tx: &FrameTx, what: &str) -> anyhow::Result<Value> {
    let r = rpc::wait_for_confirmed_receipt(
        provider,
        tx.hash(),
        std::time::Duration::from_mins(3),
        std::time::Duration::from_secs(2),
    )
    .await?;
    println!(
        "{what}: {} mined in {}, gasUsed {}, payer {}",
        tx.hash(),
        r.block_number,
        r.gas_used,
        r.payer
    );
    Ok(json!({
        "what": what,
        "hash": tx.hash(),
        "raw": tx.encode(),
        "block": r.block_number,
        "gasUsed": r.gas_used,
        "payer": r.payer,
        "frames": r.frame_receipts.iter().map(|f| json!({
            "status": f.status, "gasUsed": f.gas_used, "stateGasUsed": f.state_gas_used,
        })).collect::<Vec<_>>(),
    }))
}

#[allow(clippy::too_many_lines)]
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let funder: PrivateKeySigner = env::var("PRIVATE_KEY").context("PRIVATE_KEY")?.parse()?;
    let seed: Seed = load_seed()?;
    let chain_id = provider.get_chain_id().await?;
    let owner = seed.owner(0)?;
    let mut rng = rand::rng();
    let mut steps = vec![];

    // 1. Two paymasters for one committee; tickets; two notes.
    steps.push(
        send(
            &provider,
            &funder,
            vec![
                Frame::sender(Some(owner.address()))
                    .with_value(OWNER_TOP_UP)
                    .with_execution(10_000),
            ],
            "the funder tops up owner 0",
        )
        .await?,
    );
    let mut committee = Committee::dkg(&mut rng, common::ISSUERS)?;
    let key = *committee.sharing.public();
    let bound_pm = BoundTicketPaymaster {
        key,
        denomination: TICKET_PRICE,
        salt: B256::from(rng.random::<[u8; 32]>()),
    };
    let unbound_pm = TicketPaymaster {
        key,
        denomination: TICKET_PRICE,
        salt: B256::from(rng.random::<[u8; 32]>()),
    };
    steps.push(
        send(
            &provider,
            &owner,
            vec![
                bound_pm.deploy_frame(),
                unbound_pm.deploy_frame(),
                bound_pm.buy_frame(2),
                unbound_pm.buy_frame(2),
            ],
            "owner 0 deploys the bound and the unbound paymaster for one committee, buys 2 on each",
        )
        .await?,
    );
    let kpool = keychain_pool(&pool(), chain_id, 0);
    let keychain = seed.keychain()?;
    let mut notes = vec![];
    for _ in 0..2 {
        let events = pool_events(&provider, KEYED_POOL, 0).await?;
        let nonce = next_nonce(&keychain, &kpool, &events, None).await?;
        let note = keychain.note(&kpool, nonce).await?.note;
        let d = chain::deposit(
            &provider,
            &pool(),
            &FrameSigner::Secp256k1(owner.clone()),
            &note,
        )
        .await?;
        println!(
            "pool note {nonce}: block {}, leaf {}",
            d.receipt.block_number, d.leaf_index
        );
        steps.push(json!({
            "what": format!("owner 0 deposits keychain note {nonce}"),
            "hash": d.receipt.transaction_hash, "block": d.receipt.block_number, "leaf": d.leaf_index,
        }));
        notes.push((note, d.leaf_index, d.receipt.block_number.to::<u64>()));
    }

    // 2. Issuance. The pool's slot is the note's nullifier as its one nonce key, at 0.
    let slot_of = |k: u32, pool_note: Option<&kohaku_tornadocash::Note>| -> anyhow::Result<Slot> {
        Ok(match pool_note {
            None => Slot {
                chain_id,
                sender: seed.ticket(k)?.sender.address(),
                nonce_keys: vec![U256::ZERO],
                nonce_seq: 0,
            },
            Some(n) => Slot {
                chain_id,
                sender: KEYED_POOL,
                nonce_keys: vec![U256::from_be_bytes(B256::from(n.nullifier_hash()).0)],
                nonce_seq: 0,
            },
        })
    };
    let head = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await?
        .context("no head")?;
    let epoch = epoch_of(head.header.timestamp);
    let mut ledger = Ledger::new([(owner.address(), 4)].into());
    let claim = |k: u32, slot: Slot| -> anyhow::Result<Claim> {
        Ok(Claim {
            slot,
            epoch,
            salt: seed.ticket(k)?.salt,
        })
    };
    let mut bound = vec![];
    for (k, n) in [(K_FRESH_BOUND, None), (K_POOL_BOUND, Some(&notes[1].0))] {
        let c = BoundClaim {
            claim: claim(k, slot_of(k, n)?)?,
            binder: seed.binder(k)?.address(),
        };
        let r = seed.ticket(k)?.blinding;
        let (blinded, blinding) = blind::blind_with(r, NAMESPACE, &c.message()).context("zero")?;
        let answers = issue(
            &mut committee,
            &mut ledger,
            &owner,
            &blinded,
            k as usize % 4,
        )?;
        let t = BoundTicket {
            claim: c,
            signature: blind::unblind(&committee.sharing, &answers, &blinding)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?,
        };
        t.verify(&committee.sharing)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        bound.push(t);
    }
    let mut unbound = vec![];
    for (k, n) in [(K_FRESH_UNBOUND, None), (K_POOL_UNBOUND, Some(&notes[0].0))] {
        let c = claim(k, slot_of(k, n)?)?;
        let r = seed.ticket(k)?.blinding;
        let (blinded, blinding) = blind::blind_with(r, NAMESPACE, &c.message()).context("zero")?;
        let answers = issue(
            &mut committee,
            &mut ledger,
            &owner,
            &blinded,
            k as usize % 4,
        )?;
        let t = Ticket {
            claim: c,
            signature: blind::unblind(&committee.sharing, &answers, &blinding)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?,
        };
        t.verify(&committee.sharing)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        unbound.push(t);
    }
    println!("four tickets issued, two bound");

    // 3. The fresh senders, unbound then bound.
    let fees = rpc::suggest_fees(&provider, TIP).await?;
    let envelope = |_sender: Address| Envelope {
        chain_id,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: 0,
        fees,
    };
    let post = |m: &[u8]| {
        Frame::sender(Some(common::BOARD))
            .with_data(kohaku_frame_registry::announce::post_frame(common::BOARD, m).data)
            .with_execution(30_000)
    };
    let mut spends = vec![];
    {
        let sender = seed.ticket(K_FRESH_UNBOUND)?.sender;
        let account = Eoa::new(Signer::secp256k1(sender.address()));
        let mut sponsor = TicketSponsor::new(unbound_pm.address(), &unbound[0]);
        let mut tx = TxPlan::new(&account)
            .sponsored_by(&mut sponsor)
            .call(post(UNBOUND_TAG))
            .build(&envelope(sender.address()))?;
        sign_all(&mut tx, &[FrameSigner::Secp256k1(sender)])?;
        spends.push(executed(&provider, &tx, "a fresh sender, unbound ticket").await?);
    }
    {
        let sender = seed.ticket(K_FRESH_BOUND)?.sender;
        let binder = seed.binder(K_FRESH_BOUND)?;
        let account = Eoa::new(Signer::secp256k1(sender.address()));
        let mut sponsor = BoundTicketSponsor::new(bound_pm.address(), &bound[0]);
        let mut tx = TxPlan::new(&account)
            .sponsored_by(&mut sponsor)
            .call(post(BOUND_TAG))
            .build(&envelope(sender.address()))?;
        sign_all(
            &mut tx,
            &[
                FrameSigner::Secp256k1(sender),
                FrameSigner::Secp256k1(binder),
            ],
        )?;
        spends.push(executed(&provider, &tx, "a fresh sender, bound ticket").await?);
    }

    // 4. The unbound control: a pending withdrawal, and a copy with raised fees.
    let wfees = rpc::suggest_fees(&provider, WITHDRAWAL_TIP).await?;
    let mut control = vec![];
    let n_recipient = 10;
    {
        let (note, leaf, block) = notes[0].clone();
        let w = withdrawal(
            &provider,
            chain_id,
            note,
            leaf,
            block,
            seed.recipient(n_recipient)?.address(),
            unbound_pm.address(),
            unbound[1].pay_data(),
            wfees,
        )
        .await?;
        let mut copy = w.tx.clone();
        copy.fees = copy.fees.bumped();
        control.push(try_send(&provider, &w.tx, "unbound: the withdrawal").await?);
        control.push(
            try_send(
                &provider,
                &copy,
                "unbound: a copy with its fees raised, signed by no one",
            )
            .await?,
        );
        let winner = if control[1]["sent"].get("result").is_some() {
            &copy
        } else {
            &w.tx
        };
        control.push(mined(&provider, winner, "unbound: mined").await?);
    }

    // 5. The bound withdrawal, and three copies.
    let mut binding = vec![];
    {
        let (note, leaf, block) = notes[1].clone();
        let binder = seed.binder(K_POOL_BOUND)?;
        let w = withdrawal(
            &provider,
            chain_id,
            note,
            leaf,
            block,
            seed.recipient(n_recipient + 1)?.address(),
            bound_pm.address(),
            bound[1].pay_data(),
            wfees,
        )
        .await?;
        let mut tx = w.tx.clone();
        tx.signatures.push(binder_entry(binder.address()));
        sign_all(&mut tx, &[FrameSigner::Secp256k1(binder.clone())])?;
        // Copy 1: fees raised, the one-time key's signature kept.
        let mut c1 = tx.clone();
        c1.fees = c1.fees.bumped();
        // Copy 2: fees raised, the binder's entry removed.
        let mut c2 = c1.clone();
        c2.signatures.clear();
        // Copy 3: fees raised, another key named in the data and signing.
        let other = PrivateKeySigner::random();
        let mut c3 = c1.clone();
        let mut data = c3.frames[2].data.to_vec();
        data[40..60].copy_from_slice(other.address().as_slice());
        c3.frames[2].data = Bytes::from(data);
        c3.signatures = vec![binder_entry(other.address())];
        sign_all(&mut c3, &[FrameSigner::Secp256k1(other)])?;
        binding.push(try_send(&provider, &tx, "bound: the withdrawal").await?);
        binding.push(
            try_send(
                &provider,
                &c1,
                "bound: a copy with its fees raised, the one-time key's signature kept",
            )
            .await?,
        );
        binding.push(
            try_send(
                &provider,
                &c2,
                "bound: the same, its signature entry removed",
            )
            .await?,
        );
        binding.push(
            try_send(
                &provider,
                &c3,
                "bound: the same, another key named in the frame's data and signing",
            )
            .await?,
        );
        binding.push(mined(&provider, &tx, "bound: mined").await?);
        for c in &binding[1..4] {
            ensure!(
                c["sent"].get("error").is_some(),
                "a bound copy was accepted: {c}"
            );
        }
    }

    // The template, as a node recognises it: the code before the key and the denomination.
    let code = provider.get_code_at(bound_pm.address()).await?;
    let template = &code[..code.len() - 288];
    let ucode = provider.get_code_at(unbound_pm.address()).await?;
    let utemplate = &ucode[..ucode.len() - 288];
    println!(
        "bound template: {} bytes, keccak256 {}; unbound template: {} bytes, keccak256 {}",
        template.len(),
        keccak256(template),
        utemplate.len(),
        keccak256(utemplate)
    );

    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "chainId": chain_id,
            "owner0": owner.address(),
            "epoch": epoch,
            "committeeKey": hex(&key.encode()),
            "boundPaymaster": bound_pm.address(),
            "unboundPaymaster": unbound_pm.address(),
            "boundTemplate": { "length": template.len(), "keccak256": keccak256(template) },
            "unboundTemplate": { "length": utemplate.len(), "keccak256": keccak256(utemplate) },
            "tickets": {
                "bound": bound.iter().map(|t| json!({ "sender": t.claim.claim.slot.sender, "binder": t.claim.binder, "point": hex(&t.claim.point().encode()) })).collect::<Vec<_>>(),
                "unbound": unbound.iter().map(|t| json!({ "sender": t.claim.slot.sender, "point": hex(&t.claim.point().encode()) })).collect::<Vec<_>>(),
            },
            "issuers": committee.issuers.iter().map(|i| json!({
                "index": i.index(),
                "saw": i.transcript.iter().map(|b| hex(&b.encode())).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "steps": steps,
            "spends": spends,
            "control": control,
            "binding": binding,
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    Ok(())
}
