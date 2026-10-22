//! Blind tickets on the ethrex Hegota testnet: `exp-frames` experiment 36.
//!
//! ```text
//! PRIVATE_KEY=0x... RECORD=record.json \
//!   cargo run --release -p kohaku-frame-ticket --example blind_tickets
//! ```
//!
//! 1. Four issuers run Commonware's DKG; a quorum of three signs.
//! 2. The funder deploys a `TicketPaymaster` for the committee's key, buys three tickets, and
//!    funds a second buyer, who buys three more.
//! 3. For each ticket, the buyer makes a fresh sender, blinds the claim on that sender's first
//!    slot, and sends the blinded point, signed by the buyer, to three issuers. An issuer answers
//!    only a request on the issuers' shared list of that buyer's requests, which holds no more
//!    requests than the buyer bought tickets. A seventh request is refused by every issuer.
//! 4. Four fresh senders spend, one after another, in an order shuffled away from the order of
//!    issuance, each posting to experiment 33's board with its gas paid by its ticket.
//! 5. The last two spend at once, one ticket from each buyer: two pending transactions with one
//!    payer.
//! 6. Three transactions the paymaster must refuse: a signature that is no ticket, a spent
//!    ticket carried by another fresh sender, and a spent ticket at its sender's next nonce.
//!
//! `RECORD` names a JSON file for every transaction, the issuers' transcripts and the
//! committee's public key. No key and no blinding factor is recorded or printed.

use std::{collections::BTreeMap, env, fs};

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::{SolCall, SolEvent},
};
use anyhow::{Context, ensure};
use commonware_codec::Encode;
use commonware_cryptography::bls12381::primitives::{
    group::{G1, Scalar},
    variant::{MinSig, PartialSignature},
};
use commonware_math::algebra::{CryptoGroup, Random};
use kohaku_frame_accounts::{
    account::{Eoa, Signer},
    builder::{Envelope, TxPlan},
};
use kohaku_frame_kit::{
    Frame, FrameSigner, FrameTx,
    gas::max_cost,
    rpc::{self, HEGOTA_RPC_URL},
    sign_all,
};
use kohaku_frame_ticket::{
    Claim, Committee, Slot, Ticket, TicketPaymaster, TicketSponsor, blind,
    issuers::{Count, Ledger, request_id},
    paymaster::Bought,
    ticket::{NAMESPACE, epoch_of, g2_eip2537},
};
use rand::RngExt;
use serde_json::{Value, json};

/// `exp-frames` experiment 33's board: `post(bytes)` logs `Posted(bytes)`.
const BOARD: Address = address!("0x93DD748B72dA1b1B6F1d5ec78Cb91ee52F01727d");
/// 0.001 ETH a ticket.
const DENOMINATION: U256 = U256::from_limbs([1_000_000_000_000_000, 0, 0, 0]);
const TIP: u128 = 1_000_000_000;
const ISSUERS: usize = 4;
const TICKETS_EACH: u64 = 3;

sol! {
    function post(bytes message);
}

fn request_digest(blinded: &G1) -> B256 {
    keccak256([b"kohaku-ticket-request".as_slice(), &blinded.encode()].concat())
}

/// A buyer's request, signed with the key that bought tickets, to every issuer but
/// `left_out`. Each checks the signature and the shared list, answers, and keeps a transcript.
fn request(
    issuers: &mut [kohaku_frame_ticket::Issuer],
    ledger: &mut Ledger,
    transcripts: &mut [Vec<Value>],
    left_out: usize,
    buyer: &PrivateKeySigner,
    blinded: &G1,
) -> anyhow::Result<Vec<PartialSignature<MinSig>>> {
    let digest = request_digest(blinded);
    let signature = buyer.sign_hash_sync(&digest)?;
    let mut answers = vec![];
    for (i, issuer) in issuers.iter_mut().enumerate() {
        if i == left_out {
            continue;
        }
        let signer = signature.recover_address_from_prehash(&digest)?;
        ensure!(
            signer == buyer.address(),
            "a request not signed by its buyer"
        );
        ledger.admit(Count::Shared, i, signer, request_id(blinded))?;
        let a = issuer.answer(blinded);
        transcripts[i].push(json!({
            "buyer": signer,
            "blinded": hex(&blinded.encode()),
            "answer": hex(&a.value.encode()),
        }));
        answers.push(a);
    }
    Ok(answers)
}

/// What every step needs.
struct Run<P> {
    provider: P,
    chain_id: u64,
    paymaster: Address,
    epoch: u64,
    fees: kohaku_frame_kit::Fees,
}

/// The tickets issued, each with its fresh sender and the index of the buyer it was issued to.
struct Issued {
    tickets: Vec<(PrivateKeySigner, Ticket, usize)>,
    transcripts: Vec<Vec<Value>>,
    beyond_bought: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| HEGOTA_RPC_URL.to_owned());
    let funder: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY pays for the paymaster and buys tickets")?
        .parse()?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let chain_id = provider.get_chain_id().await?;
    let mut rng = rand::rng();

    // 1. The committee.
    let mut committee = Committee::dkg(&mut rng, ISSUERS)?;
    let quorum = committee.quorum();
    println!("committee: {ISSUERS} issuers, quorum {quorum}");
    let paymaster = TicketPaymaster {
        key: *committee.sharing.public(),
        denomination: DENOMINATION,
        salt: B256::from(rng.random::<[u8; 32]>()),
    };
    let pm = paymaster.address();
    println!("paymaster: {pm}");

    // 2. Deploy, buy, fund the second buyer, who buys.
    let second = PrivateKeySigner::random();
    let (setup, second_buy) = setup(&provider, &paymaster, &funder, &second, chain_id).await?;
    let buyers = [funder.clone(), second.clone()];

    // 3. Issuance.
    let head = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await?
        .context("no head")?;
    let run = Run {
        chain_id,
        paymaster: pm,
        epoch: epoch_of(head.header.timestamp),
        fees: rpc::suggest_fees(&provider, TIP).await?,
        provider,
    };
    let issued = issue(&run, &mut committee, &buyers).await?;

    // 4. The spends, one after another, shuffled away from the order of issuance. The last
    // ticket of each buyer is kept for the pair.
    let pair = [TICKETS_EACH as usize - 1, 2 * TICKETS_EACH as usize - 1];
    let mut order: Vec<usize> = (0..issued.tickets.len())
        .filter(|t| !pair.contains(t))
        .collect();
    for i in (1..order.len()).rev() {
        order.swap(i, rng.random_range(0..=i));
    }
    let mut spends = vec![];
    for &t in &order {
        spends.push(spend_alone(&run, &issued.tickets[t]).await?);
    }

    // 5. Two spends at once: two pending transactions with one payer.
    let at_once =
        spend_at_once(&run, &[&issued.tickets[pair[0]], &issued.tickets[pair[1]]]).await?;

    // 6. Refusals.
    let (spent_sender, spent, _) = &issued.tickets[order[0]];
    let refusals = refusals(&run, spent_sender, spent).await?;

    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "chainId": chain_id,
            "paymaster": pm,
            "denomination": DENOMINATION,
            "namespace": String::from_utf8_lossy(NAMESPACE),
            "epoch": run.epoch,
            "committee": {
                "issuers": ISSUERS,
                "quorum": quorum,
                "key": hex(&committee.sharing.public().encode()),
                "keyEip2537": hex(&g2_eip2537(committee.sharing.public())),
                "partialKeys": (0..ISSUERS as u32).map(|i| {
                    committee.sharing.partial_public(commonware_utils::Participant::new(i))
                        .map(|k| hex(&k.encode())).unwrap_or_default()
                }).collect::<Vec<_>>(),
            },
            "setup": setup,
            "secondBuy": second_buy,
            "buyers": buyers.iter().map(PrivateKeySigner::address).collect::<Vec<_>>(),
            "transcripts": committee.issuers.iter().zip(&issued.transcripts).map(|(i, t)| json!({
                "index": i.index(),
                "answers": t,
            })).collect::<Vec<_>>(),
            "spendOrder": order,
            "spends": spends,
            "atOnce": at_once,
            "beyondBought": issued.beyond_bought,
            "refusals": refusals,
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    Ok(())
}

/// The funder deploys the paymaster, buys, and funds the second buyer, who buys: both
/// transactions' records.
async fn setup<P: Provider>(
    provider: &P,
    paymaster: &TicketPaymaster,
    funder: &PrivateKeySigner,
    second: &PrivateKeySigner,
    chain_id: u64,
) -> anyhow::Result<(Value, Value)> {
    let setup = send(
        provider,
        funder,
        vec![
            paymaster.deploy_frame(),
            paymaster.buy_frame(TICKETS_EACH),
            Frame::sender(Some(second.address()))
                .with_value(DENOMINATION * U256::from(TICKETS_EACH + 1))
                .with_execution(10_000)
                .with_state(TicketSponsor::NEW_ACCOUNT_STATE),
        ],
        chain_id,
    )
    .await?;
    let second_buy = send(
        provider,
        second,
        vec![paymaster.buy_frame(TICKETS_EACH)],
        chain_id,
    )
    .await?;
    Ok((setup, second_buy))
}

/// Issue every buyer its tickets, against the shared list of each buyer's requests, then make
/// one request more than the second buyer bought.
async fn issue<P: Provider>(
    run: &Run<P>,
    committee: &mut Committee,
    buyers: &[PrivateKeySigner],
) -> anyhow::Result<Issued> {
    let mut rng = rand::rng();
    let mut ledger = Ledger::new(bought(&run.provider, run.paymaster).await?);
    println!("bought on chain: {:?}", ledger.bought);
    let mut transcripts: Vec<Vec<Value>> = vec![vec![]; ISSUERS];
    let mut tickets = vec![];
    for (b, buyer) in buyers.iter().enumerate() {
        for k in 0..TICKETS_EACH {
            let sender = PrivateKeySigner::random();
            let claim = Claim {
                slot: Slot {
                    chain_id: run.chain_id,
                    sender: sender.address(),
                    nonce_keys: vec![U256::ZERO],
                    nonce_seq: 0,
                },
                epoch: run.epoch,
                salt: B256::from(rng.random::<[u8; 32]>()),
            };
            let (blinded, blinding) = blind::blind(&mut rng, NAMESPACE, &claim.message());
            // A different quorum for each ticket: leave out one issuer in turn.
            let left_out = (b * TICKETS_EACH as usize + k as usize) % ISSUERS;
            let answers = request(
                &mut committee.issuers,
                &mut ledger,
                &mut transcripts,
                left_out,
                buyer,
                &blinded,
            )?;
            for a in &answers {
                blind::check_answer(&committee.sharing, &blinded, a)
                    .map_err(|e| anyhow::anyhow!("an issuer's answer does not check: {e:?}"))?;
            }
            let ticket = Ticket {
                signature: blind::unblind(&committee.sharing, &answers, &blinding)
                    .map_err(|e| anyhow::anyhow!("{e:?}"))?,
                claim,
            };
            ticket
                .verify(&committee.sharing)
                .map_err(|e| anyhow::anyhow!("an unblinded ticket does not verify: {e:?}"))?;
            println!("ticket issued to buyer {b}, issuer {left_out} left out");
            tickets.push((sender, ticket, b));
        }
    }
    let (extra, _) = blind::blind(&mut rng, NAMESPACE, b"one more");
    let beyond_bought = match request(
        &mut committee.issuers,
        &mut ledger,
        &mut transcripts,
        ISSUERS,
        &buyers[1],
        &extra,
    ) {
        Ok(_) => anyhow::bail!("an issuer answered a request beyond what was bought"),
        Err(e) => e.to_string(),
    };
    println!("a request beyond what the second buyer bought: refused, {beyond_bought}");
    Ok(Issued {
        tickets,
        transcripts,
        beyond_bought,
    })
}

/// One spend, simulated, sent and confirmed.
async fn spend_alone<P: Provider>(
    run: &Run<P>,
    (sender, ticket, buyer): &(PrivateKeySigner, Ticket, usize),
) -> anyhow::Result<Value> {
    let tx = spend(run.chain_id, run.fees, sender, ticket, run.paymaster)?;
    ensure!(
        max_cost(&tx, 0)? <= DENOMINATION,
        "the spend costs more than a ticket"
    );
    let done = rpc::execute(&run.provider, &tx, true).await?;
    let pay = &done.receipt.frame_receipts[1];
    println!(
        "spend {}: block {}, gasUsed {}, pay VERIFY {} execution, {} state, payer {}",
        done.hash,
        done.receipt.block_number,
        done.receipt.gas_used,
        pay.gas_used,
        pay.state_gas_used,
        done.receipt.payer
    );
    ensure!(
        done.receipt.payer == run.paymaster,
        "the paymaster did not pay"
    );
    Ok(json!({
        "buyer": buyer,
        "hash": done.hash,
        "raw": tx.encode(),
        "block": done.receipt.block_number,
        "gasUsed": done.receipt.gas_used,
        "payVerify": { "gasUsed": pay.gas_used, "stateGasUsed": pay.state_gas_used },
        "payer": done.receipt.payer,
        "sender": sender.address(),
        "point": hex(&ticket.claim.point().encode()),
        "signature": hex(&ticket.signature.encode()),
    }))
}

/// Send each spend without waiting for the one before; send a refused one again once the first
/// is mined.
async fn spend_at_once<P: Provider>(
    run: &Run<P>,
    pair: &[&(PrivateKeySigner, Ticket, usize)],
) -> anyhow::Result<Vec<Value>> {
    let txs: Vec<FrameTx> = pair
        .iter()
        .map(|(sender, ticket, _)| spend(run.chain_id, run.fees, sender, ticket, run.paymaster))
        .collect::<anyhow::Result<_>>()?;
    let mut answers = vec![];
    for tx in &txs {
        let answer = match rpc::send(&run.provider, tx).await {
            Ok(hash) => json!({ "result": hash }),
            Err(e) => json!({ "error": e.to_string() }),
        };
        println!("at once: {} -> {answer}", tx.hash());
        answers.push(answer);
    }
    let wait = |hash| {
        rpc::wait_for_confirmed_receipt(
            &run.provider,
            hash,
            std::time::Duration::from_mins(3),
            std::time::Duration::from_secs(2),
        )
    };
    let mut out = vec![];
    for ((tx, answer), (_, _, buyer)) in txs.iter().zip(&answers).zip(pair) {
        let resent = answer.get("result").is_none();
        if resent {
            wait(txs[0].hash()).await?;
            rpc::execute(&run.provider, tx, true).await?;
        }
        let r = wait(tx.hash()).await?;
        println!(
            "pair: {} block {}, payer {}, resent {resent}",
            tx.hash(),
            r.block_number,
            r.payer,
        );
        out.push(json!({
            "buyer": buyer,
            "hash": tx.hash(),
            "raw": tx.encode(),
            "answer": answer,
            "resent": resent,
            "block": r.block_number,
            "gasUsed": r.gas_used,
            "payVerify": {
                "gasUsed": r.frame_receipts[1].gas_used,
                "stateGasUsed": r.frame_receipts[1].state_gas_used,
            },
            "payer": r.payer,
        }));
    }
    Ok(out)
}

/// Three spends the paymaster must refuse: a signature that is no ticket, a spent ticket carried
/// by another fresh sender, and a spent ticket at its sender's next nonce.
async fn refusals<P: Provider>(
    run: &Run<P>,
    spent_sender: &PrivateKeySigner,
    spent: &Ticket,
) -> anyhow::Result<Vec<Value>> {
    let mut rng = rand::rng();
    let mut out = vec![];
    let junk_sender = PrivateKeySigner::random();
    let junk = Ticket {
        claim: Claim {
            slot: Slot {
                chain_id: run.chain_id,
                sender: junk_sender.address(),
                nonce_keys: vec![U256::ZERO],
                nonce_seq: 0,
            },
            epoch: run.epoch,
            salt: B256::from(rng.random::<[u8; 32]>()),
        },
        signature: G1::generator() * &Scalar::random(&mut rng),
    };
    let tx = spend(run.chain_id, run.fees, &junk_sender, &junk, run.paymaster)?;
    out.push(refuse(&run.provider, "a signature that is no ticket", &tx).await?);
    let other = PrivateKeySigner::random();
    let tx = spend(run.chain_id, run.fees, &other, spent, run.paymaster)?;
    out.push(
        refuse(
            &run.provider,
            "a spent ticket, carried by another fresh sender",
            &tx,
        )
        .await?,
    );
    let mut again = spend(run.chain_id, run.fees, spent_sender, spent, run.paymaster)?;
    again.nonce_seq = 1;
    for f in &mut again.frames {
        // No longer a new account.
        f.limits.state = 0;
    }
    sign_all(&mut again, &[FrameSigner::Secp256k1(spent_sender.clone())])?;
    out.push(
        refuse(
            &run.provider,
            "a spent ticket, at its sender's next nonce",
            &again,
        )
        .await?,
    );
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

/// A fresh sender's first transaction, paid with `ticket`: it posts to the board.
fn spend(
    chain_id: u64,
    fees: kohaku_frame_kit::Fees,
    sender: &PrivateKeySigner,
    ticket: &Ticket,
    paymaster: Address,
) -> anyhow::Result<FrameTx> {
    let account = Eoa::new(Signer::secp256k1(sender.address()));
    let mut sponsor = TicketSponsor::new(paymaster, ticket);
    let mut tx = TxPlan::new(&account)
        .sponsored_by(&mut sponsor)
        .call(
            Frame::sender(Some(BOARD))
                .with_data(
                    postCall {
                        message: b"paid with a blind ticket".to_vec().into(),
                    }
                    .abi_encode(),
                )
                .with_execution(30_000),
        )
        .build(&Envelope {
            chain_id,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: 0,
            fees,
        })?;
    sign_all(&mut tx, &[FrameSigner::Secp256k1(sender.clone())])?;
    Ok(tx)
}

/// The account's own transaction making `calls`, simulated, sent and confirmed.
async fn send<P: Provider>(
    provider: &P,
    key: &PrivateKeySigner,
    calls: Vec<Frame>,
    chain_id: u64,
) -> anyhow::Result<Value> {
    let account = Eoa::new(Signer::secp256k1(key.address()));
    let envelope = Envelope::fetch(provider, key.address(), vec![U256::ZERO], TIP).await?;
    ensure!(envelope.chain_id == chain_id);
    let mut tx = TxPlan::new(&account).calls(calls).build(&envelope)?;
    sign_all(&mut tx, &[FrameSigner::Secp256k1(key.clone())])?;
    let done = rpc::execute(provider, &tx, true).await?;
    println!(
        "{}: block {}, gasUsed {}",
        done.hash, done.receipt.block_number, done.receipt.gas_used
    );
    Ok(json!({
        "hash": done.hash,
        "raw": tx.encode(),
        "block": done.receipt.block_number,
        "gasUsed": done.receipt.gas_used,
    }))
}

/// Tickets bought from `paymaster`, by buyer, from its `Bought` logs.
async fn bought<P: Provider>(
    provider: &P,
    paymaster: Address,
) -> anyhow::Result<BTreeMap<Address, u64>> {
    let logs = provider
        .get_logs(
            &alloy::rpc::types::Filter::new()
                .address(paymaster)
                .event_signature(Bought::SIGNATURE_HASH)
                .from_block(provider.get_block_number().await?.saturating_sub(1_000)),
        )
        .await?;
    let mut out = BTreeMap::new();
    for l in &logs {
        let e = Bought::decode_log(&l.inner)?;
        *out.entry(e.buyer).or_default() += e.count.to::<u64>();
    }
    Ok(out)
}

/// Simulate and send a transaction the paymaster must refuse: the node's two answers.
async fn refuse<P: Provider>(provider: &P, what: &str, tx: &FrameTx) -> anyhow::Result<Value> {
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
