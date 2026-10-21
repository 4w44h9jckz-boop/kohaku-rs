//! What experiments 46 and 47's runs share with experiment 45's: the testnet's contracts,
//! sending, an account's transactions, and tickets whose secrets come from the seed.
#![allow(dead_code)]

use std::{env, fs};

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
    providers::Provider,
    rpc::types::Filter,
    signers::{SignerSync, local::PrivateKeySigner},
    sol,
    sol_types::{SolCall, SolEvent},
};
use anyhow::{Context, ensure};
use commonware_codec::{DecodeExt, Encode};
use commonware_cryptography::bls12381::primitives::{
    group::{G1, G2},
    ops,
    variant::{MinSig, PartialSignature},
};
use commonware_math::algebra::Field as _;
use kohaku_frame_accounts::{
    account::{Eoa, FrameAccount, Signer},
    builder::{Envelope, TxPlan},
    recovery::{DeviceRecoveryAccount, TimeRule},
};
use kohaku_frame_kit::{Frame, FrameSigner, FrameTx, rpc, sign_all};
use kohaku_frame_registry::announce::{Posted, post_frame};
use kohaku_frame_secrets::Seed;
use kohaku_frame_ticket::{
    Claim, Committee, Slot, Ticket, TicketPaymaster, TicketSponsor, blind,
    issuers::{Count, Ledger, request_id},
    paymaster::Bought,
    ticket::{NAMESPACE, epoch_of},
};
use rand::RngExt;
use serde_json::{Value, json};

/// Experiment 33's board.
pub const BOARD: Address = address!("0x93DD748B72dA1b1B6F1d5ec78Cb91ee52F01727d");
/// 0.001 ETH a ticket, as in experiment 36.
pub const TICKET_PRICE: U256 = U256::from_limbs([1_000_000_000_000_000, 0, 0, 0]);
pub const ISSUERS: usize = 4;
pub const TIP: u128 = 1_000_000_000;
/// Experiment 45's accounts: the recovery delay, seconds.
pub const DELAY: u64 = 120;
/// A board message carrying a ticket's request and the committee's blinded answer.
pub const ANSWER_TAG: u8 = 0x10;

sol! {
    function post(bytes message);
}

/// Account `i` of a seed, as experiment 45 deploys it: owner `i`, no recovery commitment.
pub fn account(seed: &Seed, i: u32) -> anyhow::Result<DeviceRecoveryAccount> {
    Ok(DeviceRecoveryAccount {
        owner: seed.owner(i)?.address(),
        commitment: B256::ZERO,
        delay: DELAY,
        rule: TimeRule::Eip,
        salt: seed.account_salt(i),
    })
}

pub fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

pub fn unhex(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(::hex::decode(s.trim_start_matches("0x"))?)
}

/// The mnemonic in `SEED_FILE`. Never printed.
pub fn load_seed() -> anyhow::Result<Seed> {
    let path = env::var("SEED_FILE").context("SEED_FILE names where the mnemonic is kept")?;
    Ok(Seed::from_mnemonic(fs::read_to_string(path)?.trim())?)
}

/// Hand a recovered mnemonic on to the next step: written to `RECOVERED_SEED_FILE`, mode 0600,
/// when that is set. Never printed. Whether it was written.
pub fn hand_on_recovered(words: &str) -> anyhow::Result<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    let Some(path) = env::var("RECOVERED_SEED_FILE")
        .ok()
        .filter(|p| !p.is_empty())
    else {
        return Ok(false);
    };
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)?;
    std::io::Write::write_all(&mut f, format!("{words}\n").as_bytes())?;
    Ok(true)
}

/// `key`'s own transaction making `calls`, simulated, sent and confirmed.
pub async fn send<P: Provider>(
    provider: &P,
    key: &PrivateKeySigner,
    calls: Vec<Frame>,
    what: &str,
) -> anyhow::Result<Value> {
    let account = Eoa::new(Signer::secp256k1(key.address()));
    let envelope = Envelope::fetch(provider, key.address(), vec![U256::ZERO], TIP).await?;
    let mut tx = TxPlan::new(&account).calls(calls).build(&envelope)?;
    sign_all(&mut tx, &[FrameSigner::Secp256k1(key.clone())])?;
    executed(provider, &tx, what).await
}

pub async fn executed<P: Provider>(
    provider: &P,
    tx: &FrameTx,
    what: &str,
) -> anyhow::Result<Value> {
    let done = rpc::execute(provider, tx, true).await?;
    let ok = done
        .receipt
        .frame_receipts
        .iter()
        .all(|f| f.status == U256::from(1));
    println!(
        "{what}: {} block {} gasUsed {}{}",
        done.hash,
        done.receipt.block_number,
        done.receipt.gas_used,
        if ok { "" } else { ", a frame FAILED" }
    );
    Ok(json!({
        "what": what,
        "hash": done.hash,
        "raw": tx.encode(),
        "block": done.receipt.block_number,
        "gasUsed": done.receipt.gas_used,
        "payer": done.receipt.payer,
        "framesSucceeded": ok,
    }))
}

/// A transaction from an account, signed by `keys` as `signer` requires, making `calls`.
pub fn account_tx(
    envelope: &Envelope,
    signer: &dyn FrameAccount,
    keys: &[PrivateKeySigner],
    calls: Vec<Frame>,
) -> anyhow::Result<FrameTx> {
    let mut tx = TxPlan::new(signer).calls(calls).build(envelope)?;
    let keys: Vec<FrameSigner> = keys.iter().cloned().map(FrameSigner::Secp256k1).collect();
    sign_all(&mut tx, &keys)?;
    Ok(tx)
}

/// Simulate and send a transaction that must be refused: the node's two answers.
pub async fn refused<P: Provider>(provider: &P, tx: &FrameTx, what: &str) -> anyhow::Result<Value> {
    let simulated = rpc::simulate(provider, tx, "latest").await?;
    let sent = match rpc::send(provider, tx).await {
        Ok(hash) => json!({ "result": hash }),
        Err(e) => json!({ "error": e.to_string() }),
    };
    println!(
        "{what}: simulation valid {}, {:?}; sent: {sent}",
        simulated.valid, simulated.violation
    );
    ensure!(
        !simulated.valid && sent.get("error").is_some(),
        "{what} was not refused"
    );
    Ok(json!({
        "what": what,
        "hash": tx.hash(),
        "raw": tx.encode(),
        "simulation": { "valid": simulated.valid, "violation": simulated.violation },
        "sent": sent,
    }))
}

/// A fresh sender's first transaction, paid with `ticket`: it posts `message` to the board.
pub fn spend(
    chain_id: u64,
    fees: kohaku_frame_kit::Fees,
    sender: &PrivateKeySigner,
    ticket: &Ticket,
    paymaster: Address,
    message: &[u8],
) -> anyhow::Result<FrameTx> {
    let account = Eoa::new(Signer::secp256k1(sender.address()));
    let mut sponsor = TicketSponsor::new(paymaster, ticket);
    let mut tx = TxPlan::new(&account)
        .sponsored_by(&mut sponsor)
        .call(
            Frame::sender(Some(BOARD))
                .with_data(
                    postCall {
                        message: message.to_vec().into(),
                    }
                    .abi_encode(),
                )
                .with_execution(40_000 + 16 * message.len() as u64),
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

/// The k-th ticket's claim, from the seed and its epoch.
pub fn claim(seed: &Seed, chain_id: u64, k: u32, epoch: u64) -> anyhow::Result<Claim> {
    let t = seed.ticket(k)?;
    Ok(Claim {
        slot: Slot {
            chain_id,
            sender: t.sender.address(),
            nonce_keys: vec![U256::ZERO],
            nonce_seq: 0,
        },
        epoch,
        salt: t.salt,
    })
}

/// `ANSWER_TAG || epoch || B || x * B`.
pub fn answer_message(epoch: u64, blinded: &G1, answer: &G1) -> Vec<u8> {
    let mut m = vec![ANSWER_TAG];
    m.extend_from_slice(&epoch.to_be_bytes());
    m.extend_from_slice(&blinded.encode());
    m.extend_from_slice(&answer.encode());
    m
}

/// Tickets `buyer` bought from `paymaster`, from its `Bought` logs.
pub async fn bought_by<P: Provider>(
    provider: &P,
    paymaster: Address,
    buyer: Address,
) -> anyhow::Result<u64> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(paymaster)
                .event_signature(Bought::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?;
    let mut n = 0;
    for l in &logs {
        let e = Bought::decode_log(&l.inner)?;
        if e.buyer == buyer {
            n += e.count.to::<u64>();
        }
    }
    Ok(n)
}

/// A new committee and its paymaster; `buyer` deploys it and buys `count` tickets, which are
/// issued blind as the seed's tickets `first..first + count`, and their answers posted.
pub struct Tickets {
    pub paymaster: Address,
    pub committee_key: G2,
    pub first: u32,
    pub issued: Vec<Ticket>,
    pub steps: Vec<Value>,
}

pub async fn buy_tickets<P: Provider>(
    provider: &P,
    seed: &Seed,
    buyer: &PrivateKeySigner,
    first: u32,
    count: u32,
) -> anyhow::Result<Tickets> {
    let mut rng = rand::rng();
    let chain_id = provider.get_chain_id().await?;
    let mut committee = Committee::dkg(&mut rng, ISSUERS)?;
    let paymaster = TicketPaymaster {
        key: *committee.sharing.public(),
        denomination: TICKET_PRICE,
        salt: B256::from(rng.random::<[u8; 32]>()),
    };
    let mut steps = vec![
        send(
            provider,
            buyer,
            vec![
                paymaster.deploy_frame(),
                paymaster.buy_frame(u64::from(count)),
            ],
            "a ticket paymaster for a new committee deployed, tickets bought",
        )
        .await?,
    ];
    let bought = bought_by(provider, paymaster.address(), buyer.address()).await?;
    let mut ledger = Ledger::new([(buyer.address(), bought)].into());
    let head = provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await?
        .context("no head")?;
    let epoch = epoch_of(head.header.timestamp);
    let mut tickets = vec![];
    let mut posts = vec![];
    for k in first..first + count {
        let c = claim(seed, chain_id, k, epoch)?;
        let r = seed.ticket(k)?.blinding;
        let (blinded, blinding) =
            blind::blind_with(r.clone(), NAMESPACE, &c.message()).context("zero blinding")?;
        let digest = keccak256([b"kohaku-ticket-request".as_slice(), &blinded.encode()].concat());
        let request = buyer.sign_hash_sync(&digest)?;
        let left_out = k as usize % ISSUERS;
        let mut answers: Vec<PartialSignature<MinSig>> = vec![];
        for (i, issuer) in committee.issuers.iter_mut().enumerate() {
            if i == left_out {
                continue;
            }
            ledger.admit(
                Count::Shared,
                i,
                request.recover_address_from_prehash(&digest)?,
                request_id(&blinded),
            )?;
            let a = issuer.answer(&blinded);
            blind::check_answer(&committee.sharing, &blinded, &a)
                .map_err(|e| anyhow::anyhow!("an answer does not check: {e:?}"))?;
            answers.push(a);
        }
        let signature = blind::unblind(&committee.sharing, &answers, &blinding)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        let ticket = Ticket {
            claim: c,
            signature,
        };
        ticket
            .verify(&committee.sharing)
            .map_err(|e| anyhow::anyhow!("a ticket does not verify: {e:?}"))?;
        posts.push(post_frame(
            BOARD,
            &answer_message(epoch, &blinded, &(signature * &r)),
        ));
        tickets.push(ticket);
    }
    steps.push(
        send(
            provider,
            buyer,
            posts,
            "the tickets' requests and blinded answers posted",
        )
        .await?,
    );
    Ok(Tickets {
        paymaster: paymaster.address(),
        committee_key: *committee.sharing.public(),
        first,
        issued: tickets,
        steps,
    })
}

/// The seed's k-th ticket, rebuilt from its answer on the board and checked under `key`.
pub fn rebuild_ticket(
    seed: &Seed,
    chain_id: u64,
    k: u32,
    board: &[Posted],
    key: &G2,
) -> anyhow::Result<(Ticket, B256)> {
    let r = seed.ticket(k)?.blinding;
    // The same ticket index may have been asked of more than one committee: take the answer
    // that verifies under `key`.
    let (c, signature, post) = board
        .iter()
        .find_map(|p| {
            let m = &p.message;
            if m.len() != 105 || m[0] != ANSWER_TAG {
                return None;
            }
            let epoch = u64::from_be_bytes(m[1..9].try_into().ok()?);
            let c = claim(seed, chain_id, k, epoch).ok()?;
            let (blinded, _) = blind::blind_with(r.clone(), NAMESPACE, &c.message())?;
            if m[9..57] != blinded.encode()[..] {
                return None;
            }
            let signature = G1::decode(&m[57..105]).ok()? * &r.inv();
            ops::verify_message::<MinSig>(key, NAMESPACE, &c.message(), &signature)
                .is_ok()
                .then_some((c, signature, p.tx))
        })
        .context("no answer on the board for this ticket under this committee")?;
    Ok((
        Ticket {
            claim: c,
            signature,
        },
        post,
    ))
}

/// Wait until the chain's head is at or past `time`.
pub async fn wait_until<P: Provider>(provider: &P, time: u64) -> anyhow::Result<u64> {
    loop {
        let head = provider
            .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
            .await?
            .context("no head")?;
        if head.header.timestamp >= time {
            return Ok(head.header.timestamp);
        }
        tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    }
}
