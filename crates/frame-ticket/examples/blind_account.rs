//! A blind account on the ethrex Hegota testnet: `exp-frames` experiment 59.
//!
//! ```text
//! PRIVATE_KEY=0x... RUN=r1 RECORD=record.json \
//!   cargo run --release -p kohaku-frame-ticket --example blind_account
//! ```
//!
//! Every key (the committee's, the binders', the recipients') is derived from `PRIVATE_KEY` and
//! `RUN`, so a rerun under the same `RUN` finds the same account. None is printed or recorded.
//! The funder deploys the account and two recipients that refuse ether, buys tickets, and asks
//! a committee of four issuers (quorum three) to sign them blind. Then the cases run:
//!
//! - (a) an honest payout; (b) its replay, and the ticket again at sequence 1;
//! - (c2) a ticket the issuers signed with no purchase, while an honest one is outstanding, then
//!   that honest one; (c) another such ticket once the key is exhausted;
//! - (d) two payouts under a key with one unit left: the second while the first is pending, and
//!   again once it is mined;
//! - (e) payouts to a recipient that reverts, and to one that burns all the gas it is given;
//! - (f) copies of a pending payout redirected: binder's entry kept, removed, another binder;
//! - (g) aggregate payouts of 2, 4 and 5 tickets, and 6, past the prefix's state-gas cap.

use std::{collections::BTreeMap, env, fs, time::Duration};

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use commonware_codec::Encode;
use kohaku_frame_accounts::{
    account::{Eoa, Signer},
    builder::{Envelope, TxPlan},
    contracts::{create2_address, deploy_frame},
};
use kohaku_frame_kit::{
    Fees, Frame, FrameSigner, FrameTx,
    rpc::{self, HEGOTA_RPC_URL},
    sign_all,
};
use kohaku_frame_ticket::{
    Committee, blind,
    blind_account::{AccountClaim, AccountTicket, BlindAccount, CLAIM, NAMESPACE, chi, payout_tx, rollover_tx, slot},
    issuers::{Count, Ledger, request_id},
};
use rand::{SeedableRng, rngs::StdRng};
use serde_json::{Value, json};

/// 0.001 ETH a ticket.
const D: U256 = U256::from_limbs([1_000_000_000_000_000, 0, 0, 0]);
const TIP: u128 = 1_000_000;
const ISSUERS: usize = 4;

struct Run<P> {
    provider: P,
    chain_id: u64,
    funder: PrivateKeySigner,
    secret: B256,
    account: BlindAccount,
    committee: Committee,
    /// One ledger per key: the funder's purchases under it.
    ledgers: BTreeMap<B256, Ledger>,
    seen: Vec<Value>,
    record: Vec<Value>,
}

fn hex(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

impl<P: Provider> Run<P> {
    fn key(&self, label: &str) -> PrivateKeySigner {
        let k = keccak256([self.secret.as_slice(), label.as_bytes()].concat());
        PrivateKeySigner::from_bytes(&k).expect("a key")
    }

    fn address(&self) -> Address {
        self.account.address()
    }

    async fn fees(&self) -> anyhow::Result<Fees> {
        Ok(rpc::suggest_fees(&self.provider, TIP).await?)
    }

    /// The funder's own transaction making `calls`, required to succeed in every frame.
    async fn funder_tx(&mut self, calls: Vec<Frame>, what: &str) -> anyhow::Result<Value> {
        let account = Eoa::new(Signer::secp256k1(self.funder.address()));
        let envelope = Envelope::fetch(&self.provider, self.funder.address(), vec![U256::ZERO], TIP).await?;
        let mut tx = TxPlan::new(&account).calls(calls).build(&envelope)?;
        sign_all(&mut tx, &[FrameSigner::Secp256k1(self.funder.clone())])?;
        let done = rpc::execute(&self.provider, &tx, true).await?;
        ensure!(done.receipt.frame_receipts.iter().all(|f| f.status == U256::from(1)), "{what}: a frame failed");
        println!("{what}: {} block {}", done.hash, done.receipt.block_number);
        Ok(json!({ "what": what, "hash": done.hash, "block": done.receipt.block_number, "gasUsed": done.receipt.gas_used }))
    }

    async fn count(&self, d: U256, epoch: u64) -> anyhow::Result<(U256, U256)> {
        let c = chi(d, epoch);
        let burned = self.provider.get_storage_at(self.address(), slot(c, 0).into()).await?;
        let minted = self.provider.get_storage_at(self.address(), slot(c, 1).into()).await?;
        Ok((burned, minted))
    }

    /// Version 2's `outstanding`, and the account's balance.
    async fn money(&self) -> anyhow::Result<(U256, U256)> {
        let out = self.provider.get_storage_at(self.address(), slot(B256::ZERO, 3).into()).await?;
        Ok((out, self.provider.get_balance(self.address()).await?))
    }

    async fn owed(&self, to: Address) -> anyhow::Result<U256> {
        Ok(self.provider.get_storage_at(self.address(), slot(to.into_word(), 2).into()).await?)
    }

    /// Buy `n` tickets under (D, epoch): the funder's purchases, and the key's ledger.
    async fn buy(&mut self, epoch: u64, n: u64) -> anyhow::Result<()> {
        let frames = (0..n).map(|_| self.account.buy_frame(D, epoch)).collect();
        let r = self.funder_tx(frames, &format!("buy {n} under epoch {epoch}")).await?;
        self.record.push(json!({ "case": "buy", "epoch": epoch, "n": n, "tx": r }));
        let ledger = self.ledgers.entry(chi(D, epoch)).or_default();
        *ledger.bought.entry(self.funder.address()).or_default() += n;
        Ok(())
    }

    /// One ticket under (D, epoch) for `binder`, signed blind by a quorum. With `honest`, every
    /// issuer first admits the request against the key's purchases; without, they sign anyway.
    fn issue(&mut self, epoch: u64, binder: Address, label: &str, honest: bool) -> anyhow::Result<AccountTicket> {
        let serial = U256::from_be_bytes(keccak256([self.secret.as_slice(), b"serial/", label.as_bytes()].concat()).0);
        let claim = AccountClaim { chain_id: self.chain_id, account: self.address(), denomination: D, epoch, serial, binder };
        let (blinded, blinding) = blind::blind(&mut rand::rng(), NAMESPACE, &claim.message());
        let quorum = self.committee.quorum();
        let id = request_id(&blinded);
        let mut answers = vec![];
        for (i, issuer) in self.committee.issuers.iter_mut().enumerate().take(quorum) {
            if honest {
                let ledger = self.ledgers.entry(claim.chi()).or_default();
                ledger.admit(Count::Shared, i, self.funder.address(), id)?;
            }
            answers.push(issuer.answer(&blinded));
        }
        let signature = blind::unblind(&self.committee.sharing, &answers, &blinding)?;
        let ticket = AccountTicket { claim, signature };
        ticket.verify(&self.committee.sharing)?;
        self.seen.push(json!({ "label": label, "blinded": hex(&blinded.encode()), "admitted": honest }));
        Ok(ticket)
    }

    fn payout(&self, tickets: &[AccountTicket], to: Address, binder: &PrivateKeySigner, fees: Fees) -> anyhow::Result<FrameTx> {
        let mut tx = payout_tx(tickets, to, fees)?;
        sign_all(&mut tx, &[FrameSigner::Secp256k1(binder.clone())])?;
        Ok(tx)
    }

    /// Simulate, send and wait for a transaction that must be mined.
    async fn mined(&mut self, tx: &FrameTx, case: &str, what: &str) -> anyhow::Result<Value> {
        let done = rpc::execute(&self.provider, tx, false).await.with_context(|| what.to_owned())?;
        let frames: Vec<Value> = done.receipt.frame_receipts.iter().map(|f| json!({ "status": f.status, "gasUsed": f.gas_used, "stateGasUsed": f.state_gas_used })).collect();
        println!("({case}) {what}: {} block {} gasUsed {} frames {frames:?}", done.hash, done.receipt.block_number, done.receipt.gas_used);
        let v = json!({ "case": case, "what": what, "hash": done.hash, "raw": tx.encode(), "block": done.receipt.block_number, "gasUsed": done.receipt.gas_used, "frames": frames, "nTickets": tx.nonce_keys.len() });
        self.record.push(v.clone());
        Ok(v)
    }

    /// Simulate and send a transaction that must be refused: the node's two answers.
    async fn refused(&mut self, tx: &FrameTx, case: &str, what: &str) -> anyhow::Result<Value> {
        let sim = rpc::simulate(&self.provider, tx, "latest").await;
        let sim = match sim {
            Ok(s) => json!({ "valid": s.valid, "violation": s.violation }),
            Err(e) => json!({ "error": e.to_string() }),
        };
        let sent = match rpc::send(&self.provider, tx).await {
            Ok(hash) => json!({ "result": hash }),
            Err(e) => json!({ "error": e.to_string() }),
        };
        println!("({case}) {what}: simulation {sim}; sent {sent}");
        let v = json!({ "case": case, "what": what, "hash": tx.hash(), "raw": tx.encode(), "simulation": sim, "sent": sent, "refused": sent.get("error").is_some() });
        self.record.push(v.clone());
        Ok(v)
    }

    async fn note(&mut self, case: &str, v: Value) {
        println!("({case}) {v}");
        self.record.push(json!({ "case": case, "state": v }));
    }
}

/// (h), on version 2: a ticket of epoch `e` traded at epoch end for one of `e + 1`, the new ticket
/// spent, and the old one tried again three ways.
#[allow(clippy::too_many_lines)]
async fn case_h<P: Provider>(mut r: Run<P>, e: u64, run: &str) -> anyhow::Result<()> {
    r.buy(e, 1).await?;
    let b = r.key("binder/h");
    let old = r.issue(e, b.address(), "h-old", true)?;
    let fees = r.fees().await?;
    let roll = {
        let mut t = rollover_tx(std::slice::from_ref(&old), fees)?;
        sign_all(&mut t, &[FrameSigner::Secp256k1(b.clone())])?;
        t
    };
    // The surplus must cover the rollover's maximum cost; a fresh account has none.
    let (out, bal) = r.money().await?;
    let max = kohaku_frame_kit::gas::max_cost(&roll, 0)?;
    if bal < out + max {
        let top = (out + max - bal) * U256::from(2);
        let v = r.funder_tx(vec![Frame::sender(Some(r.address())).with_value(top).with_execution(30_000)], "a plain transfer to the account's surplus").await?;
        r.record.push(json!({ "case": "h", "what": "surplus top-up", "value": top, "tx": v }));
    }
    let (out0, bal0) = r.money().await?;
    r.note("h", json!({ "before": { "outstanding": out0, "balance": bal0, "maxCost": max } })).await;
    r.mined(&roll, "h", "the rollover of an epoch-e ticket into e+1").await?;
    let (out1, bal1) = r.money().await?;
    let (bo, mo) = r.count(D, e).await?;
    let (bn, mn) = r.count(D, e + 1).await?;
    r.note("h", json!({ "after": { "outstanding": out1, "balance": bal1, "feePaid": bal0 - bal1, "old": [bo, mo], "new": [bn, mn] } })).await;

    // The new ticket: the issuers admit one request under the new key, by the rollover's binder.
    r.ledgers.entry(chi(D, e + 1)).or_default().bought.insert(b.address(), 1);
    let nb = r.key("binder/h-new");
    let funder = r.funder.address();
    let id_owner = std::mem::replace(&mut r.funder, b.clone());
    let new = r.issue(e + 1, nb.address(), "h-new", true)?;
    r.funder = id_owner;
    let _ = funder;
    let to = r.key("to/h").address();
    let fees = r.fees().await?;
    r.mined(&r.payout(std::slice::from_ref(&new), to, &nb, fees)?, "h", "the new ticket paid out, as in (a)").await?;
    let (bn, mn) = r.count(D, e + 1).await?;
    let (out2, _) = r.money().await?;
    r.note("h", json!({ "afterNewPayout": { "new": [bn, mn], "outstanding": out2, "recipient": r.provider.get_balance(to).await? } })).await;

    // The old ticket again.
    r.refused(&roll, "h", "the rollover's bytes again").await?;
    let mut seq1 = payout_tx(std::slice::from_ref(&old), to, r.fees().await?)?;
    seq1.nonce_seq = 1;
    sign_all(&mut seq1, &[FrameSigner::Secp256k1(b.clone())])?;
    r.refused(&seq1, "h", "the old ticket paid out at sequence 1").await?;
    let mut as_new = old.clone();
    as_new.claim.epoch = e + 1;
    as_new.claim.serial += U256::from(1);
    let mut t = payout_tx(std::slice::from_ref(&as_new), to, r.fees().await?)?;
    sign_all(&mut t, &[FrameSigner::Secp256k1(b.clone())])?;
    r.refused(&t, "h", "the old ticket's signature presented under e+1").await?;

    let out = json!({
        "chainId": r.chain_id, "account": r.address(), "version": 2, "codeBytes": r.account.initcode().len(),
        "denomination": D, "epoch": e, "run": run, "issuersSaw": r.seen, "steps": r.record,
    });
    let path = env::var("RECORD").unwrap_or_else(|_| "blind-account-h.json".to_owned());
    fs::write(&path, serde_json::to_string_pretty(&out)?)?;
    println!("record: {path}");
    Ok(())
}

/// Creation code returning `runtime` (at most 32 bytes).
fn tiny(runtime: &[u8]) -> Vec<u8> {
    let l = u8::try_from(runtime.len()).expect("short");
    [&[0x5f + l][..], runtime, &[0x60, 0x00, 0x52, 0x60, l, 0x60, 32 - l, 0xf3]].concat()
}

#[tokio::main]
#[allow(clippy::too_many_lines)]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| HEGOTA_RPC_URL.to_owned());
    let funder: PrivateKeySigner = env::var("PRIVATE_KEY").context("PRIVATE_KEY funds the run")?.parse()?;
    let run = env::var("RUN").unwrap_or_else(|_| "r1".to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let chain_id = provider.get_chain_id().await?;
    let secret = keccak256([funder.to_bytes().as_slice(), b"exp-frames/59/", run.as_bytes()].concat());
    let mut rng = StdRng::from_seed(keccak256([secret.as_slice(), b"committee"].concat()).0);
    let committee = Committee::dkg(&mut rng, ISSUERS)?;
    let code = match env::var("CODE_HEX") {
        Ok(path) => Some(alloy::hex::decode(fs::read_to_string(path)?.trim())?),
        Err(_) => None,
    };
    let account = BlindAccount { public: *committee.sharing.public(), salt: keccak256([b"exp-frames/59/account/".as_slice(), run.as_bytes()].concat()), code };
    let mut r = Run { provider, chain_id, funder, secret, account, committee, ledgers: BTreeMap::new(), seen: vec![], record: vec![] };
    println!("chain {chain_id}, run {run}, blind account {}, {} bytes of code with its key", r.address(), r.account.initcode().len());

    // Setup: the account, and two recipients that refuse ether.
    let reverter = (tiny(&[0x60, 0x00, 0x60, 0x00, 0xfd]), keccak256(b"exp-frames/59/reverter"));
    let burner = (tiny(&[0xfe]), keccak256(b"exp-frames/59/burner"));
    let reverter_at = create2_address(&reverter.0, reverter.1);
    let burner_at = create2_address(&burner.0, burner.1);
    let mut deploys = vec![];
    for (code, salt, addr) in [(r.account.initcode(), r.account.salt, r.address()), (reverter.0.clone(), reverter.1, reverter_at), (burner.0.clone(), burner.1, burner_at)] {
        if r.provider.get_code_at(addr).await?.is_empty() {
            deploys.push(deploy_frame(&code, salt, 0));
        }
    }
    if !deploys.is_empty() {
        let v = r.funder_tx(deploys, "deploy").await?;
        r.record.push(json!({ "case": "setup", "tx": v }));
    }
    // A fresh epoch base per run, so that reruns under one RUN do not meet old counts.
    let base: u64 = r.provider.get_block_number().await?;
    let e = |k: u64| base * 100 + k;

    if env::var("CASE").as_deref() == Ok("h") {
        return case_h(r, e(1), &run).await;
    }

    // (a) and (b): epoch e(1), two purchases.
    r.buy(e(1), 2).await?;
    let b_a = r.key("binder/a");
    let t_a = r.issue(e(1), b_a.address(), "a", true)?;
    let to_a = r.key("to/a").address();
    let before = r.provider.get_balance(to_a).await?;
    let fees = r.fees().await?;
    let tx_a = r.payout(std::slice::from_ref(&t_a), to_a, &b_a, fees)?;
    r.mined(&tx_a, "a", "an honest payout").await?;
    let after = r.provider.get_balance(to_a).await?;
    let (burned, minted) = r.count(D, e(1)).await?;
    r.note("a", json!({ "recipientGot": after - before, "D": D, "burned": burned, "minted": minted })).await;
    r.refused(&tx_a, "b", "the same payout's bytes again").await?;
    let mut seq1 = payout_tx(std::slice::from_ref(&t_a), to_a, r.fees().await?)?;
    seq1.nonce_seq = 1;
    sign_all(&mut seq1, &[FrameSigner::Secp256k1(b_a.clone())])?;
    r.refused(&seq1, "b", "the same ticket at sequence 1").await?;

    // (c2) and (c): a ticket with no purchase behind it, while one honest ticket is outstanding.
    let b_h = r.key("binder/honest");
    let t_h = r.issue(e(1), b_h.address(), "honest", true)?;
    let b_f = r.key("binder/forged1");
    let t_f = r.issue(e(1), b_f.address(), "forged1", false)?;
    let to_f = r.key("to/forged").address();
    let fees = r.fees().await?;
    r.mined(&r.payout(&[t_f], to_f, &b_f, fees)?, "c2", "a forged ticket while the float is there").await?;
    let tx_h = r.payout(&[t_h], r.key("to/honest").address(), &b_h, r.fees().await?)?;
    r.refused(&tx_h, "c2", "the honest holder's ticket after it").await?;
    let b_f2 = r.key("binder/forged2");
    let t_f2 = r.issue(e(1), b_f2.address(), "forged2", false)?;
    let tx_f2 = r.payout(&[t_f2], to_f, &b_f2, r.fees().await?)?;
    r.refused(&tx_f2, "c", "a forged ticket once the key is exhausted").await?;
    let (burned, minted) = r.count(D, e(1)).await?;
    r.note("c", json!({ "burned": burned, "minted": minted })).await;

    // (d): one unit under e(2), two payouts sent before either is mined.
    r.buy(e(2), 1).await?;
    let (b1, b2) = (r.key("binder/d1"), r.key("binder/d2"));
    let t1 = r.issue(e(2), b1.address(), "d1", true)?;
    let t2 = r.issue(e(2), b2.address(), "d2", false)?;
    let fees = r.fees().await?;
    let tx1 = r.payout(&[t1], r.key("to/d1").address(), &b1, fees)?;
    let tx2 = r.payout(&[t2], r.key("to/d2").address(), &b2, fees)?;
    // The pool admits one pending transaction per sender: the second is sent while the first is
    // pending, then again once the first is mined.
    let h1 = rpc::send(&r.provider, &tx1).await?;
    let s2 = rpc::send(&r.provider, &tx2).await.map_err(|e| e.to_string());
    println!("(d) the second while the first is pending: {s2:?}");
    let rc1 = rpc::wait_for_confirmed_receipt(&r.provider, h1, Duration::from_mins(2), Duration::from_secs(2)).await?;
    r.note("d", json!({ "first": h1, "block": rc1.block_number, "frames": rc1.frame_receipts.iter().map(|f| f.status).collect::<Vec<_>>(), "secondWhilePending": format!("{s2:?}") })).await;
    r.refused(&tx2, "d", "the second once the first is mined").await?;
    let (burned, minted) = r.count(D, e(2)).await?;
    r.note("d", json!({ "burned": burned, "minted": minted })).await;

    // (e): recipients that refuse ether.
    r.buy(e(3), 2).await?;
    for (label, to) in [("e-revert", reverter_at), ("e-burn", burner_at)] {
        let b = r.key(&format!("binder/{label}"));
        let t = r.issue(e(3), b.address(), label, true)?;
        let tx = r.payout(&[t], to, &b, r.fees().await?)?;
        r.mined(&tx, "e", &format!("a payout to a recipient that {}", if label == "e-revert" { "reverts" } else { "burns its gas" })).await?;
        let owed = r.owed(to).await?;
        let bal = r.provider.get_balance(to).await?;
        r.note("e", json!({ "recipient": to, "owed": owed, "balance": bal })).await;
    }
    let (burned, minted) = r.count(D, e(3)).await?;
    r.note("e", json!({ "burned": burned, "minted": minted })).await;

    // (f): a pending payout and three redirected copies.
    r.buy(e(4), 1).await?;
    let b = r.key("binder/f");
    let t = r.issue(e(4), b.address(), "f", true)?;
    let fees = r.fees().await?;
    let honest = r.payout(std::slice::from_ref(&t), r.key("to/f").address(), &b, fees)?;
    let hash = rpc::send(&r.provider, &honest).await?;
    let thief = r.key("thief");
    let redirect = |tx: &FrameTx| {
        let mut c = tx.clone();
        let mut data = c.frames[1].data.to_vec();
        data[68 + 12..100].copy_from_slice(thief.address().as_slice());
        c.frames[1].data = Bytes::from(data);
        c
    };
    let kept = redirect(&honest);
    r.refused(&kept, "f", "redirected, the binder's signature kept").await?;
    let mut removed = redirect(&honest);
    removed.signatures.clear();
    removed.signatures.push(kohaku_frame_ticket::blind_account::binder_entry(thief.address()));
    sign_all(&mut removed, &[FrameSigner::Secp256k1(thief.clone())])?;
    r.refused(&removed, "f", "redirected, the binder's entry replaced by the thief's").await?;
    let mut other = redirect(&honest);
    let mut vdata = other.frames[0].data.to_vec();
    vdata[40..60].copy_from_slice(thief.address().as_slice());
    other.frames[0].data = Bytes::from(vdata);
    other.signatures = vec![kohaku_frame_ticket::blind_account::binder_entry(thief.address())];
    sign_all(&mut other, &[FrameSigner::Secp256k1(thief.clone())])?;
    r.refused(&other, "f", "redirected, the thief named as binder and signing").await?;
    let rc = rpc::wait_for_confirmed_receipt(&r.provider, hash, Duration::from_mins(2), Duration::from_secs(2)).await?;
    r.note("f", json!({ "original": hash, "block": rc.block_number, "thiefBalance": r.provider.get_balance(thief.address()).await? })).await;

    // (g): aggregate payouts of 2, 4 and 8 tickets, one binder each.
    for (k, n) in [(5u64, 2usize), (6, 4), (7, 5)] {
        r.buy(e(k), n as u64).await?;
        let b = r.key(&format!("binder/g{n}"));
        let tickets = (0..n).map(|i| r.issue(e(k), b.address(), &format!("g{n}/{i}"), true)).collect::<anyhow::Result<Vec<_>>>()?;
        let tx = r.payout(&tickets, r.key(&format!("to/g{n}")).address(), &b, r.fees().await?)?;
        r.mined(&tx, "g", &format!("an aggregate payout of {n} tickets")).await?;
        let (burned, minted) = r.count(D, e(k)).await?;
        r.note("g", json!({ "n": n, "burned": burned, "minted": minted })).await;
    }

    // Six tickets: past the prefix's state-gas cap.
    r.buy(e(8), 6).await?;
    let b = r.key("binder/g6");
    let tickets = (0..6).map(|i| r.issue(e(8), b.address(), &format!("g6/{i}"), true)).collect::<anyhow::Result<Vec<_>>>()?;
    let tx = r.payout(&tickets, r.key("to/g6").address(), &b, r.fees().await?)?;
    r.refused(&tx, "g", "an aggregate payout of 6 tickets").await?;

    let out = json!({
        "chainId": chain_id,
        "account": r.address(),
        "codeBytes": r.account.initcode().len(),
        "denomination": D,
        "epochBase": base,
        "issuers": ISSUERS,
        "quorum": r.committee.quorum(),
        "issuersSaw": r.seen,
        "claimSelector": hex(&CLAIM),
        "steps": r.record,
    });
    let path = env::var("RECORD").unwrap_or_else(|_| "blind-account-record.json".to_owned());
    fs::write(&path, serde_json::to_string_pretty(&out)?)?;
    println!("record: {path}");
    Ok(())
}
