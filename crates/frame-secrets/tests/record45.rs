//! `exp-frames` experiment 45's run, read back from its public record
//! (`tests/fixtures/record45.json`, copied from that experiment). The run's seed is not published,
//! so this checks what anyone can: every transaction decodes and hashes to itself; each posted
//! request and blinded answer satisfies the committee's key; the issuers saw those requests and
//! nothing else; and the ticket the rebuilt wallet spent verifies under the committee's key.

use alloy::primitives::{Address, B256, Bytes};
use alloy::sol_types::SolCall;
use commonware_codec::DecodeExt;
use commonware_cryptography::bls12381::primitives::{
    group::{G1, G2},
    ops,
    variant::{MinSig, Variant},
};
use kohaku_frame_kit::FrameTx;
use kohaku_frame_ticket::{Slot, Ticket, ticket::NAMESPACE};
use serde::Deserialize;

alloy::sol! {
    function post(bytes message);
}

#[derive(Deserialize)]
struct Record {
    build: Build,
    restore: Restore,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Build {
    public: Public,
    account0: Address,
    epoch: u64,
    steps: Vec<Step>,
    issuers: Vec<Issuer>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Public {
    paymaster: Address,
    committee_key: Bytes,
}

#[derive(Deserialize)]
struct Step {
    what: String,
    hash: B256,
    raw: Option<Bytes>,
    payer: Option<Address>,
}

#[derive(Deserialize)]
struct Issuer {
    saw: Vec<Bytes>,
}

#[derive(Deserialize)]
struct Restore {
    spends: Vec<Step>,
}

fn record() -> Record {
    serde_json::from_str(include_str!("fixtures/record45.json")).unwrap()
}

fn key(r: &Record) -> G2 {
    G2::decode(r.build.public.committee_key.as_ref()).unwrap()
}

#[test]
fn every_transaction_hashes_to_itself() {
    let r = record();
    for s in r.build.steps.iter().chain(&r.restore.spends) {
        if let Some(raw) = &s.raw {
            assert_eq!(FrameTx::decode(raw).unwrap().hash(), s.hash, "{}", s.what);
        }
    }
}

#[test]
fn posted_answers_are_the_committees_and_all_the_issuers_saw() {
    let r = record();
    let post = r
        .build
        .steps
        .iter()
        .find(|s| s.what.contains("blinded answer"))
        .unwrap();
    let tx = FrameTx::decode(post.raw.as_ref().unwrap()).unwrap();
    let mut requests = vec![];
    for f in tx.frames.iter().skip(1) {
        let m = postCall::abi_decode(&f.data).unwrap().message;
        assert_eq!(m.len(), 105);
        assert_eq!(m[0], 0x10);
        assert_eq!(
            u64::from_be_bytes(m[1..9].try_into().unwrap()),
            r.build.epoch
        );
        let blinded = G1::decode(&m[9..57]).unwrap();
        let answer = G1::decode(&m[57..105]).unwrap();
        // e(x * B, g2) = e(B, X).
        MinSig::verify(&key(&r), &blinded, &answer).unwrap();
        requests.push(Bytes::copy_from_slice(&m[9..57]));
    }
    let saw: Vec<&Bytes> = r.build.issuers.iter().flat_map(|i| &i.saw).collect();
    assert_eq!(saw.len(), 6, "two requests, each to three of four issuers");
    assert!(saw.iter().all(|b| requests.contains(b)));
}

#[test]
fn the_rebuilt_ticket_verifies_and_the_paymaster_paid() {
    let r = record();
    let spend = r
        .restore
        .spends
        .iter()
        .find(|s| s.what.contains("ticket"))
        .unwrap();
    assert_eq!(spend.payer, Some(r.build.public.paymaster));
    let tx = FrameTx::decode(spend.raw.as_ref().unwrap()).unwrap();
    let ticket = Ticket::from_pay_data(Slot::of(&tx), &tx.frames[1].data).unwrap();
    assert_eq!(ticket.claim.epoch, r.build.epoch);
    ops::verify_message::<MinSig>(
        &key(&r),
        NAMESPACE,
        &ticket.claim.message(),
        &ticket.signature,
    )
    .unwrap();
    // The fresh sender's first transaction, no ether of its own.
    assert_eq!(tx.nonce_seq, 0);
    let account = r
        .restore
        .spends
        .iter()
        .find(|s| s.what.contains("account"))
        .unwrap();
    let tx = FrameTx::decode(account.raw.as_ref().unwrap()).unwrap();
    assert_eq!(tx.sender, r.build.account0);
}
