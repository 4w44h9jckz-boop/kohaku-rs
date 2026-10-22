//! `exp-frames` experiment 36's run, read back with this crate: every mined spend rebuilt byte
//! for byte by the builder, every ticket verified, every issuer's answer checked against its
//! share's key. `tests/fixtures/record.json` is the run's record, copied from that experiment.

use alloy::primitives::{Address, B256, Bytes, U256};
use commonware_codec::ReadExt;
use commonware_cryptography::bls12381::primitives::{
    group::{G1, G2},
    variant::{MinSig, Variant},
};
use kohaku_frame_accounts::{
    account::{Eoa, Signer},
    builder::{Envelope, TxPlan},
};
use kohaku_frame_kit::{Frame, FrameTx};
use kohaku_frame_ticket::{Slot, Ticket, TicketSponsor, paymaster::TicketPaymaster};
use serde::Deserialize;

const BOARD: Address = alloy::primitives::address!("0x93DD748B72dA1b1B6F1d5ec78Cb91ee52F01727d");

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    paymaster: Address,
    denomination: U256,
    committee: Committee,
    setup: Mined,
    transcripts: Vec<Transcript>,
    spends: Vec<Mined>,
    at_once: Vec<Mined>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Committee {
    key: Bytes,
    partial_keys: Vec<Bytes>,
}

#[derive(Deserialize)]
struct Mined {
    hash: B256,
    raw: Bytes,
}

#[derive(Deserialize)]
struct Transcript {
    index: usize,
    answers: Vec<Answer>,
}

#[derive(Deserialize)]
struct Answer {
    blinded: Bytes,
    answer: Bytes,
}

fn record() -> Record {
    serde_json::from_str(include_str!("fixtures/record.json")).unwrap()
}

fn g1(b: &[u8]) -> G1 {
    G1::read(&mut &b[..]).unwrap()
}

fn g2(b: &[u8]) -> G2 {
    G2::read(&mut &b[..]).unwrap()
}

/// The spend as the example lays it out, from what a wallet decides.
fn rebuild(mined: &FrameTx, paymaster: Address, ticket: &Ticket) -> FrameTx {
    let account = Eoa::new(Signer::secp256k1(mined.sender));
    let mut sponsor = TicketSponsor::new(paymaster, ticket);
    let data = mined.frames[2].data.clone();
    let mut tx = TxPlan::new(&account)
        .sponsored_by(&mut sponsor)
        .call(
            Frame::sender(Some(BOARD))
                .with_data(data)
                .with_execution(30_000),
        )
        .build(&Envelope {
            chain_id: mined.chain_id,
            nonce_keys: vec![U256::ZERO],
            nonce_seq: 0,
            fees: mined.fees,
        })
        .unwrap();
    tx.signatures.clone_from(&mined.signatures);
    tx
}

#[test]
fn the_paymaster_is_this_crates_code_with_the_committees_key() {
    let r = record();
    let setup = FrameTx::decode(&r.setup.raw).unwrap();
    assert_eq!(setup.hash(), r.setup.hash);
    let deploy = &setup.frames[1].data;
    let paymaster = TicketPaymaster {
        key: g2(&r.committee.key),
        denomination: r.denomination,
        salt: B256::from_slice(&deploy[..32]),
    };
    assert_eq!(&deploy[32..], &paymaster.initcode()[..]);
    assert_eq!(paymaster.address(), r.paymaster);
}

#[test]
fn every_mined_spend_rebuilds_and_its_ticket_verifies() {
    let r = record();
    let key = g2(&r.committee.key);
    for m in r.spends.iter().chain(&r.at_once) {
        let mined = FrameTx::decode(&m.raw).unwrap();
        assert_eq!(mined.hash(), m.hash);
        let ticket = Ticket::from_pay_data(Slot::of(&mined), &mined.frames[1].data).unwrap();
        assert!(MinSig::verify(&key, &ticket.claim.point(), &ticket.signature).is_ok());
        assert_eq!(rebuild(&mined, r.paymaster, &ticket).encode(), m.raw);
    }
}

#[test]
fn every_answer_checks_against_its_issuers_share() {
    let r = record();
    let mut n = 0;
    for t in &r.transcripts {
        let share = g2(&r.committee.partial_keys[t.index]);
        for a in &t.answers {
            assert!(MinSig::verify(&share, &g1(&a.blinded), &g1(&a.answer)).is_ok());
            n += 1;
        }
    }
    // Six tickets, three answers each.
    assert_eq!(n, 18);
}
