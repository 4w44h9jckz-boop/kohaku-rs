//! `exp-frames` experiment 48's run, read back from its public record
//! (`tests/fixtures/record48.json`, copied from that experiment): each bound ticket spent
//! verifies under the committee's key over the 152-byte message, its transaction carries the
//! binder's entry, and each refused copy lacks what the binding asks.

use alloy::primitives::{Address, B256, Bytes};
use commonware_codec::DecodeExt;
use commonware_cryptography::bls12381::primitives::{group::G2, ops, variant::MinSig};
use kohaku_frame_kit::{FrameTx, constants::mode};
use kohaku_frame_ticket::{
    Slot,
    bound::{BoundTicket, bound_paymaster_code, is_bound},
    ticket::NAMESPACE,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Record {
    committee_key: Bytes,
    bound_paymaster: Address,
    bound_template: Template,
    spends: Vec<Step>,
    binding: Vec<Step>,
}

#[derive(Deserialize)]
struct Template {
    length: usize,
    keccak256: B256,
}

#[derive(Deserialize)]
struct Step {
    what: String,
    raw: Bytes,
}

fn record() -> Record {
    serde_json::from_str(include_str!("fixtures/record48.json")).unwrap()
}

fn bound_ticket(tx: &FrameTx, paymaster: Address) -> BoundTicket {
    let pay = tx
        .frames
        .iter()
        .find(|f| f.mode == mode::VERIFY && f.target == Some(paymaster))
        .unwrap();
    BoundTicket::from_pay_data(Slot::of(tx), &pay.data).unwrap()
}

#[test]
fn the_template_is_the_embedded_code() {
    let r = record();
    // The 25-byte constructor, then the runtime, which is the template.
    let code = bound_paymaster_code();
    assert_eq!(code.len() - 25, r.bound_template.length);
    assert_eq!(
        alloy::primitives::keccak256(&code[25..]),
        r.bound_template.keccak256
    );
}

#[test]
fn spent_bound_tickets_verify_and_are_bound() {
    let r = record();
    let key = G2::decode(r.committee_key.as_ref()).unwrap();
    for part in [", bound ticket", "bound: mined"] {
        let s = r
            .spends
            .iter()
            .chain(&r.binding)
            .find(|s| s.what.contains(part))
            .unwrap();
        let tx = FrameTx::decode(&s.raw).unwrap();
        let t = bound_ticket(&tx, r.bound_paymaster);
        ops::verify_message::<MinSig>(&key, NAMESPACE, &t.claim.message(), &t.signature).unwrap();
        assert!(is_bound(&tx, t.claim.binder), "{}", s.what);
    }
}

#[test]
fn refused_copies_lack_the_binding() {
    let r = record();
    let key = G2::decode(r.committee_key.as_ref()).unwrap();
    let copy = |part: &str| {
        FrameTx::decode(
            &r.binding
                .iter()
                .find(|s| s.what.contains(part))
                .unwrap()
                .raw,
        )
        .unwrap()
    };
    let original = copy("bound: mined");
    let kept = copy("signature kept");
    // The entry is there; its signature is over the original's hash, not this one's.
    assert!(is_bound(
        &kept,
        bound_ticket(&kept, r.bound_paymaster).claim.binder
    ));
    assert_ne!(kept.sig_hash(), original.sig_hash());
    let removed = copy("entry removed");
    assert!(!is_bound(
        &removed,
        bound_ticket(&removed, r.bound_paymaster).claim.binder
    ));
    let other = copy("another key");
    let t = bound_ticket(&other, r.bound_paymaster);
    assert!(is_bound(&other, t.claim.binder));
    assert!(
        ops::verify_message::<MinSig>(&key, NAMESPACE, &t.claim.message(), &t.signature).is_err()
    );
}
