//! `exp-frames` experiment 46's run, read back from its public record
//! (`tests/fixtures/record46.json`, copied from that experiment): each commitment the owner set
//! is the hash of the reveal its start later carried, the old set's refused start revealed the
//! replaced one, and each envelope carries its recovery key's locator at one size.

use alloy::{
    primitives::{Address, B256, Bytes, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_kit::{FrameTx, constants::mode};
use kohaku_frame_secrets::guardians::{ENVELOPE_LEN, ENVELOPE_TAG, locator};
use serde::Deserialize;

alloy::sol! {
    function post(bytes message);
}

#[derive(Deserialize)]
struct Record {
    setup: Setup,
    recover: Recover,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Setup {
    recovery_keys: Vec<Address>,
    commitments: Vec<B256>,
    steps: Vec<Step>,
    refusals: Vec<Step>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Recover {
    recovery_keys: Vec<Address>,
    commitment2: B256,
    steps: Vec<Step>,
}

#[derive(Deserialize)]
struct Step {
    what: String,
    raw: Bytes,
}

fn record() -> Record {
    serde_json::from_str(include_str!("fixtures/record46.json")).unwrap()
}

fn tx(steps: &[Step], part: &str) -> FrameTx {
    let s = steps.iter().find(|s| s.what.contains(part)).unwrap();
    FrameTx::decode(&s.raw).unwrap()
}

/// The reveal in a start's `VERIFY` frame: salt || 1 || address(R).
fn reveal(t: &FrameTx) -> (B256, Address) {
    let v = t.frames.iter().find(|f| f.mode == mode::VERIFY).unwrap();
    assert_eq!(v.data.len(), 53);
    assert_eq!(v.data[32], 1);
    (keccak256(&v.data), Address::from_slice(&v.data[33..53]))
}

#[test]
fn each_start_reveals_the_commitment_then_in_force() {
    let r = record();
    let all: Vec<Step> = r.setup.steps.into_iter().chain(r.recover.steps).collect();
    let (c, key) = reveal(&tx(&all, "guardians 2 and 3 start"));
    assert_eq!((c, key), (r.setup.commitments[0], r.setup.recovery_keys[0]));
    let (c, key) = reveal(&tx(&all, "R1 starts"));
    assert_eq!((c, key), (r.setup.commitments[1], r.setup.recovery_keys[1]));
    let (c, _) = reveal(&tx(&r.setup.refusals, "old set"));
    assert_eq!(c, r.setup.commitments[0]);
    // The owner set three commitments, and the last is the one recovery left in force.
    for (part, want) in [
        ("commits the account to R0", r.setup.commitments[0]),
        ("rotates to R1", r.setup.commitments[1]),
        ("rotates to R2", r.recover.commitment2),
    ] {
        let t = tx(&all, part);
        let op = &t.frames.iter().find(|f| f.mode == mode::SENDER).unwrap().data;
        assert_eq!(op[0], 0x04);
        assert_eq!(B256::from_slice(&op[1..33]), want);
    }
}

#[test]
fn each_envelope_is_one_size_under_its_locator() {
    let r = record();
    let all: Vec<Step> = r.setup.steps.into_iter().chain(r.recover.steps).collect();
    let keys = [
        r.setup.recovery_keys[0],
        r.setup.recovery_keys[1],
        r.recover.recovery_keys[1],
    ];
    for (part, key) in ["envelope under R0", "envelope under R1", "envelope under R2"]
        .iter()
        .zip(keys)
    {
        let t = tx(&all, part);
        let post = t.frames.iter().find(|f| f.mode == mode::SENDER).unwrap();
        let m = postCall::abi_decode(&post.data).unwrap().message;
        assert_eq!(m.len(), ENVELOPE_LEN);
        assert_eq!(m[0], ENVELOPE_TAG);
        assert_eq!(&m[1..33], locator(key).as_slice());
    }
}
