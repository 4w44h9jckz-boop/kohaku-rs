//! `exp-frames` experiment 51 on the testnet (2026-10-21), checked from public data with this
//! crate alone. The enclave is simulated; what is checked is what the chain checked.

use std::{fs, path::Path};

use alloy::{
    primitives::{Address, B256, U256, address, b256, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_enclave::{
    ATTESTED, Outcome, PROVED, Statement, abi::recordCall, attestation_holds, enclave_key,
    outcome_tx, proof_holds,
};
use kohaku_frame_kit::{FrameTx, constants::mode, json::FrameTxJson};
use kohaku_frame_registry::Verifier;
use serde::Deserialize;

const VERIFIER: Address = address!("0x9732b4364573564A1DF6A63876b60c9A6AB9a437");
const OUTCOME: Address = address!("0x8A93f51D44199c074FC0bf0f28358F27FFD17938");
/// The SHA-256 of experiment 51's `enclave.ts`, the simulated enclave's measurement.
const MEASUREMENT: B256 =
    b256!("0xbb2fcc3350684526c79840482617ec5ce375650fa57162f45ca96c71698fc7b5");

const DEPLOY: &str = "0x30941135e24ee0670dcfb2ba94d15343e6f7d484ba46b396e80969be08abcea5";
const ATTESTED_TX: &str = "0xe294edcc0ea04cba5846032f6b70ee4fae4b0bb572b174028b4d7a34e4ed7cc2";
const PROVED_TX: &str = "0xd6a2834ce5e9ac8581672507586dc1776ff93b6d411a323ede79767c7a665540";

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
}

fn fixture(hash: &str) -> FrameTx {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{hash}.json"));
    let f: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    FrameTx::try_from(&f.tx).unwrap()
}

/// The outcome contract as deployed: the attestation key's public half is the initcode's tail.
fn outcome() -> Outcome {
    let deploy = fixture(DEPLOY);
    let verifier = Verifier {
        key: enclave_key(),
        salt: keccak256("exp-frames/51/verifier"),
    };
    assert_eq!(verifier.address(), VERIFIER);
    assert!(deploy.frames.contains(&verifier.deploy_frame()));
    let data = deploy
        .frames
        .iter()
        .filter(|f| f.mode == mode::SENDER && f.data.len() > 64)
        .map(|f| f.data.to_vec())
        .find(|d| *d != verifier.deploy_frame().data.to_vec())
        .unwrap();
    let n = data.len();
    let o = Outcome {
        verifier: VERIFIER,
        attestation_qx: B256::from_slice(&data[n - 64..n - 32]),
        attestation_qy: B256::from_slice(&data[n - 32..]),
        salt: keccak256("exp-frames/51/outcome"),
    };
    assert!(deploy.frames.contains(&o.deploy_frame()));
    o
}

fn recorded(tx: &FrameTx) -> recordCall {
    recordCall::abi_decode(&tx.frames[1].data).unwrap()
}

#[test]
fn lands_at_the_testnet_address() {
    assert_eq!(outcome().address(), OUTCOME);
}

#[test]
fn rebuilds_both_outputs_and_checks_their_evidence() {
    let o = outcome();
    for (hash, route) in [(ATTESTED_TX, ATTESTED), (PROVED_TX, PROVED)] {
        let mined = fixture(hash);
        let r = recorded(&mined);
        assert_eq!(r.route, U256::from(route));
        let rebuilt = outcome_tx(
            &o,
            mined.chain_id,
            route,
            r.measurement,
            r.statement,
            r.evidence,
            mined.fees,
        );
        assert_eq!(format!("{:#x}", rebuilt.hash()), hash);
    }
    let a = recorded(&fixture(ATTESTED_TX));
    let b = recorded(&fixture(PROVED_TX));
    assert_eq!(a.statement, b.statement);
    assert_eq!(a.measurement, MEASUREMENT);
    assert!(attestation_holds(
        &o,
        a.measurement,
        &a.statement,
        a.evidence[0],
        a.evidence[1]
    ));
    assert!(proof_holds(&b.statement, &b.evidence));
}

#[test]
fn the_attestation_binds_the_keys_word_the_proof_binds_the_output() {
    let o = outcome();
    let a = recorded(&fixture(ATTESTED_TX));
    let b = recorded(&fixture(PROVED_TX));
    let mut flipped: Statement = b.statement;
    flipped[8] = U256::from(1) - flipped[8];
    // The proof refuses the other output, and another ciphertext.
    assert!(!proof_holds(&flipped, &b.evidence));
    let mut other = b.statement;
    other[4] += U256::from(1);
    assert!(!proof_holds(&other, &b.evidence));
    // The mined attestation does not carry over to another output or measurement; a fresh one
    // by the same key would (experiment 51's D1 and D2), and nothing here can tell it apart.
    assert!(!attestation_holds(
        &o,
        a.measurement,
        &flipped,
        a.evidence[0],
        a.evidence[1]
    ));
    assert!(!attestation_holds(
        &o,
        B256::ZERO,
        &a.statement,
        a.evidence[0],
        a.evidence[1]
    ));
}
