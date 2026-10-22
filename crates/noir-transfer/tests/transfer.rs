//! The wallet side of experiment 42 against what Barretenberg and Noir's JavaScript packages
//! produced: Poseidon2 against `bb.js`'s outputs, the witness against `build/drive.mjs`'s
//! transfer, and, when `BB` names Barretenberg's binary, a proof Barretenberg verifies.

use std::env;
use std::path::PathBuf;

use acvm::{AcirField, FieldElement};
use kohaku_noir_transfer::{
    Circuit, Request, TRANSFER_JSON, Target, hash, hex32, note_hash, owner_of, prove, transfer,
};
use serde_json::Value;

fn fixture(name: &str) -> Value {
    let path = format!("{}/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn f(s: &str) -> FieldElement {
    FieldElement::try_from_str(s).unwrap()
}

#[test]
fn poseidon2_matches_barretenberg() {
    let v = fixture("poseidon2.vectors.json");
    for case in v["sponge"].as_array().unwrap() {
        let inputs: Vec<FieldElement> = case["inputs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| f(x.as_str().unwrap()))
            .collect();
        assert_eq!(hex32(hash(&inputs)), case["hash"].as_str().unwrap());
    }
}

/// `build/drive.mjs`'s transfer: four notes, the sender's at 0 and 2, two outputs and a fee of 1.
fn drive_request() -> Request {
    let nsk = f("0x1234567890abcdef");
    let other = owner_of(f("0xfeed"));
    let owner = owner_of(nsk);
    let notes = [
        (owner, 700, 11),
        (other, 5, 12),
        (owner, 400, 13),
        (other, 9, 14),
    ];
    let leaves: Vec<String> = notes
        .iter()
        .map(|&(o, v, r)| hex32(note_hash(o, v, FieldElement::from(r))))
        .collect();
    serde_json::from_value(serde_json::json!({
        "nsk": "0x1234567890abcdef",
        "spend": [{ "index": 0, "value": "700", "randomness": "11" }, { "index": 2, "value": "400", "randomness": "13" }],
        "outs": [{ "owner": hex32(other), "value": "600", "randomness": "21" }, { "owner": hex32(owner), "value": "499", "randomness": "22" }],
        "fee": "1",
        "context": "0xc0ffee",
        "leaves": leaves,
        "target": "evm",
    }))
    .unwrap()
}

#[test]
fn witness_matches_noir_js() {
    let summary = fixture("drive.summary.json");
    let t = transfer(&drive_request()).unwrap();
    assert_eq!(hex32(t.root), summary["root"].as_str().unwrap());
    let mut expected: Vec<String> = summary["nullifiers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap().to_string())
        .collect();
    expected.sort();
    assert_eq!(
        t.nullifiers.map(hex32).to_vec(),
        expected,
        "the nullifiers, ascending"
    );
    assert_eq!(
        t.out_hashes.map(hex32).to_vec(),
        summary["outHashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap())
            .collect::<Vec<_>>()
    );

    let circuit = Circuit::from_json(TRANSFER_JSON).unwrap();
    assert!(circuit.noir_version.starts_with("1.0.0-rc.6+"));
    circuit
        .execute(&t.inputs)
        .expect("the circuit accepts the transfer");

    // One unit more out than in: the circuit refuses it.
    let mut bad = t.inputs.clone();
    let last_value = bad.len() - 3;
    bad[last_value] += FieldElement::one();
    assert!(circuit.execute(&bad).is_err());
}

#[test]
fn proves_with_barretenberg() {
    let Ok(bb) = env::var("BB") else {
        eprintln!("BB is not set; skipping the proof");
        return;
    };
    let circuit = Circuit::from_json(TRANSFER_JSON).unwrap();
    let t = transfer(&drive_request()).unwrap();
    let witness = circuit.execute(&t.inputs).unwrap();
    for target in [Target::Evm, Target::EvmNoZk] {
        let proof = prove(&PathBuf::from(&bb), &circuit, &witness, target).unwrap();
        assert!(proof.verified);
        assert_eq!(proof.public_inputs.len(), 7);
        let fields = proof.proof.len() / 32;
        assert_eq!(fields, if target == Target::Evm { 250 } else { 221 });
    }
}
