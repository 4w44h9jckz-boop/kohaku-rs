//! Experiment 27's vectors (`experiments/27-execution-digest/erc-assets/` in exp-frames), produced
//! by the TypeScript reference through viem's EIP-712 encoder, in two sets: under EIP-8250 at
//! master, where `nonce_keys == []` selects the legacy nonce, and under `f3079a09e8`, which the
//! Hegota testnet pins, where `[0]` did. This crate computes the same digests through alloy's,
//! from the decoded transactions, each decoded under its set's rules.

use alloy::primitives::{Address, B256};
use kohaku_frame_kit::{
    Eip8250, FrameTx,
    digest::{execution_digest, execution_domain, execution_struct_hash, is_pay_frame},
    signer_of,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    domain_separator: B256,
    struct_hash: B256,
    execution_digest: B256,
    pay_frames: Vec<usize>,
    raw: alloy::primitives::Bytes,
}

#[derive(Deserialize)]
struct Vectors {
    owner: Address,
    cases: Vec<Case>,
}

/// Both sets, with the rules each is decoded under and how many vectors it holds.
fn sets() -> [(Vectors, Eip8250, usize); 2] {
    [
        (
            serde_json::from_str(include_str!("fixtures/exp27-execution-digest.json")).unwrap(),
            Eip8250::Master,
            11,
        ),
        (
            serde_json::from_str(include_str!(
                "fixtures/exp27-execution-digest-eip8250-f3079a0.json"
            ))
            .unwrap(),
            Eip8250::F3079a0,
            10,
        ),
    ]
}

#[test]
fn every_vector_digests_the_same_through_alloy() {
    for (vectors, rules, n) in sets() {
        check(&vectors, rules, n);
    }
}

#[test]
fn the_legacy_nonce_is_empty_at_master_and_zero_at_f3079a0() {
    let [(master, ..), (pinned, ..)] = sets();
    let legacy = |v: &Vectors, rules| {
        let c = v.cases.iter().find(|c| c.name == "legacy-nonce-7").unwrap();
        FrameTx::decode_with(&c.raw, rules).unwrap().nonce_keys
    };
    assert!(legacy(&master, Eip8250::Master).is_empty());
    assert_eq!(
        legacy(&pinned, Eip8250::F3079a0),
        vec![alloy::primitives::U256::ZERO]
    );
    // The testnet's decoder refuses master's legacy nonce, and master's key 0 is the testnet's
    // legacy nonce: the same bytes, another nonce domain.
    let raw =
        |v: &Vectors, name: &str| v.cases.iter().find(|c| c.name == name).unwrap().raw.clone();
    assert!(FrameTx::decode(&raw(&master, "legacy-nonce-7")).is_err());
    assert_eq!(
        FrameTx::decode(&raw(&master, "key-zero")).unwrap(),
        FrameTx::decode_with(&raw(&master, "key-zero"), Eip8250::Master).unwrap()
    );
}

fn check(vectors: &Vectors, rules: Eip8250, n: usize) {
    assert_eq!(vectors.cases.len(), n);
    for case in &vectors.cases {
        let tx =
            FrameTx::decode_with(&case.raw, rules).unwrap_or_else(|e| panic!("{}: {e}", case.name));
        let pay: Vec<usize> = (0..tx.frames.len())
            .filter(|&i| is_pay_frame(&tx.frames[i]))
            .collect();
        assert_eq!(pay, case.pay_frames, "{}: pay frames", case.name);
        assert_eq!(
            execution_domain(&tx).separator(),
            case.domain_separator,
            "{}: domain separator",
            case.name
        );
        assert_eq!(
            execution_struct_hash(&tx),
            case.struct_hash,
            "{}: struct hash",
            case.name
        );
        assert_eq!(
            execution_digest(&tx),
            case.execution_digest,
            "{}: E",
            case.name
        );

        // The owner's entry carries E as its explicit msg, and recovers to the owner over it.
        let entry = &tx.signatures[0];
        assert_eq!(
            entry.msg.as_ref(),
            case.execution_digest.as_slice(),
            "{}: entry 0 msg",
            case.name
        );
        assert_eq!(
            signer_of(entry, tx.sig_hash()).unwrap(),
            vectors.owner,
            "{}: entry 0 signer",
            case.name
        );
    }
}

#[test]
fn the_payer_part_does_not_move_e() {
    let vectors: Vectors =
        serde_json::from_str(include_str!("fixtures/exp27-execution-digest.json")).unwrap();
    let case = vectors
        .cases
        .iter()
        .find(|c| c.name == "sponsored-transfer")
        .unwrap();
    let tx = FrameTx::decode_with(&case.raw, Eip8250::Master).unwrap();
    let mut other = tx.clone();
    let pay = case.pay_frames[0];
    other.frames[pay].target = Some(Address::repeat_byte(0xbb));
    other.frames[pay].limits.execution = 77_777;
    other.frames[pay].data = vec![0xde, 0xad].into();
    other.fees.max_priority_fee_per_gas *= 20;
    other.fees.max_fee_per_gas *= 20;
    other.signatures.truncate(1);
    assert_eq!(execution_digest(&other), case.execution_digest);
    assert_ne!(other.sig_hash(), tx.sig_hash());

    let mut moved = tx.clone();
    moved.frames[2].limits.state = 0;
    assert_ne!(execution_digest(&moved), case.execution_digest);
}
