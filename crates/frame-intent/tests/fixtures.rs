//! The checker against hand-written fixtures in `docs/simulated-writes.md`'s format (exp-e2e-frames
//! at `f8c7361`). These are fixtures, not a chain's output: the coordinator reruns the cases against
//! the patched local chain.

use std::collections::HashMap;

use alloy::{
    primitives::{Address, B256, Bytes, I256, U256, address},
    signers::local::PrivateKeySigner,
};
use kohaku_frame_intent::{
    Registry, Simulation, Status, check,
    encode::{ASSERT_NAMED, ASSERT_WRITES, assert_named, assert_writes, named_entries, sign_batch},
    expand,
    layout::{address_slot, nested_slot},
    writes::{AccountWrites, Field, SlotWrite},
};
use kohaku_frame_kit::{
    Eip8250, Fees, Frame, FrameSignature, FrameSigner, FrameTx,
    constants::{ATOMIC_BATCH_FLAG, NONCE_MANAGER, approve, scheme},
    rpc::keyed_nonce_slot,
    signer_of,
};

const TOKEN: Address = address!("0x2700000000000000000000000000000000000010");
const OTHER: Address = address!("0x2700000000000000000000000000000000000011");
const DEX: Address = address!("0x2700000000000000000000000000000000000012");
const TO: Address = address!("0x2700000000000000000000000000000000000013");
const SPENDER: Address = address!("0x00000000000000000000000000000000000badd1");
const FEE_RECIPIENT: Address = Address::ZERO;
const MAX_COST: u64 = 1_000_000;

fn registry() -> Registry {
    serde_json::from_str(&format!(
        r#"{{"{TOKEN}":{{"kind":"erc20","balanceSlot":3,"allowanceSlot":4}},"{OTHER}":{{"kind":"erc20","balanceSlot":3,"allowanceSlot":4}},"{DEX}":{{"kind":"dex"}}}}"#
    ))
    .unwrap()
}

fn key() -> PrivateKeySigner {
    // A key from a public label: a fixture, not an account.
    PrivateKeySigner::from_bytes(&alloy::primitives::keccak256("exp-frames/58/fixture-owner"))
        .unwrap()
}

fn tx(nonce_keys: Vec<U256>) -> FrameTx {
    let sender = address!("0x2700000000000000000000000000000000000001");
    FrameTx {
        chain_id: 8141,
        nonce_keys,
        nonce_seq: 0,
        sender,
        frames: vec![
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None).with_execution(60_000),
            Frame::sender(Some(TOKEN)).with_execution(60_000),
            Frame::sender(None)
                .with_data(Bytes::from(ASSERT_NAMED.to_vec()))
                .with_execution(30_000),
        ],
        signatures: vec![FrameSignature {
            scheme: scheme::SECP256K1,
            signer: Some(key().address()),
            msg: Bytes::new(),
            signature: Bytes::new(),
        }],
        fees: Fees {
            max_priority_fee_per_gas: 1,
            max_fee_per_gas: 100,
            max_fee_per_blob_gas: 0,
        },
        blob_versioned_hashes: vec![],
    }
}

fn u(n: u64) -> U256 {
    U256::from(n)
}
fn e18(n: u64) -> U256 {
    U256::from(n) * U256::from(10).pow(U256::from(18))
}
fn slot(a: Address, s: B256, before: U256, after: U256) -> AccountWrites {
    AccountWrites {
        address: a,
        removed: false,
        balance: None,
        nonce: None,
        code_hash: None,
        storage: vec![SlotWrite {
            slot: s.into(),
            before,
            after,
        }],
    }
}
fn bal(a: Address, before: U256, after: U256) -> AccountWrites {
    AccountWrites {
        address: a,
        removed: false,
        balance: Some([before, after]),
        nonce: None,
        code_hash: None,
        storage: vec![],
    }
}

/// What every frame transaction writes: the fee (payer down, fee recipient up) and the nonce.
fn fee_and_nonce(t: &FrameTx, fee: u64) -> Vec<AccountWrites> {
    let mut w = vec![
        bal(FEE_RECIPIENT, u(0), u(fee)),
        bal(t.sender, e18(100), e18(100) - u(fee)),
    ];
    for k in t.nonce_keys.iter().filter(|k| !k.is_zero()) {
        w.push(slot(
            NONCE_MANAGER,
            keyed_nonce_slot(t.sender, *k),
            u(0),
            u(1),
        ));
    }
    if t.nonce_keys.iter().all(U256::is_zero) {
        w.push(AccountWrites {
            address: t.sender,
            removed: false,
            balance: None,
            nonce: Some([u(0), u(1)]),
            code_hash: None,
            storage: vec![],
        });
    }
    w
}

fn sim(writes: Vec<AccountWrites>) -> Simulation {
    Simulation {
        valid: true,
        violation: None,
        execution_status: Some("success".into()),
        max_cost: Some(u(MAX_COST)),
        payer: None,
        writes: Some(writes),
    }
}

fn transfer_writes(t: &FrameTx) -> Vec<AccountWrites> {
    vec![
        slot(TOKEN, address_slot(t.sender, 3), e18(1000), e18(990)),
        slot(TOKEN, address_slot(TO, 3), u(0), e18(10)),
    ]
}

fn params(kv: &[(&str, String)]) -> HashMap<String, String> {
    kv.iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect()
}

fn transfer_intent(t: &FrameTx) -> kohaku_frame_intent::Intent {
    expand(
        "erc20-transfer",
        &params(&[
            ("token", TOKEN.to_string()),
            ("to", TO.to_string()),
            ("amount", e18(10).to_string()),
        ]),
        t.sender,
        &registry(),
    )
    .unwrap()
}

#[test]
fn an_honest_transfer_passes_with_fee_and_nonce_exempt_by_kind() {
    for keys in [vec![u(0x57a1)], vec![U256::ZERO]] {
        let t = tx(keys);
        let mut w = transfer_writes(&t);
        w.extend(fee_and_nonce(&t, 5_000));
        let v = check(
            &t,
            &sim(w),
            &transfer_intent(&t),
            FEE_RECIPIENT,
            Eip8250::F3079a0,
        );
        assert_eq!(v.status, Status::Pass, "{v:#?}");
        assert_eq!(v.matched.len(), 2);
        assert_eq!(v.exempt.len(), 3);
    }
}

#[test]
fn an_added_approval_is_one_unlisted_slot() {
    let t = tx(vec![u(0x57a1)]);
    let mut w = transfer_writes(&t);
    w[0].storage.push(SlotWrite {
        slot: nested_slot(t.sender, SPENDER, 4).into(),
        before: u(0),
        after: U256::MAX,
    });
    w.extend(fee_and_nonce(&t, 5_000));
    let v = check(
        &t,
        &sim(w),
        &transfer_intent(&t),
        FEE_RECIPIENT,
        Eip8250::F3079a0,
    );
    assert_eq!(v.status, Status::Fail);
    assert_eq!(v.unlisted.len(), 1);
    assert_eq!(
        v.unlisted[0].field,
        Field::Storage(nested_slot(t.sender, SPENDER, 4))
    );
    assert!(v.missing.is_empty() && v.mismatched.is_empty());
}

#[test]
fn a_lying_token_is_unlisted_and_missing() {
    // Experiment 54's lying token: held[sender] falls, held[sink] and told[recipient] rise, and the
    // recipient's held slot, the one an honest transfer writes, does not change.
    let t = tx(vec![u(0x57a1)]);
    let sink = address!("0x00000000000000000000000000000000000051c4");
    let liar: Registry = serde_json::from_str(&format!(
        r#"{{"{TOKEN}":{{"kind":"erc20","balanceSlot":1,"allowanceSlot":9}}}}"#
    ))
    .unwrap();
    let intent = expand(
        "erc20-transfer",
        &params(&[
            ("token", TOKEN.to_string()),
            ("to", TO.to_string()),
            ("amount", e18(10).to_string()),
        ]),
        t.sender,
        &liar,
    )
    .unwrap();
    let mut w = vec![AccountWrites {
        address: TOKEN,
        removed: false,
        balance: None,
        nonce: None,
        code_hash: None,
        storage: vec![
            SlotWrite {
                slot: address_slot(t.sender, 1).into(),
                before: e18(1000),
                after: e18(990),
            },
            SlotWrite {
                slot: address_slot(sink, 1).into(),
                before: u(0),
                after: e18(10),
            },
            SlotWrite {
                slot: address_slot(TO, 2).into(),
                before: u(0),
                after: e18(10),
            },
        ],
    }];
    w.extend(fee_and_nonce(&t, 5_000));
    let v = check(&t, &sim(w), &intent, FEE_RECIPIENT, Eip8250::F3079a0);
    assert_eq!(v.status, Status::Fail);
    assert_eq!(v.unlisted.len(), 2);
    assert_eq!(v.missing.len(), 1);
}

#[test]
fn a_wrong_amount_is_a_mismatch_and_a_retargeted_token_is_missing() {
    let t = tx(vec![u(0x57a1)]);
    let mut w = vec![
        slot(TOKEN, address_slot(t.sender, 3), e18(1000), e18(989)),
        slot(TOKEN, address_slot(TO, 3), u(0), e18(11)),
    ];
    w.extend(fee_and_nonce(&t, 5_000));
    let v = check(
        &t,
        &sim(w),
        &transfer_intent(&t),
        FEE_RECIPIENT,
        Eip8250::F3079a0,
    );
    assert_eq!((v.status, v.mismatched.len()), (Status::Fail, 2));

    let mut w = vec![
        slot(OTHER, address_slot(t.sender, 3), e18(1000), e18(990)),
        slot(OTHER, address_slot(TO, 3), u(0), e18(10)),
    ];
    w.extend(fee_and_nonce(&t, 5_000));
    let v = check(
        &t,
        &sim(w),
        &transfer_intent(&t),
        FEE_RECIPIENT,
        Eip8250::F3079a0,
    );
    assert_eq!(
        (v.status, v.unlisted.len(), v.missing.len()),
        (Status::Fail, 2, 2)
    );
}

#[test]
fn the_exemptions_are_bounded() {
    let t = tx(vec![u(0x57a1)]);
    // A fee above the maximum cost is not a fee.
    let mut w = transfer_writes(&t);
    w.extend(fee_and_nonce(&t, MAX_COST + 1));
    let v = check(
        &t,
        &sim(w),
        &transfer_intent(&t),
        FEE_RECIPIENT,
        Eip8250::F3079a0,
    );
    assert_eq!((v.status, v.unlisted.len()), (Status::Fail, 2));
    // A nonce record moving by two is not a nonce.
    let mut w = transfer_writes(&t);
    let mut fn_ = fee_and_nonce(&t, 5_000);
    fn_[2].storage[0].after = u(2);
    w.extend(fn_);
    assert_eq!(
        check(
            &t,
            &sim(w),
            &transfer_intent(&t),
            FEE_RECIPIENT,
            Eip8250::F3079a0
        )
        .status,
        Status::Fail
    );
    // Another slot of the nonce manager is not the sender's nonce.
    let mut w = transfer_writes(&t);
    w.extend(fee_and_nonce(&t, 5_000));
    w.push(slot(
        NONCE_MANAGER,
        keyed_nonce_slot(SPENDER, u(1)),
        u(0),
        u(1),
    ));
    assert_eq!(
        check(
            &t,
            &sim(w),
            &transfer_intent(&t),
            FEE_RECIPIENT,
            Eip8250::F3079a0
        )
        .status,
        Status::Fail
    );
    // A code change is never exempt.
    let mut w = transfer_writes(&t);
    w.extend(fee_and_nonce(&t, 5_000));
    w.push(AccountWrites {
        address: t.sender,
        removed: false,
        balance: None,
        nonce: None,
        code_hash: Some([B256::ZERO, B256::repeat_byte(1)]),
        storage: vec![],
    });
    assert_eq!(
        check(
            &t,
            &sim(w),
            &transfer_intent(&t),
            FEE_RECIPIENT,
            Eip8250::F3079a0
        )
        .status,
        Status::Fail
    );
}

#[test]
fn an_ether_transfer_counts_the_value_beside_the_fee() {
    let t = tx(vec![u(0x57a1)]);
    let intent = expand(
        "eth-transfer",
        &params(&[("to", TO.to_string()), ("value", "5".into())]),
        t.sender,
        &registry(),
    )
    .unwrap();
    let mut w = vec![bal(TO, u(0), u(5))];
    let mut fnn = fee_and_nonce(&t, 5_000);
    fnn[1] = bal(t.sender, e18(100), e18(100) - u(5_005));
    w.extend(fnn);
    assert_eq!(
        check(&t, &sim(w), &intent, FEE_RECIPIENT, Eip8250::F3079a0).status,
        Status::Pass
    );
}

#[test]
fn a_swap_output_is_one_amount_at_least_the_minimum() {
    let t = tx(vec![u(0x57a1)]);
    let p = params(&[
        ("token-in", TOKEN.to_string()),
        ("amount-in", e18(10).to_string()),
        ("dex", DEX.to_string()),
        ("token-out", OTHER.to_string()),
        ("min-out", e18(9).to_string()),
    ]);
    let intent = expand("approve-and-swap", &p, t.sender, &registry()).unwrap();
    let w = |out_dex: U256, out_user: U256| {
        let mut w = vec![
            AccountWrites {
                address: TOKEN,
                removed: false,
                balance: None,
                nonce: None,
                code_hash: None,
                storage: vec![
                    SlotWrite {
                        slot: address_slot(t.sender, 3).into(),
                        before: e18(100),
                        after: e18(90),
                    },
                    SlotWrite {
                        slot: address_slot(DEX, 3).into(),
                        before: e18(500),
                        after: e18(510),
                    },
                ],
            },
            AccountWrites {
                address: OTHER,
                removed: false,
                balance: None,
                nonce: None,
                code_hash: None,
                storage: vec![
                    SlotWrite {
                        slot: address_slot(t.sender, 3).into(),
                        before: u(0),
                        after: out_user,
                    },
                    SlotWrite {
                        slot: address_slot(DEX, 3).into(),
                        before: e18(500),
                        after: e18(500) - out_dex,
                    },
                ],
            },
        ];
        w.extend(fee_and_nonce(&t, 5_000));
        w
    };
    assert_eq!(
        check(
            &t,
            &sim(w(e18(9) + u(7), e18(9) + u(7))),
            &intent,
            FEE_RECIPIENT,
            Eip8250::F3079a0
        )
        .status,
        Status::Pass
    );
    assert_eq!(
        check(
            &t,
            &sim(w(e18(8), e18(8))),
            &intent,
            FEE_RECIPIENT,
            Eip8250::F3079a0
        )
        .status,
        Status::Fail,
        "below the minimum"
    );
    assert_eq!(
        check(
            &t,
            &sim(w(e18(10), e18(9))),
            &intent,
            FEE_RECIPIENT,
            Eip8250::F3079a0
        )
        .status,
        Status::Fail,
        "the DEX pays more than the user gets"
    );
}

#[test]
fn a_replay_has_the_same_writes_as_its_original() {
    // Experiment 58's probe C1: under a revision switch the nonce record reads empty again, so the
    // replay writes what the original wrote. The list cannot tell them apart.
    let t = tx(vec![u(0x57a1)]);
    let mut w = transfer_writes(&t);
    w.extend(fee_and_nonce(&t, 5_000));
    let original = check(
        &t,
        &sim(w.clone()),
        &transfer_intent(&t),
        FEE_RECIPIENT,
        Eip8250::F3079a0,
    );
    let replay = check(
        &t,
        &sim(w),
        &transfer_intent(&t),
        FEE_RECIPIENT,
        Eip8250::F3079a0,
    );
    assert_eq!(original, replay);
    assert_eq!(replay.status, Status::Pass);
}

#[test]
fn invalid_or_unexecuted_is_not_simulated() {
    let t = tx(vec![u(0x57a1)]);
    let mut s = sim(vec![]);
    s.writes = None;
    assert_eq!(
        check(
            &t,
            &s,
            &transfer_intent(&t),
            FEE_RECIPIENT,
            Eip8250::F3079a0
        )
        .status,
        Status::NotSimulated
    );
    s.valid = false;
    s.violation = Some("validation prefix frame reverted".into());
    assert_eq!(
        check(
            &t,
            &s,
            &transfer_intent(&t),
            FEE_RECIPIENT,
            Eip8250::F3079a0
        )
        .status,
        Status::NotSimulated
    );
}

#[test]
fn the_two_encodings_and_the_signed_batch() {
    let t = tx(vec![u(0x57a1)]);
    let mut w = transfer_writes(&t);
    w.extend(fee_and_nonce(&t, 5_000));
    let intent = transfer_intent(&t);
    let v = check(&t, &sim(w), &intent, FEE_RECIPIENT, Eip8250::F3079a0);

    let aw = assert_writes(&v, t.sender).unwrap();
    assert_eq!(&aw[..4], &ASSERT_WRITES);
    // two token slots and the nonce record; no balance besides the payer's; then the payer
    assert_eq!(U256::from_be_slice(&aw[4..36]), u(3));
    assert_eq!(aw.len(), 4 + 32 + 3 * 96 + 32 + 32);
    assert_eq!(&aw[aw.len() - 20..], t.sender.as_slice());

    let named = assert_named(&v, &intent).unwrap();
    assert_eq!(named_entries(&named), 2);
    // the recipient's balanceOf, expected 10e18
    // entry 0 is 96 + 64 bytes (a 36-byte call padded); entry 1, the recipient's balanceOf, expects 10e18
    assert_eq!(
        U256::from_be_slice(&named[4 + 160 + 32..4 + 160 + 64]),
        e18(10)
    );

    let signer = FrameSigner::Secp256k1(key());
    let batch = sign_batch(&t, &named, &signer).unwrap();
    assert_eq!(batch.frames[1].flags & ATOMIC_BATCH_FLAG, ATOMIC_BATCH_FLAG);
    assert_eq!(batch.frames[0].flags & ATOMIC_BATCH_FLAG, 0);
    assert_eq!(batch.frames[2].data, named);
    assert_eq!(
        signer_of(&batch.signatures[0], batch.sig_hash()).unwrap(),
        key().address()
    );
    let _ = I256::ZERO;
}
