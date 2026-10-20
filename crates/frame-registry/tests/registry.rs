//! `exp-frames` experiment 32 on the testnet (2026-10-20), checked from public data with this
//! crate alone: the contracts land at the testnet's addresses, each deposit's leaf is its call's,
//! the tree's roots are the ones the updates proved against, each update is rebuilt byte for
//! byte and its proof verifies, and a spend's kernel input matches the TypeScript one.

use std::{fs, path::Path};

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_kit::{Fees, FrameTx, constants::mode, json::FrameTxJson};
use kohaku_frame_registry::{
    Application, Note, Registry, Rule, Secrets, Spend, Update, Verifier,
    contracts::kernel_key,
    note::{leaf, tag},
    update::{UpdateError, abi::depositCall, decode_update, root_of, update_tx, word_field},
};
use kohaku_tornadocash::Field;
use serde::Deserialize;
use serde_json::Value;

const HASHER: Address = address!("0x38955FBe81DBf136A84A1c711619C0Ab8Ce7813b");
const REGISTRY: Address = address!("0xbC85035Ae5aE1a35E638Ae54E58eAAa1DC2eE990");
const VERIFIER: Address = address!("0xFe46ff84b94D2Dcb381E2B0A5c5a5a8A886829bc");
const FIXED_POOL: Address = address!("0xDce509d999D5a8Cca2873FD4c431665d4eB7f9F6");
const BALANCE: Address = address!("0x0E2180d727a6CD4B2216cB16BD3e9e607a7Ebf0a");
const STORED_RULE: Address = address!("0xA41c6f469AFB82074B0508Ca850A5060fd946E8E");

const DEPLOY: &str = "0x42741335b5d25984f9b1751c5b2aa648ebd0331a1437d3b03dc138c2c75f52d1";
const DEPOSITS: &str = "0xae640af20f516dbd96c758097667615bb3126d8cc96affa6adfb42e0c2abe7d0";
/// A (`FixedPool`), B (`Balance`, with change), C (`Balance`, the change note).
const UPDATES: [&str; 3] = [
    "0x511572f1bad85edc4be60bfe71126373d4be0f5bd8fe0d4a53f6f0e49d23a03d",
    "0xa5b18e15e3bb1b8c4a137ac6c409029e833658fab85ab2ebfc156c8f89e82f76",
    "0x587e541e7ad9192c57ac7e9b687a4d2222f5d1f22cc2ef1685c9429409a8492c",
];

const MILLI: u64 = 1_000_000_000_000_000;

fn salt(label: &str) -> B256 {
    keccak256(format!("exp-frames/32/{label}"))
}

fn verifier() -> Verifier {
    Verifier {
        key: kernel_key(),
        salt: salt("verifier"),
    }
}

fn registry() -> Registry {
    Registry {
        hasher: HASHER,
        verifier: verifier().address(),
        root_salt: keccak256("exp-frames/32/registry"),
        salt: salt("registry/v1"),
    }
}

fn apps() -> [Application; 3] {
    [
        Application {
            rule: Rule::FixedPool {
                denomination: U256::from(MILLI),
            },
            salt: salt("app/fixed-pool"),
        },
        Application {
            rule: Rule::Balance {
                cap: U256::from(2 * MILLI),
            },
            salt: salt("app/balance"),
        },
        Application {
            rule: Rule::Stored {
                cap: U256::from(2 * MILLI),
            },
            salt: salt("app/stored-rule"),
        },
    ]
}

fn app(address: Address) -> Application {
    apps().into_iter().find(|a| a.address() == address).unwrap()
}

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
    receipt: Value,
}

fn fixture(hash: &str) -> (FrameTx, Value) {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/registry/{hash}.json"));
    let f: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let tx = FrameTx::try_from(&f.tx).unwrap();
    assert_eq!(tx.hash(), f.tx.hash);
    (tx, f.receipt)
}

fn word(f: Field) -> U256 {
    f.into()
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

/// Every `Inserted` log of a receipt: (app, leaf, index).
fn inserted(receipt: &Value) -> Vec<(Address, Field, u32)> {
    let topic = keccak256("Inserted(address,bytes32,uint32)");
    let mut out = vec![];
    for f in receipt["frameReceipts"].as_array().unwrap() {
        for l in f["logs"].as_array().unwrap() {
            let topics: Vec<Vec<u8>> = l["topics"]
                .as_array()
                .unwrap()
                .iter()
                .map(hex_bytes)
                .collect();
            if topics.first().map(Vec::as_slice) != Some(topic.as_slice()) {
                continue;
            }
            let data = hex_bytes(&l["data"]);
            out.push((
                Address::from_slice(&topics[1][12..]),
                word_field(B256::from_slice(&data[..32])),
                U256::from_be_slice(&data[32..64]).to::<u32>(),
            ));
        }
    }
    out
}

/// The root and updates frame 2 carried, and the slot frame 0 named.
fn carried(tx: &FrameTx) -> (U256, u64, Vec<Update>) {
    let (root, updates) = decode_update(&tx.frames[2].data).unwrap();
    let slot = u64::from_be_bytes(tx.frames[0].data[32..40].try_into().unwrap());
    (root, slot, updates)
}

#[test]
fn lands_at_the_testnet_addresses() {
    assert_eq!(verifier().address(), VERIFIER);
    assert_eq!(registry().address(), REGISTRY);
    let [fixed, balance, stored] = apps().map(|a| a.address());
    assert_eq!((fixed, balance, stored), (FIXED_POOL, BALANCE, STORED_RULE));
    let (deploy, _) = fixture(DEPLOY);
    let frames: Vec<_> = [verifier().deploy_frame(), registry().deploy_frame()]
        .into_iter()
        .chain(apps().map(|a| a.deploy_frame()))
        .collect();
    for f in &frames {
        assert!(deploy.frames.contains(f));
    }
}

#[test]
fn each_deposit_leaf_is_its_call() {
    let (tx, receipt) = fixture(DEPOSITS);
    let logs = inserted(&receipt);
    let calls: Vec<_> = tx
        .frames
        .iter()
        .filter(|f| f.mode == mode::SENDER)
        .collect();
    assert_eq!((calls.len(), logs.len()), (5, 5));
    for (i, (frame, (logged_app, logged_leaf, index))) in calls.iter().zip(&logs).enumerate() {
        assert_eq!(frame.target, Some(REGISTRY));
        let call = depositCall::abi_decode(&frame.data).unwrap();
        assert_eq!(call.app, *logged_app);
        assert!(app(call.app).rule.accepts(frame.value));
        let value = frame.value.to::<u64>();
        assert_eq!(leaf(call.app, word_field(call.inner), value), *logged_leaf);
        assert_eq!(*index as usize, i);
    }
}

#[test]
fn the_tree_gives_the_roots_the_updates_proved_against() {
    let (_, deposits) = fixture(DEPOSITS);
    let mut leaves: Vec<Field> = inserted(&deposits).into_iter().map(|(_, l, _)| l).collect();
    let after_deposits = U256::from_be_bytes(root_of(&leaves).unwrap().0);
    let [a, b, c] = UPDATES.map(fixture);
    assert_eq!(carried(&a.0).0, after_deposits);
    assert_eq!(carried(&b.0).0, after_deposits);
    // B's change note is the sixth leaf, of Balance, and C proves against the root after it.
    let change = inserted(&b.1);
    assert_eq!(change.len(), 1);
    assert_eq!((change[0].0, change[0].2), (BALANCE, 5));
    assert_eq!(word(change[0].1), carried(&b.0).2[0].new_commitment);
    leaves.push(change[0].1);
    assert_eq!(
        carried(&c.0).0,
        U256::from_be_bytes(root_of(&leaves).unwrap().0)
    );
}

#[test]
fn rebuilds_every_update_and_verifies_its_proof() {
    let key = kernel_key();
    for hash in UPDATES {
        let (mined, _) = fixture(hash);
        let (root, slot, updates) = carried(&mined);
        let rebuilt = update_tx(
            &registry(),
            mined.chain_id,
            root,
            slot,
            &updates,
            mined.fees,
        )
        .unwrap();
        assert_eq!(rebuilt, mined);
        for u in &updates {
            assert!(key.verify(&u.proof, &u.public_inputs(root)));
            let owner = app(Address::from_word(u.tag.into()));
            assert!(owner.rule.allows(u.withdrawn, !u.new_commitment.is_zero()));
            // The proof binds the tag, the recipient and the fee.
            let other = if owner.address() == FIXED_POOL {
                BALANCE
            } else {
                FIXED_POOL
            };
            let as_other = Update {
                tag: tag(other).into(),
                ..*u
            };
            assert!(!key.verify(&as_other.proof, &as_other.public_inputs(root)));
            let redirected = Update {
                recipient: Address::repeat_byte(0x11),
                ..*u
            };
            assert!(!key.verify(&redirected.proof, &redirected.public_inputs(root)));
        }
    }
}

#[test]
fn the_same_secrets_gave_two_nonce_keys() {
    let [(a, _), (b, _), _] = UPDATES.map(fixture);
    let (_, _, ua) = carried(&a);
    let (_, _, ub) = carried(&b);
    assert_eq!(ua[0].tag, word(tag(FIXED_POOL)));
    assert_eq!(ub[0].tag, word(tag(BALANCE)));
    assert_eq!(a.nonce_keys, vec![ua[0].nullifier]);
    assert_eq!(b.nonce_keys, vec![ub[0].nullifier]);
    assert_ne!(a.nonce_keys, b.nonce_keys);
}

#[test]
fn a_spend_gives_the_typescript_kernel_input() {
    let v: Value = serde_json::from_slice(
        &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/kernel-input.json"))
            .unwrap(),
    )
    .unwrap();
    let dec = |x: &Value| U256::from_str_radix(x.as_str().unwrap(), 10).unwrap();
    let field = |x: &Value| Field::try_from(dec(x)).unwrap();
    let seed = hex_bytes(&v["seed"]);
    let secrets = Secrets::derive(&seed, "vector");
    let change = Secrets::derive(&seed, "vector/change");
    let fixed = Note {
        app: FIXED_POOL,
        secrets,
        state: MILLI,
    };
    let held = Note {
        app: BALANCE,
        secrets,
        state: 3 * MILLI,
    };
    let leaves = [fixed.leaf(), held.leaf()];
    let expected: Vec<Field> = v["leaves"].as_array().unwrap().iter().map(field).collect();
    assert_eq!(leaves.to_vec(), expected);
    assert_ne!(fixed.nullifier(), held.nullifier());

    let spend = Spend {
        note: held,
        index: 1,
        withdrawn: MILLI,
        new_inner: Some(change.inner()),
        recipient: address!("0x000000000000000000000000000000000000dEaD"),
        fee: U256::from(10_000_000_000u64),
        link: U256::ZERO,
    };
    let input = spend.kernel_input(&leaves).unwrap();
    let i = &v["input"];
    assert_eq!(input.root, field(&i["root"]));
    assert_eq!(input.nullifier, field(&i["nullifier"]));
    assert_eq!(input.new_commitment, field(&i["newCommitment"]));
    assert_eq!(input.tag, field(&i["tag"]));
    assert_eq!(U256::from(input.withdrawn), dec(&i["withdrawn"]));
    assert_eq!(input.binding, dec(&i["binding"]));
    assert_eq!(input.nullifier_secret, field(&i["nullifierSecret"]));
    assert_eq!(input.secret, field(&i["secret"]));
    assert_eq!(U256::from(input.state), dec(&i["state"]));
    assert_eq!(input.new_inner, field(&i["newInner"]));
    let path: Vec<Field> = i["pathElements"]
        .as_array()
        .unwrap()
        .iter()
        .map(field)
        .collect();
    assert_eq!(input.path_elements.to_vec(), path);
    let indices: Vec<U256> = i["pathIndices"]
        .as_array()
        .unwrap()
        .iter()
        .map(dec)
        .collect();
    assert_eq!(input.path_indices.map(U256::from).to_vec(), indices);
}

#[test]
fn refuses_what_the_registry_refuses() {
    let u = |nullifier: u64, link: u64| Update {
        nullifier: U256::from(nullifier),
        new_commitment: U256::ZERO,
        tag: tag(BALANCE).into(),
        withdrawn: U256::from(MILLI),
        recipient: Address::ZERO,
        fee: U256::from(1),
        link: U256::from(link),
        proof: [U256::ZERO; 8],
    };
    let tx = |us: &[Update]| update_tx(&registry(), 8141, U256::ZERO, 0, us, Fees::default());
    assert_eq!(tx(&[]).unwrap_err(), UpdateError::Count(0));
    assert_eq!(
        tx(&[u(1, 0), u(2, 0), u(3, 0)]).unwrap_err(),
        UpdateError::Count(3)
    );
    assert_eq!(tx(&[u(2, 1), u(1, 2)]).unwrap_err(), UpdateError::Order);
    assert_eq!(tx(&[u(1, 0), u(2, 0)]).unwrap_err(), UpdateError::Link);
    assert_eq!(tx(&[u(1, 5)]).unwrap_err(), UpdateError::Link);
    let mut greedy = u(1, 0);
    greedy.fee = U256::from(2 * MILLI);
    assert_eq!(tx(&[greedy]).unwrap_err(), UpdateError::Fee);
    let pair = tx(&[u(1, 2), u(2, 1)]).unwrap();
    assert_eq!(pair.nonce_keys, vec![U256::from(1), U256::from(2)]);
}
