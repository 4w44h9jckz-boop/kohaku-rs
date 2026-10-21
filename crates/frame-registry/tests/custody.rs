//! `exp-frames` experiment 40 on the testnet (2026-10-20), checked from public data with this
//! crate alone: the registry and the vaults land at the testnet's addresses, each vault's scope
//! is the one the TypeScript computed, each deposit's leaf is its call's under its vault's scope,
//! each update is rebuilt byte for byte, its proof verifies under its own vault's scope and its
//! own fees and under no other, and every payment it made came from its own vault.

use std::{fs, path::Path};

use alloy::{
    primitives::{Address, B256, U256, address, b256, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_kit::{Fees, FrameTx, constants::mode, json::FrameTxJson};
use kohaku_frame_registry::{
    Verifier,
    contracts::kernel_key,
    custody::{Kind, Vault, VaultedRegistry, abi::depositCall, decode_update, leaf, update_tx},
};
use kohaku_tornadocash::Field;
use serde::Deserialize;
use serde_json::Value;

const CHAIN_ID: u64 = 8141;
const HASHER: Address = address!("0x38955FBe81DBf136A84A1c711619C0Ab8Ce7813b");
const REGISTRY: Address = address!("0x246FBf1ca115E6f9993658e0e46F24E4C9054Df6");
const VAULT_A: Address = address!("0x7Bc7902c7DEABFbD7Abd783C49BA7Bf946D13314");
const VAULT_B: Address = address!("0xFF52Ebefff973bc75eef6BD6D52887B6fDFB9757");
const VAULT_C: Address = address!("0xbD80555C4E78Ad93D2227555299dc720415774C3");
/// The scopes, as experiment 40's `record.json` has them.
const SCOPES: [(Address, B256); 3] = [
    (
        VAULT_A,
        b256!("0x2fa7d06a139262400b399c0652443e198a7d3b06005608a3569f80baba982e3f"),
    ),
    (
        VAULT_B,
        b256!("0x063918a0cf8663f718337168fbca90347bb49c808915294c140daa54a84b474a"),
    ),
    (
        VAULT_C,
        b256!("0x2a850b160bcf1c3878492c0ada3699ed4e79870c3ed7a231bea4ea26ec1c56e6"),
    ),
];

const DEPLOY: &str = "0x34181a825e9cf8b3180ba45642aa7cc6d0887248047f710dd2fa813278605b3f";
const DEPOSITS: &str = "0x78a32be20e034d2a0b6d6bf9da11da6ab2cb8ed031a5c053fd16edd7556e88aa";
/// A (vault A, spent whole), B1 (vault B, with change), B2 (vault B, the change note).
const UPDATES: [(&str, Address); 3] = [
    (
        "0xdc4debd1c5050b21921893c84220dd88665155071e412000e292d15a1596084b",
        VAULT_A,
    ),
    (
        "0x4e1ceffa630e9479d5839bef550b78521e5ad4637a05bf804018f00ac3a9d485",
        VAULT_B,
    ),
    (
        "0xb8c106513ddacdc937ec57c2b635f8feb1cb5d9d2ed5130b3524240da141971a",
        VAULT_B,
    ),
];

const MILLI: u64 = 1_000_000_000_000_000;
const FEE: u64 = 10_000_000_000;
/// What a copy offered in experiment 40's Y2: a tip of 8,000 wei and a cap of 10,000.
const RAISED: Fees = Fees {
    max_priority_fee_per_gas: 8_000,
    max_fee_per_gas: 10_000,
    max_fee_per_blob_gas: 0,
};

fn salt(label: &str) -> B256 {
    keccak256(format!("exp-frames/{label}"))
}

fn registry() -> VaultedRegistry {
    VaultedRegistry {
        hasher: HASHER,
        verifier: Verifier {
            key: kernel_key(),
            salt: salt("32/verifier"),
        }
        .address(),
        root_salt: keccak256("exp-frames/40/registry"),
        salt: salt("40/registry/v1"),
    }
}

fn vaults() -> [Vault; 3] {
    let r = registry().address();
    let v = |label: &str, kind, amount: u64| Vault {
        registry: r,
        kind,
        amount: U256::from(amount),
        salt: salt(&format!("40/vault/{label}")),
    };
    [
        v("a", Kind::Fixed, MILLI),
        v("b", Kind::Balance, 2 * MILLI),
        v("c", Kind::Fixed, MILLI),
    ]
}

fn vault(address: Address) -> Vault {
    vaults()
        .into_iter()
        .find(|v| v.address() == address)
        .unwrap()
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

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

/// The logs of frame `i` with `topic`: (address, topics, data).
fn logs(receipt: &Value, i: usize, topic: B256) -> Vec<(Address, Vec<B256>, Vec<u8>)> {
    receipt["frameReceipts"][i]["logs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| {
            let topics: Vec<B256> = l["topics"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| B256::from_slice(&hex_bytes(t)))
                .collect();
            (
                l["address"].as_str().unwrap().parse().unwrap(),
                topics,
                hex_bytes(&l["data"]),
            )
        })
        .filter(|(_, t, _)| t.first() == Some(&topic))
        .collect()
}

#[test]
fn the_registry_and_the_vaults_are_at_the_testnets_addresses() {
    assert_eq!(registry().address(), REGISTRY);
    let addresses: Vec<Address> = vaults().iter().map(Vault::address).collect();
    assert_eq!(addresses, [VAULT_A, VAULT_B, VAULT_C]);
    let (tx, _) = fixture(DEPLOY);
    let deployed: Vec<_> = tx
        .frames
        .iter()
        .filter(|f| f.mode == mode::SENDER)
        .map(|f| f.data.clone())
        .collect();
    assert!(deployed.contains(&registry().deploy_frame().data));
    for v in vaults() {
        assert!(deployed.contains(&v.deploy_frame().data));
    }
}

#[test]
fn each_vaults_scope_is_the_typescripts_and_twins_differ() {
    for (address, expected) in SCOPES {
        let scope: U256 = vault(address).scope(CHAIN_ID).into();
        assert_eq!(B256::from(scope), expected);
    }
    let [a, _, c] = vaults();
    assert_eq!(a.params(), c.params());
    assert_ne!(a.scope(CHAIN_ID), c.scope(CHAIN_ID));
}

#[test]
fn each_deposits_leaf_is_its_calls_under_its_vaults_scope() {
    let (tx, receipt) = fixture(DEPOSITS);
    let inserted = keccak256("Inserted(address,bytes32,uint32)");
    let mut seen = 0;
    for (i, f) in tx.frames.iter().enumerate() {
        if f.mode != mode::SENDER {
            continue;
        }
        let call = depositCall::abi_decode(&f.data).unwrap();
        let [(at, topics, data)] = logs(&receipt, i, inserted).try_into().unwrap();
        assert_eq!(at, REGISTRY);
        assert_eq!(Address::from_word(topics[1]), call.vault);
        let scope = vault(call.vault).scope(CHAIN_ID);
        let inner = Field::try_from(U256::from_be_bytes(call.inner.0)).unwrap();
        let value: u64 = f.value.to();
        let logged: U256 = U256::from_be_slice(&data[..32]);
        let expected: U256 = leaf(scope, inner, value).into();
        assert_eq!(logged, expected);
        seen += 1;
    }
    assert_eq!(seen, 4);
}

#[test]
fn each_update_is_rebuilt_byte_for_byte_and_proves_only_under_its_own_vault_and_fees() {
    let key = kernel_key();
    let paid = keccak256("Paid(address,uint256)");
    for (hash, expected_vault) in UPDATES {
        let (mined, receipt) = fixture(hash);
        let (root, update) = decode_update(&mined.frames[2].data).unwrap();
        assert_eq!(update.vault, expected_vault);
        let slot = u64::from_be_bytes(mined.frames[0].data[32..40].try_into().unwrap());
        let rebuilt = update_tx(&registry(), CHAIN_ID, root, slot, &update, mined.fees);
        assert_eq!(rebuilt.encode(), mined.encode(), "{hash}");
        assert_eq!(format!("{:#x}", rebuilt.hash()), hash);

        let scope = vault(update.vault).scope(CHAIN_ID);
        assert!(key.verify(
            &update.proof,
            &update.public_inputs(root, scope, &mined.fees)
        ));
        for other in vaults().iter().filter(|v| v.address() != update.vault) {
            let inputs = update.public_inputs(root, other.scope(CHAIN_ID), &mined.fees);
            assert!(
                !key.verify(&update.proof, &inputs),
                "{hash} under another vault"
            );
        }
        assert!(!key.verify(&update.proof, &update.public_inputs(root, scope, &RAISED)));

        // Both payments of the update frame, the recipient's and the fee, from the note's vault.
        let payments = logs(&receipt, 2, paid);
        let from: Vec<Address> = payments.iter().map(|(a, _, _)| *a).collect();
        assert_eq!(from, [expected_vault, expected_vault]);
        let to: Vec<Address> = payments
            .iter()
            .map(|(_, t, _)| Address::from_word(t[1]))
            .collect();
        assert_eq!(to, [update.recipient, REGISTRY]);
        let amounts: Vec<U256> = payments
            .iter()
            .map(|(_, _, d)| U256::from_be_slice(d))
            .collect();
        assert_eq!(amounts, [update.withdrawn - update.fee, U256::from(FEE)]);
    }
}
