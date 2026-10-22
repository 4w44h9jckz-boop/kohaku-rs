//! `exp-frames` experiment 50 on the testnet (2026-10-21), checked from public data with this
//! crate alone: the verifier and both registries land at the testnet's addresses, each update is
//! rebuilt byte for byte with its mined signature, its proof verifies with `owner` as the seventh
//! input, and its owner's signature passes the checks the registry makes. Then a fresh update is
//! signed here and checked the same way, and the refusals of experiment 50's D1, D2 and D4 are
//! reproduced offline.

use std::{fs, path::Path};

use alloy::primitives::{Address, B256, U256, address, keccak256};
use kohaku_frame_device_key::{
    OwnerError, RegistryV3, Route, check_owner, kernel_key, owner, owner_of, public_inputs,
    sign_update, update_tx,
};
use kohaku_frame_kit::{FrameTx, constants::scheme, json::FrameTxJson};
use kohaku_frame_registry::{Update, Verifier, update::decode_update};
use p256::ecdsa::SigningKey;
use serde::Deserialize;

const HASHER: Address = address!("0x38955FBe81DBf136A84A1c711619C0Ab8Ce7813b");
const VERIFIER: Address = address!("0x37c5Dff8221f3109B1eC9102350c81bBe0Fa9c03");
const REGISTRY: Address = address!("0x1C9F1f8aA4Ce97Eec5534d89bCE82dC13813531b");
const CONTROL: Address = address!("0x0dbEB0f932318fC9C4d8d13FA342f11bDd098517");

const DEPLOY: &str = "0x32473dfe4d2a64c12d1ce9e3fad7de371ae73a89825cba1418359a37a949d67e";
/// A (ARBITRARY, with change), B (P256 entry), C (ARBITRARY), E (the control).
const UPDATES: [(&str, Route); 4] = [
    (
        "0x30978e720bbf4c9968315e3714b1cc0f84e5d0a91c759078c558f6b87276b5f0",
        Route::Arbitrary,
    ),
    (
        "0x4a2a10d30be9da33e21d222d4f1db601af7349ac1013ff525033e0080e3ce712",
        Route::P256,
    ),
    (
        "0x545b0204e217d83ba9ce6c57194545e54a881c38546a9178fa49a73f679f8dac",
        Route::Arbitrary,
    ),
    (
        "0x5d83710e73f8886950c391c13460cb8bea59473badc980489b5ccdbdb3b6eb09",
        Route::None,
    ),
];

fn salt(label: &str) -> B256 {
    keccak256(format!("exp-frames/50/{label}"))
}

fn verifier() -> Verifier {
    Verifier {
        key: kernel_key(),
        salt: salt("verifier"),
    }
}

fn registry(keyed: bool) -> RegistryV3 {
    let label = if keyed {
        "registry/v3"
    } else {
        "registry/v3-control"
    };
    RegistryV3 {
        hasher: HASHER,
        verifier: verifier().address(),
        root_salt: salt(label),
        salt: salt(label),
        keyed,
    }
}

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
}

fn fixture(hash: &str) -> FrameTx {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/{hash}.json"));
    let f: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let tx = FrameTx::try_from(&f.tx).unwrap();
    assert_eq!(tx.hash(), f.tx.hash);
    tx
}

fn carried(tx: &FrameTx) -> (U256, u64, Update) {
    let (root, updates) = decode_update(&tx.frames[2].data).unwrap();
    let slot = u64::from_be_bytes(tx.frames[0].data[32..40].try_into().unwrap());
    assert_eq!(updates.len(), 1);
    (root, slot, updates[0])
}

fn rebuilt(hash: &str, route: Route) -> (FrameTx, U256, Update) {
    let mined = fixture(hash);
    let (root, slot, update) = carried(&mined);
    let r = registry(route != Route::None);
    let mut tx = update_tx(&r, mined.chain_id, root, slot, &update, route, mined.fees);
    tx.signatures.clone_from(&mined.signatures);
    (tx, root, update)
}

#[test]
fn lands_at_the_testnet_addresses() {
    assert_eq!(verifier().address(), VERIFIER);
    assert_eq!(registry(true).address(), REGISTRY);
    assert_eq!(registry(false).address(), CONTROL);
    let deploy = fixture(DEPLOY);
    for f in [
        verifier().deploy_frame(),
        registry(true).deploy_frame(),
        registry(false).deploy_frame(),
    ] {
        assert!(deploy.frames.contains(&f));
    }
}

#[test]
fn rebuilds_each_update_and_checks_its_proof_and_owner() {
    let key = kernel_key();
    for (hash, route) in UPDATES {
        let (tx, root, update) = rebuilt(hash, route);
        assert_eq!(format!("{:#x}", tx.hash()), hash);
        assert!(
            key.verify(&update.proof, &public_inputs(&update, root)),
            "{hash}: proof"
        );
        match route {
            Route::None => assert!(tx.signatures.is_empty()),
            Route::Arbitrary | Route::P256 => {
                let want = if route == Route::P256 {
                    scheme::P256
                } else {
                    scheme::ARBITRARY
                };
                assert_eq!(tx.signatures[0].scheme, want);
                check_owner(&tx, owner(&update)).unwrap();
            }
        }
    }
}

#[test]
fn the_change_note_names_a_fresh_key() {
    let (_, _, a) = rebuilt(UPDATES[0].0, Route::Arbitrary);
    let (_, _, b) = rebuilt(UPDATES[1].0, Route::P256);
    assert!(!a.new_commitment.is_zero());
    assert_ne!(owner(&a), owner(&b));
}

#[test]
fn signs_a_fresh_update_and_refuses_what_the_registry_refuses() {
    // C's update, re-signed here: a software P-256 key stands in for a device's enclave key.
    let device = SigningKey::from_slice(&keccak256("kohaku/device-key/test/owner").0).unwrap();
    let stranger = SigningKey::from_slice(&keccak256("kohaku/device-key/test/stranger").0).unwrap();
    let (_, _, mut update) = rebuilt(UPDATES[2].0, Route::Arbitrary);
    update.link = owner_of(device.verifying_key());
    let mined = fixture(UPDATES[2].0);
    let (root, slot, _) = carried(&mined);
    let mut tx = update_tx(
        &registry(true),
        mined.chain_id,
        root,
        slot,
        &update,
        Route::Arbitrary,
        mined.fees,
    );
    sign_update(&mut tx, &device).unwrap();
    check_owner(&tx, owner(&update)).unwrap();

    // D1: a stranger signs.
    let mut d1 = tx.clone();
    sign_update(&mut d1, &stranger).unwrap();
    assert!(matches!(
        check_owner(&d1, owner(&update)),
        Err(OwnerError::NotOwner)
    ));

    // D2: the owner's signature with s replaced by n - s.
    let mut d2 = tx.clone();
    let sig = d2.signatures[0].signature.to_vec();
    let s = U256::from_be_slice(&sig[32..64]);
    let n = U256::from_str_radix(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        16,
    )
    .unwrap();
    let mut high = sig.clone();
    high[32..64].copy_from_slice(&(n - s).to_be_bytes::<32>());
    d2.signatures[0].signature = high.into();
    assert!(matches!(
        check_owner(&d2, owner(&update)),
        Err(OwnerError::HighS)
    ));

    // D4: the signature moved onto an update that pays someone else.
    let mut other = update;
    other.recipient = address!("0x00000000000000000000000000000000000000d4");
    let mut d4 = update_tx(
        &registry(true),
        mined.chain_id,
        root,
        slot,
        &other,
        Route::Arbitrary,
        mined.fees,
    );
    d4.signatures.clone_from(&tx.signatures);
    assert!(matches!(
        check_owner(&d4, owner(&other)),
        Err(OwnerError::P256(_))
    ));
}
