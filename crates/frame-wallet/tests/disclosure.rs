//! The association set's check against a tree circomlibjs built (`tests/fixtures/leanimt-5.json`,
//! five leaves, written by `exp-frames` experiment 35's tooling), and the wallet's wording.

use std::{fs, path::Path};

use alloy::primitives::U256;
use kohaku_frame_wallet::disclosure::{AssociationSet, Crowd, DisclosureError};
use serde_json::Value;

fn vector() -> (Vec<u8>, U256) {
    let v: Value = serde_json::from_slice(
        &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/leanimt-5.json"))
            .unwrap(),
    )
    .unwrap();
    let export = serde_json::to_vec(&v["export"]).unwrap();
    (
        export,
        U256::from_str_radix(v["root"].as_str().unwrap(), 10).unwrap(),
    )
}

#[test]
fn verifies_a_set_circomlibjs_built() {
    let (export, root) = vector();
    let set = AssociationSet::verify(&export, root).unwrap();
    assert_eq!(set.labels(), &[1, 2, 3, 4, 5].map(U256::from));
    assert_eq!(set.levels.len(), 4);
}

#[test]
fn refuses_a_set_that_does_not_hash_to_its_root() {
    let (export, root) = vector();
    assert!(matches!(
        AssociationSet::verify(&export, root + U256::from(1)),
        Err(DisclosureError::Root)
    ));
    // A label changed below an unchanged tree.
    let mut levels: Vec<Vec<String>> = serde_json::from_slice(&export).unwrap();
    levels[0][4] = "6".into();
    let tampered = serde_json::to_vec(&levels).unwrap();
    assert!(matches!(
        AssociationSet::verify(&tampered, root),
        Err(DisclosureError::Level(1))
    ));
}

#[test]
fn words_the_crowd() {
    assert_eq!(Crowd::of(3), Crowd::Identifies);
    assert_eq!(Crowd::of(96), Crowd::Few);
    assert_eq!(Crowd::of(2_266), Crowd::Many);
    assert!(Crowd::of(3).warning(3).contains("all but name you"));
}
