//! The derivation pinned by a vector from a public mnemonic, which `exp-frames` experiment 45
//! checks again in TypeScript. `UPDATE_VECTOR=1` writes it.

use alloy::primitives::{Address, B256, address};
use commonware_codec::Encode;
use kohaku_frame_secrets::Seed;
use serde_json::{Value, json};

/// BIP-39's 24-word mnemonic of 32 zero bytes: public, so nothing derived from it is secret.
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const VAULT: Address = address!("0x7Bc7902c7DEABFbD7Abd783C49BA7Bf946D13314");
const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vector.json");

fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn vector() -> Value {
    let seed = Seed::from_mnemonic(PHRASE).unwrap();
    let mut keys = serde_json::Map::new();
    for label in [
        "account/0/salt",
        "account/0/recovery-salt/0",
        "pool/keychain",
        "pool/recipient/0",
        "view",
        "ticket/0/sender",
        "ticket/0/salt",
        "ticket/0/blinding",
        "backup/0/key",
        "backup/0/locator",
    ] {
        keys.insert(label.to_owned(), json!(h(&seed.key(label))));
    }
    let custody = seed.custody(VAULT, 0);
    let ticket = seed.ticket(0).unwrap();
    json!({
        "mnemonic": PHRASE,
        "hkdf": { "salt": "kohaku-seed-v1" },
        "K": keys,
        "owner": (0..2).map(|i| seed.owner(i).unwrap().address()).collect::<Vec<_>>(),
        "addresses": {
            "pool/keychain": seed.secp256k1("pool/keychain").unwrap().address(),
            "pool/recipient/0": seed.recipient(0).unwrap().address(),
            "ticket/0/sender": ticket.sender.address(),
        },
        "view": h(&seed.view().unwrap().public),
        "custody": {
            "vault": VAULT,
            "label": format!("custody/{}/0", kohaku_frame_secrets::derive::lower(VAULT)),
            "nullifierSecret": B256::from(custody.nullifier_secret),
            "secret": B256::from(custody.secret),
        },
        "ticketBlinding": { "dst": "kohaku-seed-v1/ticket-blinding", "scalar": h(&ticket.blinding.encode()) },
    })
}

#[test]
fn derivation_matches_the_vector() {
    let v = vector();
    if std::env::var("UPDATE_VECTOR").is_ok() {
        std::fs::write(
            PATH,
            format!("{}\n", serde_json::to_string_pretty(&v).unwrap()),
        )
        .unwrap();
    }
    let pinned: Value = serde_json::from_str(&std::fs::read_to_string(PATH).unwrap()).unwrap();
    assert_eq!(v, pinned);
}
