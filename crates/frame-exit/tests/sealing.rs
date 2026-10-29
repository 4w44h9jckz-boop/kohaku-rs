//! The owner's opening key from the one seed, pinned by a vector from a public mnemonic, and the
//! sealing: who can open a message, under which context, and that a message says nothing about
//! whom it is for. `UPDATE_VECTOR=1` writes the vector.

use alloy::primitives::{Address, B256, address};
use kohaku_frame_exit::{
    Context, MESSAGE_LEN, OPENING_LEN, OpeningKey, Published, latest, open, opening_key, recipient,
    scan, seal,
};
use kohaku_frame_secrets::Seed;
use serde_json::{Value, json};

/// BIP-39's 24-word mnemonic of 32 zero bytes: public, so nothing derived from it is secret.
const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const VAULT: Address = address!("0x7Bc7902c7DEABFbD7Abd783C49BA7Bf946D13314");
const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/vector.json");

fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn plaintext(tag: u8) -> [u8; OPENING_LEN] {
    std::array::from_fn(|i| tag.wrapping_add(i as u8))
}

fn vector() -> Value {
    let seed = Seed::from_mnemonic(PHRASE).unwrap();
    let keys: Vec<Value> = (0..2)
        .map(|o| {
            json!({
                "o": o,
                "openingPublic": h(&opening_key(&seed, VAULT, o).unwrap().public),
                "recipient": recipient(&seed, VAULT, o).unwrap().to_string(),
            })
        })
        .collect();
    let to = opening_key(&seed, VAULT, 0).unwrap();
    let ephemeral = OpeningKey::from_secret(B256::repeat_byte(0x11)).unwrap();
    let context = Context {
        vault: VAULT,
        update: 7,
    };
    let message = seal(&to.public, &context, &plaintext(0xa0), &ephemeral).unwrap();
    json!({
        "phrase": PHRASE,
        "vault": VAULT.to_string(),
        "keys": keys,
        "seal": {
            "ephemeralSecret": h(B256::repeat_byte(0x11).as_slice()),
            "update": 7,
            "plaintext": h(&plaintext(0xa0)),
            "message": h(&message),
        },
    })
}

#[test]
fn the_derivation_and_a_seal_match_the_vector() {
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

#[test]
fn only_the_owner_opens_and_only_in_its_context() {
    let mut rng = rand::rng();
    let owner = OpeningKey::random(&mut rng);
    let other = OpeningKey::random(&mut rng);
    let context = Context {
        vault: VAULT,
        update: 3,
    };
    let m = seal(
        &owner.public,
        &context,
        &plaintext(1),
        &OpeningKey::random(&mut rng),
    )
    .unwrap();
    assert_eq!(open(&owner, &context, &m), Some(plaintext(1)));
    assert_eq!(open(&other, &context, &m), None, "another key");
    assert_eq!(
        open(
            &owner,
            &Context {
                update: 4,
                ..context
            },
            &m
        ),
        None,
        "another update"
    );
    assert_eq!(
        open(
            &owner,
            &Context {
                vault: Address::repeat_byte(1),
                ..context
            },
            &m
        ),
        None,
        "another vault"
    );
    let mut flipped = m;
    flipped[MESSAGE_LEN - 1] ^= 1;
    assert_eq!(open(&owner, &context, &flipped), None, "a changed tag");
    assert_eq!(
        open(&owner, &context, &m[..MESSAGE_LEN - 1]),
        None,
        "a short message"
    );
}

#[test]
fn a_message_says_nothing_of_whom_it_is_for() {
    let mut rng = rand::rng();
    let owner = OpeningKey::random(&mut rng);
    let context = Context {
        vault: VAULT,
        update: 1,
    };
    let a = seal(
        &owner.public,
        &context,
        &plaintext(1),
        &OpeningKey::random(&mut rng),
    )
    .unwrap();
    let b = seal(
        &owner.public,
        &context,
        &plaintext(1),
        &OpeningKey::random(&mut rng),
    )
    .unwrap();
    // Every message is the same length, whoever it is for.
    assert_eq!(a.len(), MESSAGE_LEN);
    // The owner's key is in neither, whole or as its x-coordinate.
    for m in [&a, &b] {
        assert!(!m.windows(33).any(|w| w == owner.public));
        assert!(!m.windows(32).any(|w| w == &owner.public[1..]));
    }
    // Two messages to one owner, with the same opening, share nothing past the version byte
    // but by chance: the ephemeral keys and ciphertexts differ.
    assert_ne!(a[2..35], b[2..35]);
    assert_ne!(a[35..], b[35..]);
}

#[test]
fn scanning_finds_the_owners_openings_among_others_and_the_latest() {
    let mut rng = rand::rng();
    let owner = OpeningKey::random(&mut rng);
    let others: Vec<OpeningKey> = (0..7).map(|_| OpeningKey::random(&mut rng)).collect();
    let batch = |update: u64, mine: Option<(usize, u8)>| {
        let context = Context {
            vault: VAULT,
            update,
        };
        let mut messages: Vec<Vec<u8>> = others
            .iter()
            .map(|k| {
                seal(
                    &k.public,
                    &context,
                    &plaintext(0),
                    &OpeningKey::random(&mut rand::rng()),
                )
                .unwrap()
                .to_vec()
            })
            .collect();
        if let Some((at, tag)) = mine {
            let m = seal(
                &owner.public,
                &context,
                &plaintext(tag),
                &OpeningKey::random(&mut rand::rng()),
            )
            .unwrap();
            messages.insert(at, m.to_vec());
        }
        Published { context, messages }
    };
    let published = vec![
        batch(1, Some((3, 10))),
        batch(2, None),
        batch(3, Some((0, 30))),
        batch(4, None),
    ];
    let found = scan(&owner, &published);
    assert_eq!(
        found
            .iter()
            .map(|f| (f.update, f.position))
            .collect::<Vec<_>>(),
        [(1, 3), (3, 0)]
    );
    let last = latest(&owner, &published).unwrap();
    assert_eq!((last.update, last.opening), (3, plaintext(30)));
    // A message moved to another update's list does not open there.
    let mut moved = published.clone();
    let m = moved[0].messages.remove(3);
    moved[1].messages.push(m);
    assert_eq!(
        scan(&owner, &moved)
            .iter()
            .map(|f| f.update)
            .collect::<Vec<_>>(),
        [3]
    );
    // Another owner's key finds only its own.
    assert_eq!(scan(&others[0], &published).len(), 4);
}

#[test]
fn debug_shows_no_secret() {
    let k = OpeningKey::from_secret(B256::repeat_byte(0x42)).unwrap();
    let s = format!("{k:?}");
    assert!(!s.contains(&hex::encode(B256::repeat_byte(0x42))));
    assert!(s.contains(&hex::encode(k.public)));
}
