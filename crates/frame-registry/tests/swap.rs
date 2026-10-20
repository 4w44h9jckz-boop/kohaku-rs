//! `exp-frames` experiment 33 on the testnet (2026-10-20), checked from public data with this
//! crate alone: registry version 2, the second asset and the board land at their addresses, the
//! swap and the two owners' own updates are rebuilt byte for byte, every proof verifies with its
//! deadline, the swap's two updates name each other, each posted message is a sealed offer or
//! answer, and the announcement vector seals to the TypeScript's bytes and opens.

use std::{fs, path::Path};

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_kit::{Fees, FrameTx, constants::mode, json::FrameTxJson};
use kohaku_frame_registry::{
    Application, Board, Registry, Rule, Verifier, Version,
    announce::{Accept, Keys, OVERHEAD, Offer, abi::postCall, offer_id, open, seal},
    contracts::kernel_key,
    update::{UpdateError, decode_update, pair_link, root_of, update_tx, word_field},
};
use kohaku_tornadocash::Field;
use serde::Deserialize;
use serde_json::Value;

const HASHER: Address = address!("0x38955FBe81DBf136A84A1c711619C0Ab8Ce7813b");
const REGISTRY: Address = address!("0x755e6d982048bf6F97C0f9C1e2174233Add3c02c");
const ASSET_A: Address = address!("0x0E2180d727a6CD4B2216cB16BD3e9e607a7Ebf0a");
const ASSET_B: Address = address!("0x1BCDda250187F6be61a19e4cE2eC898fF64AFd86");
const BOARD: Address = address!("0x93DD748B72dA1b1B6F1d5ec78Cb91ee52F01727d");

const DEPLOY: &str = "0x5b6337411c4dc5f064d997092c7bc402945ec72d79eab80464ed51561cde08b8";
const DEPOSITS: &str = "0x24410da16729b59beae6f3c4744de8751e6f4dfe68f2e7d32ef964a9b62e0cf9";
const SWAP: &str = "0x5c365fc175720516a5b42c6698bb6c5c49d04a3ee6e7afeeed0417163b5b31c6";
/// Alice spends the note the swap gave her; Alice cancels by spending her other note.
const SOLO: [&str; 2] = [
    "0xb3ad9012421ceb90f2036ac487245f1287ad00b686b00354623da809f397a59d",
    "0x7cf64acf879235591a839a839245eaf695a9388e6092be939f35b9df4b75a3a5",
];
/// Offers and answers, alternating.
const POSTS: [&str; 6] = [
    "0x3b738bc4148383dd59b95cb25f072060152a5374238e8a53144da3c1bdececf5",
    "0xcaf0a6750deecf96ccbb5343f70e9d53c487ad3748e98169bf734509515d3758",
    "0x26c2a5dbd21c43b5dae25d297b3b16a30afe107e4537d21763f289eb898278f7",
    "0x112912eeb61a6cafc5d88af3ea32425ffb9b66c07be4da76b84abce890f94d4b",
    "0xbd11755a16be048d3230aa886417a9d82a9bdaf3010dac6de0425aabdf8d3e15",
    "0xcb150c4958a7297544b2cabc6354f1c5648c2f4874cb05863e970b71f0263625",
];

fn salt(label: &str) -> B256 {
    keccak256(format!("exp-frames/33/{label}"))
}

fn registry() -> Registry {
    Registry {
        version: Version::V2,
        hasher: HASHER,
        verifier: Verifier {
            key: kernel_key(),
            salt: keccak256("exp-frames/32/verifier"),
        }
        .address(),
        root_salt: keccak256("exp-frames/33/registry"),
        salt: salt("registry/v2"),
    }
}

fn asset_b() -> Application {
    Application {
        rule: Rule::Balance {
            cap: U256::from(2_000_000_000_000_000u64),
        },
        salt: salt("app/balance-b"),
    }
}

fn board() -> Board {
    Board {
        salt: salt("board"),
    }
}

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
    receipt: Value,
}

fn fixture(hash: &str) -> (FrameTx, Value) {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/fixtures/swap/{hash}.json"));
    let f: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let tx = FrameTx::try_from(&f.tx).unwrap();
    assert_eq!(tx.hash(), f.tx.hash);
    (tx, f.receipt)
}

fn hex_bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

/// The leaves the registry logged in a receipt, in order.
fn inserted(receipt: &Value) -> Vec<Field> {
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
            if topics.first().map(Vec::as_slice) == Some(topic.as_slice()) {
                out.push(word_field(B256::from_slice(&hex_bytes(&l["data"])[..32])));
            }
        }
    }
    out
}

/// The deadline, the slot, the root and the updates a version-2 update carried.
fn carried(tx: &FrameTx) -> (u64, u64, U256, Vec<kohaku_frame_registry::Update>) {
    let deadline = u64::from_be_bytes(tx.frames[0].data[..8].try_into().unwrap());
    let slot = u64::from_be_bytes(tx.frames[1].data[32..40].try_into().unwrap());
    let (root, updates) = decode_update(&tx.frames[3].data).unwrap();
    (deadline, slot, root, updates)
}

#[test]
fn lands_at_the_testnet_addresses() {
    assert_eq!(registry().address(), REGISTRY);
    assert_eq!(asset_b().address(), ASSET_B);
    assert_eq!(board().address(), BOARD);
    let (deploy, _) = fixture(DEPLOY);
    for f in [
        registry().deploy_frame(),
        asset_b().deploy_frame(),
        board().deploy_frame(),
    ] {
        assert!(deploy.frames.contains(&f));
    }
}

#[test]
fn rebuilds_the_swap_and_the_owners_updates_and_verifies_every_proof() {
    let key = kernel_key();
    for hash in std::iter::once(SWAP).chain(SOLO) {
        let (mined, _) = fixture(hash);
        let (deadline, slot, root, updates) = carried(&mined);
        let rebuilt = update_tx(
            &registry(),
            mined.chain_id,
            root,
            slot,
            Some(deadline),
            &updates,
            mined.fees,
        )
        .unwrap();
        assert_eq!(rebuilt, mined);
        for u in &updates {
            assert!(key.verify(&u.proof, &u.public_inputs(root, Some(deadline))));
            // The deadline is bound: with another, or none, the proof fails.
            assert!(!key.verify(&u.proof, &u.public_inputs(root, Some(deadline + 1))));
            assert!(!key.verify(&u.proof, &u.public_inputs(root, None)));
        }
    }
}

#[test]
fn the_swap_spends_both_notes_into_each_others_hands() {
    let (swap, _) = fixture(SWAP);
    let (_, _, _, u) = carried(&swap);
    assert_eq!(u.len(), 2);
    assert_eq!(swap.nonce_keys, vec![u[0].nullifier, u[1].nullifier]);
    // Each names the other's nullifier and change note; the two are of different assets.
    assert_eq!(u[0].link, pair_link(u[1].nullifier, u[1].new_commitment));
    assert_eq!(u[1].link, pair_link(u[0].nullifier, u[0].new_commitment));
    let tags: Vec<Address> = u.iter().map(|x| Address::from_word(x.tag.into())).collect();
    assert!(tags.contains(&ASSET_A) && tags.contains(&ASSET_B));
    // Nothing is paid out: each takes only its fee, and the rest goes to the other side.
    assert!(
        u.iter()
            .all(|x| x.withdrawn == x.fee && !x.new_commitment.is_zero())
    );

    // Experiment 32's link, the other's nullifier alone, is refused under version 2.
    let mut v1_style = u.clone();
    v1_style[0].link = u[1].nullifier;
    v1_style[1].link = u[0].nullifier;
    let tx = |us: &[kohaku_frame_registry::Update], d| {
        update_tx(&registry(), 8141, U256::ZERO, 0, d, us, Fees::default())
    };
    assert_eq!(tx(&v1_style, Some(1)).unwrap_err(), UpdateError::Link);
    // Either update alone, or the pair with one side's change redirected, is refused too.
    assert_eq!(tx(&u[..1], Some(1)).unwrap_err(), UpdateError::Link);
    let mut redirected = u.clone();
    redirected[1].new_commitment = U256::from(1);
    assert_eq!(tx(&redirected, Some(1)).unwrap_err(), UpdateError::Link);
    assert_eq!(tx(&u, None).unwrap_err(), UpdateError::Deadline);
}

#[test]
fn the_roots_are_the_trees_the_registry_logged() {
    let (_, deposits) = fixture(DEPOSITS);
    let (swap, swap_receipt) = fixture(SWAP);
    let mut leaves = inserted(&deposits);
    assert_eq!(leaves.len(), 4);
    let root = |l: &[Field]| U256::from_be_bytes(root_of(l).unwrap().0);
    assert_eq!(carried(&swap).2, root(&leaves));
    let changes = inserted(&swap_receipt);
    assert_eq!(changes.len(), 2);
    let (_, _, _, u) = carried(&swap);
    for c in &changes {
        let c: U256 = (*c).into();
        assert!(u.iter().any(|x| x.new_commitment == c));
    }
    leaves.extend(changes);
    for hash in SOLO {
        assert_eq!(carried(&fixture(hash).0).2, root(&leaves));
    }
}

#[test]
fn the_board_holds_three_sealed_offers_and_three_answers() {
    for (i, hash) in POSTS.iter().enumerate() {
        let (tx, _) = fixture(hash);
        let post = tx.frames.iter().find(|f| f.mode == mode::SENDER).unwrap();
        assert_eq!(post.target, Some(BOARD));
        let m = postCall::abi_decode(&post.data).unwrap().message;
        assert_eq!(m[0], 1);
        let plain = if i % 2 == 0 { Offer::LEN } else { Accept::LEN };
        assert_eq!(m.len(), OVERHEAD + plain);
    }
}

#[test]
fn seals_the_vector_to_the_typescript_bytes_and_opens_it() {
    let v: Value = serde_json::from_slice(
        &fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/announcement.json"))
            .unwrap(),
    )
    .unwrap();
    let seed = hex_bytes(&v["seed"]);
    let [alice, bob, e1, e2] =
        ["alice", "bob", "offer", "accept"].map(|l| Keys::derive(&seed, l).unwrap());
    assert_eq!(
        alice.public.to_vec(),
        hex_bytes(&v["keys"]["alice"]["public"])
    );
    assert_eq!(bob.secret.to_vec(), hex_bytes(&v["keys"]["bob"]["secret"]));

    let offer_plain = hex_bytes(&v["offer"]["plaintext"]);
    let offer_message = seal(&bob.public, &offer_plain, &e1).unwrap();
    assert_eq!(offer_message, hex_bytes(&v["offer"]["message"]));
    assert_eq!(
        offer_id(&offer_message).to_vec(),
        hex_bytes(&v["offer"]["id"])
    );
    let opened = open(bob.secret, &offer_message).unwrap();
    let offer = Offer::decode(&opened).unwrap();
    assert_eq!(offer.encode(), offer_plain);
    assert_eq!(offer.reply_key, alice.public);
    assert_eq!(open(alice.secret, &offer_message), None);

    let accept_message =
        seal(&offer.reply_key, &hex_bytes(&v["accept"]["plaintext"]), &e2).unwrap();
    assert_eq!(accept_message, hex_bytes(&v["accept"]["message"]));
    let accept = Accept::decode(&open(alice.secret, &accept_message).unwrap()).unwrap();
    assert_eq!(accept.offer, offer_id(&offer_message));
    assert_eq!(open(bob.secret, &accept_message), None);
}
