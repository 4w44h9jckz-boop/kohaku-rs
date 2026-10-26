//! A note no committee member can redeem, end to end and offline: the owner's receiving address,
//! the intent sealed to the committee, the committee's three parts of the nullifier and the
//! commitment they make with the owner's secret point, the openings sealed to the owner, the
//! owner's assembly and check, every kind of garbage, and the redemption transaction.

use alloy::primitives::{Address, B256, U256, address};
use kohaku_frame_exit::{
    Context, MESSAGE_LEN, OpeningKey,
    intent::{SEALED_LEN, open_intent, seal_intent},
    note::{
        Garbage, MEMBERS, Part, assemble, check, member_mask, note_secret, receive, secret_point,
        split,
    },
    opening_key, seal,
    vault::{MAX_SEQUENCE, redemption},
};
use kohaku_frame_pool::withdrawal::{FramePool, PoolMode, WithdrawalOpts};
use kohaku_frame_secrets::Seed;
use kohaku_tornadocash::{
    Field, Note, Nullifier, Secret, merkle_tree::MerkleTree, pack_point, pedersen_point,
    unpack_point,
};
use rand::RngExt;

const PHRASE: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const VAULT: Address = address!("0x7Bc7902c7DEABFbD7Abd783C49BA7Bf946D13314");

fn seed() -> Seed {
    Seed::from_mnemonic(PHRASE).unwrap()
}

#[test]
fn the_secret_point_is_circomlibs() {
    // circomlibjs: packPoint(H(0^31 || s) - H(0^62)) for s = bytes 101..=131.
    let s = Secret::new(std::array::from_fn(|i| 101 + i as u8));
    assert_eq!(
        hex::encode(pack_point(&secret_point(&s))),
        "224d59f278e36b0f80fde3448ca7fe3f4c9e06742075dceec9ef1331171e13a3"
    );
}

/// The committee, honestly: three random parts of a nullifier, the commitment they make with the
/// owner's secret point, and each part sealed to the owner.
struct Committee {
    parts: [[u8; 31]; MEMBERS],
    commitment: Field,
}

impl Committee {
    fn new(secret_point_packed: &[u8; 32]) -> Self {
        let n: [u8; 31] = rand::rng().random();
        let parts = split(&n);
        let z = [0u8; 62];
        let a = |part: &[u8; 31]| {
            let mut d = [0u8; 62];
            d[..31].copy_from_slice(part);
            pedersen_point(&d)
        };
        let zero = pedersen_point(&z);
        let b = unpack_point(secret_point_packed).unwrap();
        let point = a(&parts[0])
            .add(&a(&parts[1]))
            .add(&a(&parts[2]))
            .add(&zero.neg())
            .add(&zero.neg())
            .add(&b);
        Self {
            parts,
            commitment: Field::from(point.x),
        }
    }

    fn openings(&self, to: &[u8; 33], leaf: u32, context: &Context) -> Vec<u8> {
        (0..MEMBERS)
            .flat_map(|m| {
                let part = Part {
                    member: m as u8,
                    part: self.parts[m],
                    leaf,
                    update: context.update,
                };
                seal(
                    to,
                    context,
                    &part.encode(),
                    &OpeningKey::random(&mut rand::rng()),
                )
                .unwrap()
                .to_vec()
            })
            .collect()
    }
}

#[test]
fn the_owner_alone_can_open_and_spend() {
    let seed = seed();
    let address = receive(&seed, VAULT, 0, 0).unwrap();
    let secret = note_secret(&seed, VAULT, 0);
    // The receiving address carries neither the secret nor the opening key's secret.
    assert!(
        !address
            .secret_point
            .windows(31)
            .any(|w| w == secret.as_bytes())
    );

    // The holder seals it to the committee in the intent; the committee opens it.
    let committee_key = OpeningKey::random(&mut rand::rng());
    let sealed = seal_intent(
        &committee_key.public,
        VAULT,
        5,
        &address,
        &OpeningKey::random(&mut rand::rng()),
    )
    .unwrap();
    assert_eq!(sealed.len(), SEALED_LEN);
    assert_eq!(
        open_intent(&committee_key, VAULT, 5, &sealed),
        Some(address)
    );
    assert_eq!(
        open_intent(&committee_key, VAULT, 6, &sealed),
        None,
        "another intent index"
    );
    assert_eq!(
        open_intent(&OpeningKey::random(&mut rand::rng()), VAULT, 5, &sealed),
        None
    );

    // The committee makes the commitment from three parts and the secret point.
    let committee = Committee::new(&address.secret_point);
    let n: [u8; 31] = std::array::from_fn(|i| committee.parts.iter().fold(0, |b, p| b | p[i]));
    let note = Note::new(Nullifier::new(n), secret);
    assert_eq!(
        note.commitment(),
        committee.commitment,
        "C = x(A(n_0) + A(n_1) + A(n_2) - 2A(0) + B(s))"
    );

    // The owner opens the update's three parts, assembles n and checks C.
    let key = opening_key(&seed, VAULT, 0).unwrap();
    let context = Context {
        vault: VAULT,
        update: 5,
    };
    let openings = committee.openings(&key.public, 1, &context);
    let opening = assemble(&key, &context, &openings).unwrap().unwrap();
    assert_eq!((opening.leaf, opening.update), (1, 5));
    let checked = check(&opening, &secret, committee.commitment).unwrap();
    assert_eq!(checked.commitment(), committee.commitment);
    assert_eq!(checked.nullifier_hash(), note.nullifier_hash());

    // Another key sees nothing in it; all members' parts together, without s, do not make C.
    assert!(assemble(&OpeningKey::random(&mut rand::rng()), &context, &openings).is_none());
    let guess = Note::new(Nullifier::new(n), Secret::new([0; 31]));
    assert_ne!(guess.commitment(), committee.commitment);
}

#[test]
#[allow(clippy::too_many_lines)]
fn every_kind_of_garbage_is_caught() {
    let seed = seed();
    let address = receive(&seed, VAULT, 0, 1).unwrap();
    let secret = note_secret(&seed, VAULT, 1);
    let key = opening_key(&seed, VAULT, 0).unwrap();
    let context = Context {
        vault: VAULT,
        update: 9,
    };
    let committee = Committee::new(&address.secret_point);
    let fresh = || OpeningKey::random(&mut rand::rng());
    let sealed = |m: usize, part: [u8; 31], leaf: u32, update: u64| {
        seal(
            &key.public,
            &context,
            &Part {
                member: m as u8,
                part,
                leaf,
                update,
            }
            .encode(),
            &fresh(),
        )
        .unwrap()
        .to_vec()
    };
    let build = |parts: Vec<Vec<u8>>| parts.concat();
    let p = committee.parts;

    let ok = build(vec![
        sealed(0, p[0], 2, 9),
        sealed(1, p[1], 2, 9),
        sealed(2, p[2], 2, 9),
    ]);
    assert!(assemble(&key, &context, &ok).unwrap().is_ok());

    let other = seal(
        &fresh().public,
        &context,
        &Part {
            member: 2,
            part: p[2],
            leaf: 2,
            update: 9,
        }
        .encode(),
        &fresh(),
    )
    .unwrap()
    .to_vec();
    let cases: Vec<(Vec<u8>, Garbage)> = vec![
        (
            build(vec![sealed(0, p[0], 2, 9), sealed(1, p[1], 2, 9), other]),
            Garbage::Parts(2),
        ),
        (
            build(vec![
                sealed(1, p[1], 2, 9),
                sealed(0, p[0], 2, 9),
                sealed(2, p[2], 2, 9),
            ]),
            Garbage::Member {
                position: 0,
                member: 1,
            },
        ),
        (
            build(vec![
                sealed(0, [0xff; 31], 2, 9),
                sealed(1, p[1], 2, 9),
                sealed(2, p[2], 2, 9),
            ]),
            Garbage::Windows(0),
        ),
        (
            build(vec![
                sealed(0, p[0], 2, 9),
                sealed(1, p[1], 3, 9),
                sealed(2, p[2], 2, 9),
            ]),
            Garbage::Disagree,
        ),
        (
            build(vec![
                sealed(0, p[0], 2, 8),
                sealed(1, p[1], 2, 8),
                sealed(2, p[2], 2, 8),
            ]),
            Garbage::Update {
                named: 8,
                published: 9,
            },
        ),
        (
            ok[..2 * MESSAGE_LEN].to_vec(),
            Garbage::Length(2 * MESSAGE_LEN),
        ),
    ];
    for (openings, expected) in cases {
        assert_eq!(assemble(&key, &context, &openings), Some(Err(expected)));
    }
    // A part that opens to bad padding is malformed.
    let mut bad = Part {
        member: 0,
        part: p[0],
        leaf: 2,
        update: 9,
    }
    .encode();
    bad[47] = 1;
    let malformed = build(vec![
        seal(&key.public, &context, &bad, &fresh())
            .unwrap()
            .to_vec(),
        sealed(1, p[1], 2, 9),
        sealed(2, p[2], 2, 9),
    ]);
    assert_eq!(
        assemble(&key, &context, &malformed),
        Some(Err(Garbage::Malformed(0)))
    );

    // A nullifier that does not make the vault's commitment with the owner's secret.
    let opening = assemble(&key, &context, &ok).unwrap().unwrap();
    let wrong = Field::try_from(U256::from(7u8)).unwrap();
    assert_eq!(check(&opening, &secret, wrong), Err(Garbage::Commitment(2)));
}

#[test]
fn the_windows_partition_the_nullifier() {
    let masks: Vec<[u8; 31]> = (0..MEMBERS).map(member_mask).collect();
    #[allow(clippy::needless_range_loop)]
    for i in 0..31 {
        assert_eq!(
            masks[0][i] | masks[1][i] | masks[2][i],
            0xff,
            "byte {i} covered"
        );
        assert_eq!(
            masks[0][i] & masks[1][i] | masks[1][i] & masks[2][i] | masks[0][i] & masks[2][i],
            0,
            "byte {i} once"
        );
    }
}

#[test]
// The Groth16 prover overflows a debug build's stack.
#[cfg_attr(debug_assertions, ignore = "run with `cargo test --release -- --ignored`")]
fn the_redemption_is_the_refund_pools_withdrawal_at_the_chosen_sequence() {
    let seed = seed();
    let address = receive(&seed, VAULT, 0, 0).unwrap();
    let committee = Committee::new(&address.secret_point);
    let key = opening_key(&seed, VAULT, 0).unwrap();
    let context = Context {
        vault: VAULT,
        update: 1,
    };
    let opening = assemble(
        &key,
        &context,
        &committee.openings(&key.public, 1, &context),
    )
    .unwrap()
    .unwrap();
    let note = check(
        &opening,
        &note_secret(&seed, VAULT, 0),
        committee.commitment,
    )
    .unwrap();

    let others: [Note; 2] = [rand::rng().random(), rand::rng().random()];
    let leaves = vec![
        others[0].commitment(),
        committee.commitment,
        others[1].commitment(),
    ];
    let vault = FramePool {
        address: VAULT,
        mode: PoolMode::Refund,
        salt: B256::repeat_byte(9),
    };
    let opts = WithdrawalOpts {
        root_slot: Some(1_000),
        ..WithdrawalOpts::new(8141)
    };
    let recipient = kohaku_frame_exit::recipient(&seed, VAULT, 0).unwrap();
    for sequence in 0..=MAX_SEQUENCE {
        let (tx, proof) = redemption(
            &vault,
            &note,
            &leaves,
            recipient,
            &opts,
            sequence,
            &mut rand::rng(),
        )
        .unwrap();
        assert_eq!(tx.sender, VAULT, "the vault is the sender");
        assert_eq!(tx.nonce_seq, sequence);
        assert_eq!(
            tx.nonce_keys,
            vec![U256::from_be_bytes(proof.inputs.nullifier_hash.0)]
        );
        assert!(tx.signatures.is_empty(), "nothing signed");
        assert_eq!(proof.inputs.relayer, VAULT, "the vault pays");
        assert_eq!(proof.inputs.recipient, recipient);
        assert_eq!(
            B256::from(note.nullifier_hash()),
            proof.inputs.nullifier_hash
        );
        assert_eq!(
            B256::from(MerkleTree::from_leaves(&leaves).unwrap().root().unwrap()),
            proof.inputs.root
        );
        assert_eq!(proof.leaf_index, 1);
    }
    assert!(
        redemption(
            &vault,
            &note,
            &leaves,
            recipient,
            &opts,
            MAX_SEQUENCE + 1,
            &mut rand::rng()
        )
        .is_err()
    );
}
