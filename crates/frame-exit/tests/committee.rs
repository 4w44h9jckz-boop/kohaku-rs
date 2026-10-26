//! The committee's own vectors (`exp-e2e-frames` `test/fixtures/x9/vectors.json`, fake keys from
//! a seed, for checks only), read by the owner's side: the intent opens to the owner's address,
//! the three openings assemble to the nullifier at the leaf, and the note makes the commitment.

use alloy::primitives::{Address, B256};
use kohaku_frame_exit::{
    Context, OpeningKey,
    intent::open_intent,
    note::{Garbage, assemble, check, secret_point},
};
use kohaku_tornadocash::{Field, Secret, pack_point};
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!("fixtures/committee.json")).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn key(v: &Value) -> OpeningKey {
    OpeningKey::from_secret(B256::from_slice(&bytes(v))).unwrap()
}

#[test]
fn the_committees_vectors_open_on_the_owners_side() {
    let v = vectors();
    let vault: Address = v["vault"].as_str().unwrap().parse().unwrap();
    let index = v["index"].as_u64().unwrap();
    let owner = key(&v["ownerSecret"]);
    let committee = key(&v["committeeSecret"]);
    assert_eq!(owner.public.to_vec(), bytes(&v["ownerKey"]));
    assert_eq!(committee.public.to_vec(), bytes(&v["committeeKey"]));

    // The intent carries the owner's opening key and secret point.
    let address = open_intent(&committee, vault, index, &bytes(&v["sealedIntent"])).unwrap();
    assert_eq!(address.key, owner.public);
    assert_eq!(address.secret_point.to_vec(), bytes(&v["b"]));
    let secret = Secret::new(bytes(&v["secret"]).try_into().unwrap());
    assert_eq!(pack_point(&secret_point(&secret)), address.secret_point);

    // The openings, published at update = intent index, assemble to the nullifier at the leaf.
    let openings = bytes(&v["openings"]);
    let context = Context {
        vault,
        update: index,
    };
    let opening = assemble(&owner, &context, &openings).unwrap().unwrap();
    assert_eq!(
        opening.leaf,
        u32::try_from(v["leaf"].as_u64().unwrap()).unwrap()
    );
    assert_eq!(opening.update, index);
    assert_eq!(
        opening.nullifier.as_bytes().to_vec(),
        bytes(&v["nullifier"])
    );
    assert!(assemble(&committee, &context, &openings).is_none());
    assert!(
        assemble(
            &owner,
            &Context {
                vault,
                update: index + 1
            },
            &openings
        )
        .is_none(),
        "sealed for one update only"
    );

    // With the owner's secret, the note is the commitment the vault holds.
    let commitment = Field::try_from(B256::from_slice(&bytes(&v["commitment"]))).unwrap();
    let note = check(&opening, &secret, commitment).unwrap();
    assert_eq!(note.commitment(), commitment);
    let other = Field::try_from(B256::with_last_byte(7)).unwrap();
    assert_eq!(
        check(&opening, &secret, other),
        Err(Garbage::Commitment(opening.leaf))
    );
}
