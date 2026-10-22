use alloy::primitives::{B256, U256, address};
use kohaku_frame_pool::{FramePoolError, prove};
use kohaku_tornadocash::{Note, Payer, merkle_tree::MerkleTree};
use rand::RngExt;

fn notes(n: usize) -> Vec<Note> {
    let mut rng = rand::rng();
    (0..n).map(|_| rng.random::<Note>()).collect()
}

#[test]
fn refuses_a_note_that_is_not_a_leaf() {
    let notes = notes(3);
    let leaves: Vec<_> = notes[..2].iter().map(Note::commitment).collect();
    let payer = Payer {
        address: address!("0x00000000000000000000000000000000000000aa"),
        fee: U256::ZERO,
        refund: U256::ZERO,
    };
    let err = prove(
        notes[2].clone(),
        &leaves,
        address!("0x00000000000000000000000000000000000000bb"),
        payer,
        &mut rand::rng(),
    )
    .unwrap_err();
    assert!(matches!(err, FramePoolError::MissingLeaf));
}

#[test]
#[ignore = "run with `cargo test --release -- --ignored`"]
fn proves_against_the_tree_of_the_leaves() -> anyhow::Result<()> {
    let notes = notes(4);
    let leaves: Vec<_> = notes.iter().map(Note::commitment).collect();
    let recipient = address!("0x00000000000000000000000000000000000000bb");
    // A pool that pays for its own withdrawal names itself as relayer and takes the fee.
    let pool = address!("0x00000000000000000000000000000000000000aa");
    let payer = Payer {
        address: pool,
        fee: U256::from(10_000_000_000u64),
        refund: U256::ZERO,
    };

    let proof = prove(
        notes[2].clone(),
        &leaves,
        recipient,
        payer,
        &mut rand::rng(),
    )?;

    let root = MerkleTree::from_leaves(&leaves)?.root()?;
    assert_eq!(proof.leaf_index, 2);
    assert_eq!(proof.commitment, B256::from(notes[2].commitment()));
    assert_eq!(proof.inputs.root, B256::from(root));
    assert_eq!(
        proof.inputs.nullifier_hash,
        B256::from(notes[2].nullifier_hash())
    );
    assert_eq!(proof.inputs.recipient, recipient);
    assert_eq!(proof.inputs.relayer, pool);
    assert_eq!(proof.inputs.fee, payer.fee);
    assert_eq!(proof.inputs.refund, U256::ZERO);
    assert_eq!(proof.proof.len(), 8 * 32);
    Ok(())
}
