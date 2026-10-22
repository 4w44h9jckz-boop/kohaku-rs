//! A withdrawal's witness, shared and put back together: every private value is replicated as
//! the format says and sums to the witness, and only the six public inputs are in the clear.

use alloy::primitives::{Address, U256};
use ark_bn254::Fr;
use kohaku_tornadocash::{Field, Note, Payer};
use kohaku_witness_share::{
    Encoding, MEMBERS, NUM_INSTANCE_VARIABLES, WITNESS_LEN, decimal, extend_witness, reconstruct,
    share,
};
use rand::RngExt;

#[test]
fn shares_put_back_the_withdrawal_witness() {
    let mut rng = rand::rng();
    let note: Note = rng.random();
    let others: [Note; 2] = [rng.random(), rng.random()];
    let leaves: Vec<Field> = vec![
        others[0].commitment(),
        note.commitment(),
        others[1].commitment(),
    ];
    let pool = Address::repeat_byte(0xe1);
    let payer = Payer {
        address: pool,
        fee: U256::from(10u64).pow(U256::from(13u64)),
        refund: U256::ZERO,
    };
    let (leaf, public, inputs) =
        kohaku_frame_pool::circuit_inputs(note.clone(), &leaves, Address::repeat_byte(0x42), payer)
            .unwrap();
    assert_eq!(leaf, 1);
    let witness = extend_witness(&inputs).unwrap();
    assert_eq!(witness.len(), WITNESS_LEN);

    for encoding in [Encoding::Replicated, Encoding::SeededReplicated] {
        let shares = share(&witness, encoding, &mut rand08::rngs::OsRng).unwrap();
        assert_eq!(shares.members.len(), MEMBERS);
        assert_eq!(reconstruct(&shares.members).unwrap(), witness);

        // The six public inputs, in the circuit's order, and nothing private, in the clear.
        let expected = [
            U256::from_be_bytes(public.root.0),
            U256::from_be_bytes(public.nullifier_hash.0),
            U256::from_be_slice(public.recipient.as_slice()),
            U256::from_be_slice(public.relayer.as_slice()),
            public.fee,
            public.refund,
        ];
        assert_eq!(
            shares.public.inputs,
            expected.iter().map(ToString::to_string).collect::<Vec<_>>()
        );
        if encoding == Encoding::Replicated {
            // 28,293 private values, two field elements each, plus framing.
            let private = WITNESS_LEN - NUM_INSTANCE_VARIABLES;
            for m in &shares.members {
                assert!(
                    m.len() > private * 64 && m.len() < private * 64 + 1024,
                    "{} bytes",
                    m.len()
                );
            }
        }
        // No share carries a private value in the clear: the note's nullifier and secret
        // (witness indices 7 and 8, after the public inputs) appear in no share's bytes.
        for k in [NUM_INSTANCE_VARIABLES, NUM_INSTANCE_VARIABLES + 1] {
            let le = ark_ff::BigInteger::to_bytes_le(&ark_ff::PrimeField::into_bigint(witness[k]));
            for m in &shares.members {
                assert!(
                    !m.windows(32).any(|w| w == le.as_slice()),
                    "a private value in the clear"
                );
            }
        }
    }
    assert_eq!(decimal(&Fr::from(7u64)), "7");
}
