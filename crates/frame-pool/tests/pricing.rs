//! The two ways a pool-paid withdrawal is priced, without a chain: `Pricing::Uniform` gives every
//! withdrawal from a pool the same limits and fee, whoever proves it; `Pricing::Tightened` gives
//! limits and a fee that follow one simulation. The use per frame is what X1's refund-pool
//! withdrawal used on the testnet (5,579 / 244,744 / 14,255 / 11,531).

use alloy::primitives::{Address, U256, address, keccak256};
use kohaku_frame_kit::FrameTx;
use kohaku_frame_pool::{
    chain::{WALLET_FEES, tightened_withdrawal, uniform_fee, uniform_withdrawal, worst_case_fee},
    withdrawal::{FramePool, PoolMode, Pricing, WithdrawalOpts, worst_case_max_cost},
};
use kohaku_tornadocash::{Field, Note};
use rand::RngExt;

const REFUND_POOL: Address = address!("0xe19605853A749322655470199Fd31D3F3e53Baf9");
const X1_USED: [u64; 4] = [5_579, 244_744, 14_255, 11_531];

fn pool() -> FramePool {
    FramePool {
        address: REFUND_POOL,
        mode: PoolMode::Refund,
        salt: keccak256("exp-frames/30/refund-pool"),
    }
}

fn opts() -> WithdrawalOpts {
    WithdrawalOpts {
        root_slot: Some(523_382),
        fees: WALLET_FEES,
        ..WithdrawalOpts::new(8141)
    }
}

fn limits(tx: &FrameTx) -> Vec<u64> {
    tx.frames.iter().map(|f| f.limits.execution).collect()
}

fn spend() -> (Note, Vec<Field>) {
    let mut rng = rand::rng();
    let note: Note = rng.random();
    let others: [Note; 2] = [rng.random(), rng.random()];
    let leaves = vec![
        others[0].commitment(),
        note.commitment(),
        others[1].commitment(),
    ];
    (note, leaves)
}

#[test]
fn uniform_is_the_default() {
    assert_eq!(WithdrawalOpts::new(8141).pricing, Pricing::Uniform);
    assert_eq!(Pricing::default(), Pricing::Uniform);
}

#[test]
fn uniform_gives_every_withdrawal_the_pools_defaults_and_one_fee() {
    let recipient = Address::repeat_byte(0x42);
    let fee = uniform_fee(&pool(), recipient, &opts()).unwrap();
    assert_eq!(
        fee,
        U256::from(173_077_600_000_000u64),
        "the fee X6's committee withdrawal carried, in wei"
    );

    let mut seen = vec![];
    for _ in 0..2 {
        let (note, leaves) = spend();
        let (tx, proof) = uniform_withdrawal(
            &pool(),
            &note,
            &leaves,
            recipient,
            &opts(),
            &mut rand::rng(),
        )
        .unwrap();
        assert_eq!(
            limits(&tx),
            [10_000, 400_000, 100_000, 50_000],
            "the pool's default limits"
        );
        assert_eq!(proof.inputs.fee, fee);
        // The fee covers this very transaction's worst case, and no more.
        assert_eq!(worst_case_max_cost(&tx).unwrap(), fee);
        seen.push((limits(&tx), proof.inputs.fee));
    }
    // Two different notes: the same limits and the same fee.
    assert_eq!(seen[0], seen[1]);

    // Limits passed in are ignored: the defaults are what make withdrawals alike.
    let (note, leaves) = spend();
    let o = WithdrawalOpts {
        execution_limits: Some(vec![20_000, 300_000, 100_000, 25_000]),
        ..opts()
    };
    let (tx, _) =
        uniform_withdrawal(&pool(), &note, &leaves, recipient, &o, &mut rand::rng()).unwrap();
    assert_eq!(limits(&tx), [10_000, 400_000, 100_000, 50_000]);
}

#[test]
fn tightened_follows_the_simulation_and_costs_less() {
    let recipient = Address::repeat_byte(0x42);
    let o = WithdrawalOpts {
        pricing: Pricing::Tightened,
        ..opts()
    };
    let (note, leaves) = spend();
    let (tx, proof) = tightened_withdrawal(
        &pool(),
        &note,
        &leaves,
        recipient,
        &o,
        &X1_USED,
        &mut rand::rng(),
    )
    .unwrap();
    // A quarter over the use plus 5,000, never below the pool's floors (100,000 and 25,000).
    assert_eq!(
        limits(&tx),
        [11_973, 310_930, 100_000, 25_000],
        "the limits X6's device withdrawal carried"
    );
    assert_eq!(
        proof.inputs.fee,
        U256::from(150_658_200_000_000u64),
        "the fee X6's device withdrawal carried, in wei"
    );
    assert_eq!(worst_case_max_cost(&tx).unwrap(), proof.inputs.fee);
    assert_eq!(
        worst_case_fee(
            &pool(),
            recipient,
            &WithdrawalOpts {
                execution_limits: Some(limits(&tx)),
                ..o.clone()
            }
        )
        .unwrap(),
        proof.inputs.fee
    );
    assert!(proof.inputs.fee < uniform_fee(&pool(), recipient, &o).unwrap());
}
