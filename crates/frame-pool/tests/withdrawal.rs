//! The withdrawals mined on the Hegota testnet, rebuilt byte for byte: six built in TypeScript
//! by `exp-frames` experiment 06, one sent by `examples/keyed_withdrawal.rs`, two built in
//! TypeScript by `exp-frames` experiment 30 (one from its `RefundPool`), one `RefundPool`
//! withdrawal sent by `examples/refund_withdrawal.rs`, and the note `kohaku-frame-wallet`'s
//! `device_recovery` example recovered from two devices and withdrew.

use std::{fs, path::Path};

use alloy::{
    primitives::{Address, B256, U256, address, b256, keccak256},
    sol_types::SolCall,
};
use kohaku_frame_kit::{
    FrameTx,
    constants::{RECENT_ROOT, approve, mode},
    json::FrameTxJson,
};
use kohaku_frame_pool::{
    PublicInputs,
    withdrawal::{
        FramePool, PoolMode, REFUND_EXECUTION, WithdrawalOpts, WithdrawalTxError,
        abi::withdrawCall, tightened_limits, withdrawal_tx, worst_case_max_cost,
    },
};
use serde::Deserialize;

const STORAGE_POOL: Address = address!("0xa082522bF0745bDC93e91427ea0321Ec605f508c");
const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");
const REFUND_POOL: Address = address!("0xe19605853A749322655470199Fd31D3F3e53Baf9");

fn keyed_salt() -> B256 {
    keccak256("exp-frames/06/pool-keyed")
}

fn refund_salt() -> B256 {
    keccak256("exp-frames/30/refund-pool")
}

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
}

fn mined() -> Vec<FrameTx> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chain");
    let mut out: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let f: Fixture = serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap();
            let tx = FrameTx::try_from(&f.tx).unwrap();
            assert_eq!(tx.hash(), f.tx.hash);
            tx
        })
        .collect();
    out.sort_by_key(FrameTx::hash);
    out
}

/// How a mined withdrawal was rebuilt.
struct Rebuilt {
    pool: FramePool,
    sponsor: Option<Address>,
    /// Whether the builder's default execution limits reproduced it, or the mined limits had to
    /// be passed, as a wallet that tightens them from a simulation passes them.
    default_limits: bool,
    built: Result<FrameTx, WithdrawalTxError>,
}

/// Read back what the builder was given: the proof from the withdrawal frame, the slot from the
/// recent-root frame, the sponsor from the payment frame, and the execution limits when they
/// are not the defaults.
fn rebuild(mined: &FrameTx) -> Rebuilt {
    let pool = if mined.sender == KEYED_POOL {
        FramePool {
            address: KEYED_POOL,
            mode: PoolMode::Keyed,
            salt: keyed_salt(),
        }
    } else if mined.sender == REFUND_POOL {
        FramePool {
            address: REFUND_POOL,
            mode: PoolMode::Refund,
            salt: refund_salt(),
        }
    } else {
        assert_eq!(mined.sender, STORAGE_POOL);
        FramePool {
            address: STORAGE_POOL,
            mode: PoolMode::Storage,
            salt: B256::ZERO,
        }
    };
    let w = mined
        .frames
        .iter()
        .find(|f| f.mode == mode::SENDER)
        .unwrap();
    let call = withdrawCall::abi_decode(&w.data).unwrap();
    let inputs = PublicInputs {
        root: call.root,
        nullifier_hash: call.nullifierHash,
        recipient: call.recipient,
        relayer: call.relayer,
        fee: call.fee,
        refund: call.refund,
    };
    let sponsor = mined
        .frames
        .iter()
        .find(|f| f.mode == mode::VERIFY && f.flags == approve::PAYMENT)
        .and_then(|f| f.target);
    let root_slot = mined
        .frames
        .iter()
        .find(|f| f.target == Some(RECENT_ROOT))
        .map(|f| u64::from_be_bytes(f.data[32..40].try_into().unwrap()));
    let verify = mined
        .frames
        .iter()
        .find(|f| f.mode == mode::VERIFY && f.target.is_none())
        .unwrap();
    let opts = WithdrawalOpts {
        sponsor,
        root_slot,
        nonce: Some(mined.nonce_seq),
        verify_execution: verify.limits.execution,
        fees: mined.fees,
        ..WithdrawalOpts::new(mined.chain_id)
    };
    let built = withdrawal_tx(&pool, &inputs, &call.proof, &opts);
    if built.as_ref().is_ok_and(|b| b == mined) {
        return Rebuilt {
            pool,
            sponsor,
            default_limits: true,
            built,
        };
    }
    let opts = WithdrawalOpts {
        execution_limits: Some(mined.frames.iter().map(|f| f.limits.execution).collect()),
        ..opts
    };
    Rebuilt {
        pool,
        sponsor,
        default_limits: false,
        built: withdrawal_tx(&pool, &inputs, &call.proof, &opts),
    }
}

#[test]
fn rebuilds_every_mined_withdrawal() {
    let mut layouts = Vec::new();
    let mut limits = [0usize; 2];
    for tx in mined() {
        let r = rebuild(&tx);
        let built = r.built.unwrap();
        assert_eq!(built, tx);
        assert_eq!(built.hash(), tx.hash());
        layouts.push((r.pool.mode, r.sponsor.is_some()));
        limits[usize::from(r.default_limits)] += 1;
    }
    // All five layouts are covered.
    for layout in [
        (PoolMode::Storage, false),
        (PoolMode::Storage, true),
        (PoolMode::Keyed, false),
        (PoolMode::Keyed, true),
        (PoolMode::Refund, false),
    ] {
        assert!(layouts.contains(&layout), "{layout:?}");
    }
    // Experiment 06, `keyed_withdrawal` and `device_recovery` used the defaults; experiment 30 and
    // `refund_withdrawal` tightened every limit from a simulation.
    assert_eq!(limits, [3, 8]);
}

#[test]
fn a_refund_pool_takes_no_sponsor_and_keeps_its_floors() {
    let tx = mined()
        .into_iter()
        .find(|t| t.sender == REFUND_POOL)
        .unwrap();
    let w = &tx.frames[2];
    let call = withdrawCall::abi_decode(&w.data).unwrap();
    let inputs = PublicInputs {
        root: call.root,
        nullifier_hash: call.nullifierHash,
        recipient: call.recipient,
        relayer: call.relayer,
        fee: call.fee,
        refund: call.refund,
    };
    let pool = FramePool {
        address: REFUND_POOL,
        mode: PoolMode::Refund,
        salt: refund_salt(),
    };
    let opts = WithdrawalOpts {
        root_slot: Some(1),
        fees: tx.fees,
        ..WithdrawalOpts::new(tx.chain_id)
    };
    let refuse =
        |opts: &WithdrawalOpts| withdrawal_tx(&pool, &inputs, &call.proof, opts).unwrap_err();
    assert!(matches!(
        refuse(&WithdrawalOpts {
            sponsor: Some(REFUND_POOL),
            ..opts.clone()
        }),
        WithdrawalTxError::SponsoredRefund
    ));
    assert!(matches!(
        refuse(&WithdrawalOpts {
            execution_limits: Some(vec![10_000, 400_000, 100_000]),
            ..opts.clone()
        }),
        WithdrawalTxError::Limits {
            frames: 4,
            limits: 3
        }
    ));
    assert!(matches!(
        refuse(&WithdrawalOpts {
            execution_limits: Some(vec![10_000, 400_000, 100_000, 24_999]),
            ..opts.clone()
        }),
        WithdrawalTxError::BelowFloor {
            frame: 3,
            limit: 24_999,
            floor: 25_000
        }
    ));
    assert!(matches!(
        refuse(&WithdrawalOpts {
            execution_limits: Some(vec![10_000, 400_000, 99_999, 25_000]),
            ..opts.clone()
        }),
        WithdrawalTxError::BelowFloor { frame: 2, .. }
    ));
    // The defaults, with a fee that covers their max cost: the refund frame comes last, to the
    // pool, with no data and no value.
    let rich = PublicInputs {
        fee: U256::from(10u64.pow(15)),
        ..inputs
    };
    let built = withdrawal_tx(&pool, &rich, &call.proof, &opts).unwrap();
    let refund = built.frames.last().unwrap();
    assert_eq!(refund.mode, mode::DEFAULT);
    assert_eq!(refund.target, Some(REFUND_POOL));
    assert!(refund.data.is_empty() && refund.value.is_zero());
    assert_eq!(refund.limits.execution, REFUND_EXECUTION);
}

#[test]
fn tightens_limits_as_experiment_30_did() {
    // Experiment 30's RefundPool withdrawal: limits from a simulation's use, tightened.
    let tx = mined()
        .into_iter()
        .find(|t| {
            t.hash() == b256!("0xc992b54ace771290579f92435cb12e7eee1368d216eb02c7ed0544343aa2cd10")
        })
        .unwrap();
    let limits: Vec<u64> = tx.frames.iter().map(|f| f.limits.execution).collect();
    // Its frames' execution use, from the experiment's README. A use under the floor is lifted
    // to it; the rest come out at a quarter over plus 5,000.
    let used = [5_579, 244_744, 14_255, 11_531];
    assert_eq!(tightened_limits(&tx, &used), limits);
    // The note's fee covers the worst case of its own shape.
    let call = withdrawCall::abi_decode(&tx.frames[2].data).unwrap();
    assert_eq!(call.fee, worst_case_max_cost(&tx).unwrap());
}

#[test]
fn refuses_what_the_pool_would_refuse() {
    let tx = mined()
        .into_iter()
        .find(|t| t.sender == KEYED_POOL && t.frames.len() == 3)
        .unwrap();
    let w = tx.frames.last().unwrap();
    let call = withdrawCall::abi_decode(&w.data).unwrap();
    let inputs = PublicInputs {
        root: call.root,
        nullifier_hash: call.nullifierHash,
        recipient: call.recipient,
        relayer: call.relayer,
        fee: call.fee,
        refund: call.refund,
    };
    let pool = FramePool {
        address: KEYED_POOL,
        mode: PoolMode::Keyed,
        salt: keyed_salt(),
    };
    let opts = WithdrawalOpts {
        root_slot: Some(1),
        ..WithdrawalOpts::new(tx.chain_id)
    };
    let refuse = |inputs: &PublicInputs, opts: &WithdrawalOpts| {
        withdrawal_tx(&pool, inputs, &call.proof, opts).unwrap_err()
    };

    // The proof names the pool as relayer, so a sponsor cannot be paid with it.
    let sponsored = WithdrawalOpts {
        sponsor: Some(Address::repeat_byte(1)),
        ..opts.clone()
    };
    assert!(matches!(
        refuse(&inputs, &sponsored),
        WithdrawalTxError::Relayer { .. }
    ));
    assert!(matches!(
        refuse(
            &inputs,
            &WithdrawalOpts {
                root_slot: None,
                ..opts.clone()
            }
        ),
        WithdrawalTxError::MissingSlot
    ));
    assert!(matches!(
        refuse(
            &PublicInputs {
                refund: U256::from(1),
                ..inputs
            },
            &opts
        ),
        WithdrawalTxError::Refund
    ));
    assert!(matches!(
        refuse(
            &PublicInputs {
                fee: U256::from(1_000),
                ..inputs
            },
            &opts
        ),
        WithdrawalTxError::Fee { .. }
    ));
}
