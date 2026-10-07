//! The withdrawals mined on the Hegota testnet, rebuilt byte for byte: six built in TypeScript
//! by `exp-frames` experiment 06, and one sent by `examples/keyed_withdrawal.rs`.

use std::{fs, path::Path};

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
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
        FramePool, PoolMode, WithdrawalOpts, WithdrawalTxError, abi::withdrawCall, withdrawal_tx,
    },
};
use serde::Deserialize;

const STORAGE_POOL: Address = address!("0xa082522bF0745bDC93e91427ea0321Ec605f508c");
const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");

fn keyed_salt() -> B256 {
    keccak256("exp-frames/06/pool-keyed")
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

/// Read back what the builder was given: the proof from the withdrawal frame, the slot from the
/// recent-root frame, the sponsor from the payment frame.
fn rebuild(
    mined: &FrameTx,
) -> (
    FramePool,
    Option<Address>,
    Result<FrameTx, WithdrawalTxError>,
) {
    let pool = if mined.sender == KEYED_POOL {
        FramePool {
            address: KEYED_POOL,
            mode: PoolMode::Keyed,
            salt: keyed_salt(),
        }
    } else {
        assert_eq!(mined.sender, STORAGE_POOL);
        FramePool {
            address: STORAGE_POOL,
            mode: PoolMode::Storage,
            salt: B256::ZERO,
        }
    };
    let w = mined.frames.last().unwrap();
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
    (pool, sponsor, built)
}

#[test]
fn rebuilds_every_mined_withdrawal() {
    let mut layouts = Vec::new();
    for tx in mined() {
        let (pool, sponsor, built) = rebuild(&tx);
        let built = built.unwrap();
        assert_eq!(built, tx);
        assert_eq!(built.hash(), tx.hash());
        layouts.push((pool.mode, sponsor.is_some()));
    }
    // All four layouts are covered.
    for layout in [
        (PoolMode::Storage, false),
        (PoolMode::Storage, true),
        (PoolMode::Keyed, false),
        (PoolMode::Keyed, true),
    ] {
        assert!(layouts.contains(&layout), "{layout:?}");
    }
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
        ..opts
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
                ..opts
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
