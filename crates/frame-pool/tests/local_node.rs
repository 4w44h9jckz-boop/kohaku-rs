//! `examples/keyed_withdrawal.rs` against a local ethrex node from `kohaku-fork-kit`, instead of
//! the testnet: the keyed pool is deployed first, by the same CREATE2 frames `exp-frames`
//! experiment 06 used (`tests/fixtures/deployments.json`, exported by its `export.ts`), so it
//! lands at its testnet address. Then a deposit and a withdrawal with the pool as sender, and
//! the withdrawal's frames must use exactly the gas the example's withdrawal used on the testnet
//! in block 304501.
//!
//! Skipped unless `ETHREX_BIN` names an ethrex binary built as `kohaku_fork_kit::ethrex` says.

use std::{fs, path::Path};

use alloy::{
    primitives::{Address, Bytes, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::ensure;
use kohaku_fork_kit::ethrex::EthrexBuilder;
use kohaku_frame_kit::{
    Frame, FrameSigner, FrameTx, constants::approve, json::FrameTxReceiptJson, rpc, sign_all,
};
use kohaku_frame_pool::{
    chain, prove,
    withdrawal::{DENOMINATION, FramePool, POOL_FEES, PoolMode, WithdrawalOpts, withdrawal_tx},
};
use kohaku_tornadocash::{Note, Payer};
use rand::RngExt;
use serde::Deserialize;

const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");
/// `examples/keyed_withdrawal.rs`'s fee.
const FEE: u64 = 10_000_000_000;
/// The withdrawal `examples/keyed_withdrawal.rs` sent to the testnet, mined in block 304501.
const TESTNET_WITHDRAWAL: &str =
    "0x7fa5825c354120258bde7201b5a9d9342b04d1cfbea8fb99b80f27362f029017";

#[derive(Deserialize)]
struct Deployments {
    contracts: Vec<Deployment>,
}

#[derive(Deserialize)]
struct Deployment {
    label: String,
    address: Address,
    target: Address,
    data: Bytes,
    execution: u64,
    state: u64,
}

#[derive(Deserialize)]
struct Fixture {
    receipt: FrameTxReceiptJson,
}

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
}

#[tokio::test(flavor = "multi_thread")]
async fn keyed_withdrawal_spends_the_testnets_frame_gas() -> anyhow::Result<()> {
    let Some(builder) = EthrexBuilder::from_env() else {
        eprintln!("skipped: ETHREX_BIN does not name an ethrex binary");
        return Ok(());
    };
    let funder = PrivateKeySigner::random();
    let ethrex = builder
        .prefund(funder.address(), U256::from(10u128.pow(19)))
        .spawn()
        .await?;
    let provider = ProviderBuilder::new().connect_http(ethrex.rpc_url().parse()?);
    let funder = FrameSigner::Secp256k1(funder);

    // 1. The hasher, the patched verifier and the keyed pool, each from the funder's account.
    let deployments: Deployments =
        serde_json::from_slice(&fs::read(fixtures().join("deployments.json"))?)?;
    for d in deployments.contracts {
        let from = funder.address();
        let mut tx = FrameTx {
            chain_id: ethrex.chain_id(),
            nonce_keys: vec![U256::ZERO],
            nonce_seq: rpc::nonce_seq(&provider, from, &[U256::ZERO]).await?,
            sender: from,
            frames: vec![
                Frame::verify(approve::EXECUTION_AND_PAYMENT, None).with_execution(20_000),
                Frame::sender(Some(d.target))
                    .with_data(d.data)
                    .with_execution(d.execution)
                    .with_state(d.state),
            ],
            signatures: vec![funder.placeholder(None)],
            fees: POOL_FEES,
            blob_versioned_hashes: vec![],
        };
        sign_all(&mut tx, std::slice::from_ref(&funder))?;
        rpc::execute(&provider, &tx, true).await?;
        ensure!(
            !provider.get_code_at(d.address).await?.is_empty(),
            "{} is not at {}",
            d.label,
            d.address
        );
    }

    // 2. What the example does: deposit, read the tree back, prove, withdraw.
    let pool = FramePool {
        address: KEYED_POOL,
        mode: PoolMode::Keyed,
        salt: keccak256("exp-frames/06/pool-keyed"),
    };
    let note: Note = rand::rng().random();
    let deposited = chain::deposit(&provider, &pool, &funder, &note).await?;
    let leaves = chain::leaves(&provider, pool.address, deposited.leaf_index).await?;
    let recipient = PrivateKeySigner::random().address();
    let payer = Payer {
        address: pool.address,
        fee: U256::from(FEE),
        refund: U256::ZERO,
    };
    let proof = prove(note, &leaves, recipient, payer, &mut rand::rng())?;
    ensure!(proof.inputs.root == deposited.root);
    let opts = WithdrawalOpts {
        root_slot: Some(deposited.slot),
        ..WithdrawalOpts::new(ethrex.chain_id())
    };
    let tx = withdrawal_tx(&pool, &proof.inputs, &proof.proof, &opts)?;
    let receipt = rpc::execute(&provider, &tx, true).await?.receipt;
    ensure!(receipt.payer == pool.address, "the pool did not pay");
    ensure!(provider.get_balance(recipient).await? == U256::from(DENOMINATION - u128::from(FEE)));

    // 3. Frame for frame, the gas the same withdrawal used on the testnet.
    let testnet: Fixture = serde_json::from_slice(&fs::read(
        fixtures().join(format!("chain/{TESTNET_WITHDRAWAL}.json")),
    )?)?;
    let gas = |r: &FrameTxReceiptJson| -> Vec<(U256, U256, U256)> {
        r.frame_receipts
            .iter()
            .map(|f| (f.status, f.gas_used, f.state_gas_used))
            .collect()
    };
    assert_eq!(gas(&receipt), gas(&testnet.receipt));
    Ok(())
}
