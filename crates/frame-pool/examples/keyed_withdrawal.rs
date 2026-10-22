//! Deposit into the keyed frame-native pool on the ethrex Hegota testnet, then withdraw with the
//! pool as `tx.sender`: no relayer, no EOA, no signature on the withdrawal.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-pool --example keyed_withdrawal
//! ```
//!
//! `PRIVATE_KEY` pays the deposit (0.001 ETH plus gas); `RPC_URL` defaults to the testnet. The
//! pool is the one `exp-frames` experiment 06 deployed. The note is printed to standard error
//! before the deposit is sent, so a deposit whose withdrawal fails can still be recovered.

use std::{env, time::Duration};

use alloy::{
    primitives::{Address, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, bail, ensure};
use kohaku_frame_kit::{
    FrameSigner, FrameTx,
    json::FrameTxReceiptJson,
    rpc::{self, HEGOTA_RPC_URL},
};
use kohaku_frame_pool::{
    chain, prove,
    withdrawal::{DENOMINATION, FramePool, PoolMode, WithdrawalOpts, withdrawal_tx},
};
use kohaku_tornadocash::{Note, Payer};
use rand::RngExt;

/// The keyed pool `exp-frames` experiment 06 deployed on the testnet.
const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");
/// What the withdrawal pays the pool for its gas. It must cover the transaction's max cost.
const FEE: u64 = 10_000_000_000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| HEGOTA_RPC_URL.to_owned());
    let signer: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY pays the deposit")?
        .parse()?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let chain_id = provider.get_chain_id().await?;
    let pool = FramePool {
        address: KEYED_POOL,
        mode: PoolMode::Keyed,
        salt: keccak256("exp-frames/06/pool-keyed"),
    };

    // 1. Deposit, from an ordinary account signing an ordinary frame transaction. The pool
    //    published its new root to EIP-8272 in the same frame.
    let note: Note = rand::rng().random();
    eprintln!("note 0x{}", hex::encode(note.preimage()));
    let deposited =
        chain::deposit(&provider, &pool, &FrameSigner::Secp256k1(signer), &note).await?;
    let (leaf_index, root, slot) = (deposited.leaf_index, deposited.root, deposited.slot);
    println!(
        "deposit: block {}; leaf {leaf_index}, root {root} published in slot {slot}",
        deposited.receipt.block_number
    );

    // 2. The tree as it stood after this deposit, from the pool's Deposit events.
    let leaves = chain::leaves(&provider, pool.address, leaf_index).await?;

    // 3. Prove. The pool is the relayer: it pays the gas and keeps the fee.
    let recipient = PrivateKeySigner::random().address();
    let payer = Payer {
        address: pool.address,
        fee: U256::from(FEE),
        refund: U256::ZERO,
    };
    let proof = prove(note, &leaves, recipient, payer, &mut rand::rng())?;
    ensure!(
        proof.inputs.root == root,
        "the tree rebuilt from events does not match the published root"
    );

    // 4. Withdraw, with the pool as sender.
    let opts = WithdrawalOpts {
        root_slot: Some(slot),
        ..WithdrawalOpts::new(chain_id)
    };
    let tx = withdrawal_tx(&pool, &proof.inputs, &proof.proof, &opts)?;
    let withdrawal = submit(&provider, &tx, "withdrawal").await?;
    ensure!(withdrawal.payer == pool.address, "the pool did not pay");

    let received = provider.get_balance(recipient).await?;
    println!("recipient {recipient} received {received} wei");
    ensure!(received == U256::from(DENOMINATION - u128::from(FEE)));
    Ok(())
}

/// Simulate, refuse anything that would not succeed, send, and wait for the receipt.
async fn submit<P: Provider>(
    provider: &P,
    tx: &FrameTx,
    label: &str,
) -> anyhow::Result<FrameTxReceiptJson> {
    let sim = rpc::simulate(provider, tx, "latest").await?;
    if !sim.valid || sim.execution_status.as_deref() != Some("success") {
        bail!(
            "{label}: simulation refused: {}",
            sim.violation
                .or(sim.execution_error)
                .unwrap_or_else(|| "no reason given".to_owned())
        );
    }
    let hash = rpc::send(provider, tx).await?;
    println!("{label}: sent {hash}");
    let receipt = rpc::wait_for_receipt(
        provider,
        hash,
        Duration::from_mins(2),
        Duration::from_secs(2),
    )
    .await?;
    ensure!(receipt.status == U256::from(1), "{label}: reverted");
    let frames: Vec<String> = receipt
        .frame_receipts
        .iter()
        .map(|f| format!("{}+{}", f.gas_used, f.state_gas_used))
        .collect();
    println!(
        "{label}: block {}, gasUsed {}, payer {}, frames (execution+state) {}",
        receipt.block_number,
        receipt.gas_used,
        receipt.payer,
        frames.join(" ")
    );
    Ok(receipt)
}
