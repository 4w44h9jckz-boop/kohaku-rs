//! Deposit into `exp-frames` experiment 30's `RefundPool` on the ethrex Hegota testnet, then
//! withdraw with the pool as `tx.sender` and a last frame that refunds the note's fee less the
//! gas: no relayer, no EOA and no signature on the withdrawal, and the note pays about its gas.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-pool --example refund_withdrawal
//! ```
//!
//! `PRIVATE_KEY` pays the deposit (0.001 ETH plus gas); `RPC_URL` defaults to the testnet. The
//! withdrawal is priced as experiment 30 priced it ([`chain::priced_withdrawal`], fees
//! [`chain::WALLET_FEES`]). The note is printed to standard error before the deposit is sent, so
//! a deposit whose withdrawal fails can still be recovered.
//!
//! With `SEND_RPC_URL` set, the withdrawal is handed to that node alone with
//! `eth_sendRawTransaction`, for example a mempool node that is not the chain's, and the receipt
//! is awaited from `RPC_URL`. The deposit, the simulation and the reads still go to `RPC_URL`.

use std::{env, time::Duration};

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::SolEvent,
};
use anyhow::{Context, ensure};
use kohaku_frame_kit::{FrameSigner, FrameTx, gas::max_cost, json::FrameTxReceiptJson, rpc};
use kohaku_frame_pool::{
    chain::{self, WALLET_FEES},
    withdrawal::{DENOMINATION, FramePool, PoolMode, WithdrawalOpts, abi::FeeRefund},
};
use kohaku_tornadocash::Note;
use rand::RngExt;

/// The `RefundPool` `exp-frames` experiment 30 deployed on the testnet.
const REFUND_POOL: Address = address!("0xe19605853A749322655470199Fd31D3F3e53Baf9");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let signer: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY pays the deposit")?
        .parse()?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let chain_id = provider.get_chain_id().await?;
    let pool = FramePool {
        address: REFUND_POOL,
        mode: PoolMode::Refund,
        salt: keccak256("exp-frames/30/refund-pool"),
    };

    // 1. Deposit. The pool publishes the new root to EIP-8272 in the same frame, so the root the
    //    withdrawal proves against is recent.
    let note: Note = rand::rng().random();
    eprintln!("note 0x{}", hex::encode(note.preimage()));
    let deposited =
        chain::deposit(&provider, &pool, &FrameSigner::Secp256k1(signer), &note).await?;
    println!(
        "deposit: {} in block {}; leaf {}, root {} published in slot {}",
        deposited.receipt.transaction_hash,
        deposited.receipt.block_number,
        deposited.leaf_index,
        deposited.root,
        deposited.slot
    );

    // 2. Prove and price from the tree as it stood after this deposit.
    let leaves = chain::leaves(&provider, pool.address, deposited.leaf_index).await?;
    let recipient = PrivateKeySigner::random().address();
    let opts = WithdrawalOpts {
        root_slot: Some(deposited.slot),
        fees: WALLET_FEES,
        ..WithdrawalOpts::new(chain_id)
    };
    let (tx, proof) = chain::priced_withdrawal(
        &provider,
        &pool,
        &note,
        &leaves,
        recipient,
        &opts,
        &mut rand::rng(),
    )
    .await?;
    ensure!(
        proof.inputs.root == deposited.root,
        "the tree rebuilt from events does not match the published root"
    );
    let limits: Vec<String> = tx
        .frames
        .iter()
        .map(|f| f.limits.execution.to_string())
        .collect();
    println!(
        "withdrawal: limits {}; fee in the note {} wei; max cost {} wei",
        limits.join(" / "),
        proof.inputs.fee,
        max_cost(&tx, 0)?
    );

    // 3. Withdraw, with the pool as sender and payer.
    let before = provider.get_balance(pool.address).await?;
    let (hash, receipt) = send(&provider, &tx).await?;
    ensure!(receipt.status == U256::from(1), "the withdrawal reverted");
    ensure!(receipt.payer == pool.address, "the pool did not pay");
    let frames: Vec<String> = receipt
        .frame_receipts
        .iter()
        .map(|f| format!("{}:{}+{}", f.status, f.gas_used, f.state_gas_used))
        .collect();
    println!(
        "withdrawal: {} in block {}, gasUsed {}, effective price {} wei, frames (status:execution+state) {}",
        hash,
        receipt.block_number,
        receipt.gas_used,
        receipt.effective_gas_price,
        frames.join(" / ")
    );

    // 4. What the note paid: the fee less the refund, against the gas the chain charged.
    let (refunded, bound) = receipt
        .frame_receipts
        .iter()
        .flat_map(|f| &f.logs)
        .find(|l| l.address == pool.address && l.topics.first() == Some(&FeeRefund::SIGNATURE_HASH))
        .map(|l| {
            (
                U256::from_be_slice(&l.data[..32]),
                U256::from_be_slice(&l.data[32..64]),
            )
        })
        .context("no FeeRefund event")?;
    let charged = receipt.gas_used * receipt.effective_gas_price;
    let after = provider.get_balance(pool.address).await?;
    let kept = after + U256::from(DENOMINATION) - before;
    ensure!(
        kept == proof.inputs.fee - charged - refunded,
        "the pool kept {kept} wei, expected fee less gas less refund"
    );
    let received = provider.get_balance(recipient).await?;
    ensure!(received == U256::from(DENOMINATION) - proof.inputs.fee + refunded);
    println!(
        "fee {} wei; charged {charged}; refunded {refunded}; the pool's bound on the charge {bound} ({} gas over); kept by the pool {kept}; recipient {recipient} received {received}",
        proof.inputs.fee,
        (bound - charged) / receipt.effective_gas_price,
    );
    Ok(())
}

/// Simulate, then send: to `SEND_RPC_URL` alone when it is set, else to `RPC_URL`. Either way the
/// receipt is awaited from `RPC_URL` until a block is built on it.
async fn send<P: Provider>(
    provider: &P,
    tx: &FrameTx,
) -> anyhow::Result<(B256, FrameTxReceiptJson)> {
    if let Ok(send_url) = env::var("SEND_RPC_URL") {
        let sim = rpc::simulate(provider, tx, "latest").await?;
        ensure!(
            sim.valid && sim.execution_status.as_deref() == Some("success"),
            "the withdrawal would not succeed: {:?}",
            sim.violation.or(sim.execution_error)
        );
        let first = ProviderBuilder::new().connect_http(send_url.parse()?);
        let hash = rpc::send(&first, tx).await?;
        println!("withdrawal: {hash} handed to {send_url} only");
        let receipt = rpc::wait_for_confirmed_receipt(
            provider,
            hash,
            Duration::from_mins(5),
            Duration::from_secs(2),
        )
        .await?;
        Ok((hash, receipt))
    } else {
        let executed = rpc::execute(provider, tx, true).await?;
        Ok((executed.hash, executed.receipt))
    }
}
