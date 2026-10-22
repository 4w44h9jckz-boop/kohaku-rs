//! `exp-frames` experiment 30's withdrawal, the end-to-end run X1's, with its witness shared for
//! a proving committee instead of proved: deposit a fresh note into the `RefundPool`, build the
//! withdrawal's circuit inputs, extend the witness, and write the three members' shares in the
//! committee's fixed format.
//!
//! ```text
//! PRIVATE_KEY=0x... OUT_DIR=shares cargo run --release -p kohaku-witness-share --example share_withdrawal
//! ```
//!
//! `OUT_DIR` receives `share-0.bin` to `share-2.bin` and `public.json`, which member `i` reads
//! (`share-i.bin` alone), and `withdrawal.json`, what [`assemble_withdrawal`] needs to turn the
//! committee's proof into the transaction. None of them holds the note: the note is printed to
//! standard error before the deposit, as `refund_withdrawal` prints it, so a deposit can be
//! recovered, and nothing else.
//!
//! The wallet does not prove, so it prices the withdrawal as [`Pricing::Uniform`] does: the
//! pool's default limits and the worst-case fee at them ([`chain::uniform_fee`]), the limits and
//! fee a wallet that proves for itself also uses by default. The refund pool returns what the gas
//! did not use. [`Pricing::Tightened`] needs a draft proof, so it is refused here.
//!
//! [`assemble_withdrawal`]: ../assemble_withdrawal/index.html

use std::{env, path::PathBuf};

use alloy::{
    primitives::{Address, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use kohaku_frame_kit::{FrameSigner, rpc};
use kohaku_frame_pool::{
    chain::{self, WALLET_FEES},
    withdrawal::{FramePool, PoolMode, Pricing, WithdrawalOpts},
};
use kohaku_tornadocash::{Note, Payer};
use kohaku_witness_share::{Encoding, extend_witness, share, write};
use rand::RngExt;
use serde_json::json;

/// The `RefundPool` `exp-frames` experiment 30 deployed on the testnet.
const REFUND_POOL: Address = address!("0xe19605853A749322655470199Fd31D3F3e53Baf9");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let out = PathBuf::from(env::var("OUT_DIR").unwrap_or_else(|_| "shares".to_owned()));
    let signer: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY pays the deposit")?
        .parse()?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let chain_id = provider.get_chain_id().await?;
    let salt = keccak256("exp-frames/30/refund-pool");
    let pool = FramePool {
        address: REFUND_POOL,
        mode: PoolMode::Refund,
        salt,
    };

    // 1. Deposit, as refund_withdrawal does.
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

    // 2. The withdrawal's inputs, at the worst-case fee for the default limits.
    let leaves = chain::leaves(&provider, pool.address, deposited.leaf_index).await?;
    let recipient = PrivateKeySigner::random().address();
    let opts = WithdrawalOpts {
        root_slot: Some(deposited.slot),
        fees: WALLET_FEES,
        ..WithdrawalOpts::new(chain_id)
    };
    ensure!(
        opts.pricing == Pricing::Uniform,
        "a withdrawal proved by a committee has no draft to tighten from"
    );
    let fee = chain::uniform_fee(&pool, recipient, &opts)?;
    let payer = Payer {
        address: pool.address,
        fee,
        refund: U256::ZERO,
    };
    let (leaf_index, public, inputs) =
        kohaku_frame_pool::circuit_inputs(note, &leaves, recipient, payer)?;
    ensure!(
        public.root == deposited.root,
        "the tree rebuilt from events does not match the published root"
    );

    // 3. The witness, extended by the wallet, then shared: the wallet's last step.
    let witness = extend_witness(&inputs)?;
    let shares = share(&witness, Encoding::Replicated, &mut rand08::rngs::OsRng)?;
    write(&out, &shares)?;
    let withdrawal = json!({
        "chainId": chain_id,
        "pool": pool.address,
        "salt": salt,
        "rootSlot": deposited.slot,
        "leafIndex": leaf_index,
        "deposit": deposited.receipt.transaction_hash,
        "publicInputs": public,
        "fees": "chain::WALLET_FEES",
        "pricing": "uniform",
    });
    std::fs::write(
        out.join("withdrawal.json"),
        serde_json::to_vec_pretty(&withdrawal)?,
    )?;
    let sizes: Vec<String> = shares.members.iter().map(|m| m.len().to_string()).collect();
    println!(
        "shares: {} values, members' shares {} bytes; fee {fee} wei; written to {}",
        witness.len(),
        sizes.join(" / "),
        out.display()
    );
    Ok(())
}
