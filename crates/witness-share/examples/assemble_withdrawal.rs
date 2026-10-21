//! The committee's proof, put into the withdrawal `share_withdrawal` shared: read
//! `withdrawal.json` and the proof the members wrote, build the transaction exactly as the
//! wallet would have built it around its own proof at [`Pricing::Uniform`]
//! ([`kohaku_frame_pool::chain::uniform_withdrawal`]'s limits), simulate it, and send it if `SEND` is set.
//!
//! ```text
//! cargo run --release -p kohaku-witness-share --example assemble_withdrawal -- shares/withdrawal.json members.json
//! ```
//!
//! `members.json` is what the committee's `co-withdraw local` writes: one record per member, each
//! with the proof as the pool's verifier takes it (`solidity`, eight 32-byte words). The three
//! must agree. No key is needed: the pool is the sender and the payer, and nothing is signed.

use std::{env, time::Duration};

use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::ProviderBuilder,
};
use anyhow::{Context, ensure};
use kohaku_frame_kit::rpc;
use kohaku_frame_pool::{
    PublicInputs,
    chain::WALLET_FEES,
    withdrawal::{FramePool, PoolMode, Pricing, WithdrawalOpts, withdrawal_tx},
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Withdrawal {
    chain_id: u64,
    pool: Address,
    salt: B256,
    root_slot: u64,
    public_inputs: PublicInputs,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Member {
    #[serde(rename = "member")]
    id: usize,
    solidity: String,
    public_inputs: Vec<String>,
    verified: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = env::args().skip(1);
    let (w, m) = (args.next(), args.next());
    let (Some(w), Some(m)) = (w, m) else {
        anyhow::bail!("usage: assemble_withdrawal <withdrawal.json> <members.json>");
    };
    let w: Withdrawal = serde_json::from_slice(&std::fs::read(&w)?)?;
    let members: Vec<Member> = serde_json::from_slice(&std::fs::read(&m)?)?;
    ensure!(
        members.len() == 3,
        "{} member records, expected 3",
        members.len()
    );
    ensure!(
        members
            .iter()
            .all(|r| r.verified && r.solidity == members[0].solidity),
        "the members' proofs differ, or one did not verify"
    );
    let i = &w.public_inputs;
    let expected = [
        U256::from_be_bytes(i.root.0),
        U256::from_be_bytes(i.nullifier_hash.0),
        U256::from_be_slice(i.recipient.as_slice()),
        U256::from_be_slice(i.relayer.as_slice()),
        i.fee,
        i.refund,
    ]
    .map(|x| x.to_string());
    for r in &members {
        ensure!(
            r.public_inputs == expected,
            "member {} proved other public inputs",
            r.id
        );
    }
    let proof: Bytes = members[0].solidity.parse().context("the proof's words")?;

    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let pool = FramePool {
        address: w.pool,
        mode: PoolMode::Refund,
        salt: w.salt,
    };
    let opts = WithdrawalOpts {
        root_slot: Some(w.root_slot),
        fees: WALLET_FEES,
        pricing: Pricing::Uniform,
        ..WithdrawalOpts::new(w.chain_id)
    };
    let tx = withdrawal_tx(&pool, &w.public_inputs, &proof, &opts)?;
    let sim = rpc::simulate(&provider, &tx, "latest").await?;
    let used: Vec<String> = sim
        .frames
        .iter()
        .flatten()
        .map(|f| f.gas_used.to_string())
        .collect();
    println!(
        "simulation: valid {}, execution {:?}, violation {:?}, frames {}",
        sim.valid,
        sim.execution_status,
        sim.violation,
        used.join(" / ")
    );
    ensure!(
        sim.valid && sim.execution_status.as_deref() == Some("success"),
        "the withdrawal would not succeed"
    );
    if env::var("SEND").is_ok() {
        let hash = rpc::send(&provider, &tx).await?;
        let receipt = rpc::wait_for_confirmed_receipt(
            &provider,
            hash,
            Duration::from_mins(5),
            Duration::from_secs(2),
        )
        .await?;
        println!(
            "withdrawal: {hash} in block {}, status {}, gasUsed {}",
            receipt.block_number, receipt.status, receipt.gas_used
        );
    }
    Ok(())
}
