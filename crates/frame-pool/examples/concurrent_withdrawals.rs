//! Two withdrawals from one wallet, sent at once through a mempool node, on the ethrex Hegota
//! testnet: `exp-frames` experiment 34.
//!
//! ```text
//! PRIVATE_KEY=0x... SEND_RPC_URL=http://127.0.0.1:14337/rpc/ RECORD=record.json \
//!   cargo run --release -p kohaku-frame-pool --example concurrent_withdrawals
//! ```
//!
//! 1. Two notes are deposited into `exp-frames` experiment 06's keyed pool.
//! 2. [`chain::keyed_batch`] builds both withdrawals against the same root, each with its own
//!    nullifier hash as its nonce key and the pool as sender and payer.
//! 3. Both are handed to the node at `SEND_RPC_URL` (a skandha node with `--frames.handoff`),
//!    back to back, before either is mined.
//! 4. A second spend of the first note, to another recipient, is handed to the same node while
//!    the first is pending: it has the same nonce key, so it can only replace the first.
//! 5. The receipts are awaited from `RPC_URL`.
//!
//! `RECORD` names a JSON file for the transactions' bytes and the node's answers. `PRIVATE_KEY`
//! pays the deposits. No key or note is printed.

use std::{env, fs, time::Duration};

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use kohaku_frame_kit::{
    FrameSigner, FrameTx,
    rpc::{self, HEGOTA_RPC_URL},
};
use kohaku_frame_pool::{
    chain,
    withdrawal::{FramePool, PoolMode, WithdrawalOpts},
};
use kohaku_tornadocash::Note;
use rand::RngExt;
use serde_json::{Value, json};

/// The keyed pool `exp-frames` experiment 06 deployed on the testnet.
const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| HEGOTA_RPC_URL.to_owned());
    let send_url = env::var("SEND_RPC_URL").context("SEND_RPC_URL names the mempool node")?;
    let funder: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY pays the deposits")?
        .parse()?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let node = ProviderBuilder::new().connect_http(send_url.parse()?);
    let chain_id = provider.get_chain_id().await?;
    let pool = FramePool {
        address: KEYED_POOL,
        mode: PoolMode::Keyed,
        salt: keccak256("exp-frames/06/pool-keyed"),
    };

    // 1. Two deposits. The second's root covers both notes.
    let notes: [Note; 2] = [rand::rng().random(), rand::rng().random()];
    let last = deposit_both(&provider, &pool, &funder, &notes).await?;
    let leaves = chain::leaves(&provider, pool.address, last.leaf_index).await?;
    let opts = WithdrawalOpts {
        root_slot: Some(last.slot),
        ..WithdrawalOpts::new(chain_id)
    };

    // 2. The batch: two notes, two fresh recipients, one root.
    let recipients = [
        PrivateKeySigner::random().address(),
        PrivateKeySigner::random().address(),
    ];
    let spends = [
        (notes[0].clone(), recipients[0]),
        (notes[1].clone(), recipients[1]),
    ];
    let batch =
        chain::keyed_batch(&provider, &pool, &spends, &leaves, &opts, &mut rand::rng()).await?;
    let txs: Vec<FrameTx> = batch.into_iter().map(|(tx, _)| tx).collect();
    // The same note again, to a third recipient: the same nullifier, so the same nonce key.
    let (again, _) = chain::priced_withdrawal(
        &provider,
        &pool,
        &notes[0],
        &leaves,
        PrivateKeySigner::random().address(),
        &opts,
        &mut rand::rng(),
    )
    .await?;
    ensure!(again.nonce_keys == txs[0].nonce_keys);

    // 3 and 4. Hand them to the node, back to back.
    let answers = hand_over(
        &node,
        &[
            ("A", &txs[0]),
            ("B", &txs[1]),
            ("A again, the same note", &again),
        ],
    )
    .await;
    ensure!(answers[0].get("result").is_some() && answers[1].get("result").is_some());

    // 5. The receipts.
    let blocks = mined_blocks(&provider, &txs, pool.address).await?;
    println!("same block: {}", blocks[0] == blocks[1]);
    let landed = provider
        .get_transaction_receipt(again.hash())
        .await
        .ok()
        .flatten()
        .is_some();
    println!("the same note again was mined: {landed}");

    if let Ok(path) = env::var("RECORD") {
        let record = json!({
            "pool": pool.address,
            "chainId": chain_id,
            "root": B256::from(last.root),
            "slot": last.slot,
            "sentTo": send_url,
            "pair": txs.iter().zip(&answers).zip(&blocks).map(|((tx, a), b)| json!({
                "hash": tx.hash(), "raw": raw(tx), "answer": a, "block": b,
            })).collect::<Vec<Value>>(),
            "sameNote": {
                "hash": again.hash(), "raw": raw(&again), "answer": answers[2],
                "replaces": txs[0].hash(), "mined": landed,
            },
            "recipients": recipients,
        });
        fs::write(
            &path,
            format!("{}\n", serde_json::to_string_pretty(&record)?),
        )?;
        println!("recorded in {path}");
    }
    Ok(())
}

/// Wait for each to be mined, paid for by `payer`: the blocks they landed in.
async fn mined_blocks<P: Provider>(
    provider: &P,
    txs: &[FrameTx],
    payer: Address,
) -> anyhow::Result<Vec<U256>> {
    let mut blocks = vec![];
    for tx in txs {
        let r = rpc::wait_for_confirmed_receipt(
            provider,
            tx.hash(),
            Duration::from_mins(3),
            Duration::from_secs(2),
        )
        .await?;
        println!(
            "mined: {} block {} index {}, gasUsed {}, payer {}",
            tx.hash(),
            r.block_number,
            r.transaction_index,
            r.gas_used,
            r.payer
        );
        ensure!(r.payer == payer, "the pool did not pay");
        blocks.push(r.block_number);
    }
    Ok(blocks)
}

/// `eth_sendRawTransaction` to the node for each, in order, without waiting: its answers.
async fn hand_over<P: Provider>(node: &P, txs: &[(&str, &FrameTx)]) -> Vec<Value> {
    let mut answers = vec![];
    for (what, tx) in txs {
        let answer = match rpc::send(node, tx).await {
            Ok(hash) => json!({ "result": hash }),
            Err(e) => json!({ "error": e.to_string() }),
        };
        println!("{what}: {} -> {answer}", tx.hash());
        answers.push(answer);
    }
    answers
}

/// Deposit each note in its own transaction; the last deposit's root covers them all.
async fn deposit_both<P: Provider>(
    provider: &P,
    pool: &FramePool,
    funder: &PrivateKeySigner,
    notes: &[Note],
) -> anyhow::Result<chain::Deposited> {
    let mut last = None;
    for note in notes {
        let d = chain::deposit(
            provider,
            pool,
            &FrameSigner::Secp256k1(funder.clone()),
            note,
        )
        .await?;
        println!(
            "deposit: {} block {}, leaf {}",
            d.receipt.transaction_hash, d.receipt.block_number, d.leaf_index
        );
        last = Some(d);
    }
    last.context("no notes")
}

fn raw(tx: &FrameTx) -> String {
    format!("0x{}", hex::encode(tx.encode()))
}
