//! Runner step "intent", on the holder's device: the holder of a note queues an intent for the
//! note's new owner, sealed to the vault's committee. The owner never sends its own.
//!
//! ```text
//! PRIVATE_KEY=... VAULT=0x... RECEIVE_FILE=receive.json SEND_RPC_URL=... RPC_URL=... \
//!   cargo run --release -p kohaku-frame-exit --example exit_intent
//! ```
//!
//! `RECEIVE_FILE` is what the owner's `exit_receive` wrote. The intent takes the vault's `tail()`
//! as its index, is sealed under it, and is an ordinary frame transaction from the holder's
//! account, handed to the node at `SEND_RPC_URL` alone and awaited on `RPC_URL`. If another
//! intent took the index first, the vault emits a different index and the step fails: send it
//! again. The holder's key comes from the environment only, and is never printed.

mod common;

use std::{env, fs, time::Duration};

use alloy::{
    primitives::U256, signers::local::PrivateKeySigner, sol_types::SolCall, sol_types::SolEvent,
};
use anyhow::{Context as _, ensure};
use common::{chain, digest, fail, node, print, required, unhex, vault};
use kohaku_frame_exit::{
    OpeningKey,
    intent::seal_intent,
    note::Receive,
    vault::{abi, committee_key, tail},
};
use kohaku_frame_kit::{
    Frame, FrameSigner, FrameTx,
    constants::{STORAGE_SET_STATE_GAS, approve},
    rpc, sign_all,
};
use kohaku_frame_pool::chain::WALLET_FEES;
use serde_json::{Value, json};

/// `enqueue`'s execution, as the committee's runner sends it.
const ENQUEUE_EXECUTION: u64 = 200_000;
/// The intent's hash, the tail, and the queue's start when it was empty.
const ENQUEUE_STATE: u64 = 3 * STORAGE_SET_STATE_GAS;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let vault = vault()?;
    let holder: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY, the holder's key, from the environment")?
        .trim()
        .parse()?;
    let receive: Value = serde_json::from_str(&fs::read_to_string(required("receive-file")?)?)?;
    let address = Receive {
        key: unhex(receive["openingKey"].as_str().context("openingKey")?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("openingKey is not 33 bytes"))?,
        secret_point: unhex(receive["secretPoint"].as_str().context("secretPoint")?)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("secretPoint is not 32 bytes"))?,
    };
    ensure!(
        receive["vault"].as_str().and_then(|v| v.parse().ok()) == Some(vault),
        "the receiving address is for another vault"
    );

    let chain = chain()?;
    let node = node()?;
    let chain_id = alloy::providers::Provider::get_chain_id(&chain).await?;
    let committee = committee_key(&chain, vault).await?;
    let index = tail(&chain, vault).await?;
    let sealed = seal_intent(
        &committee,
        vault,
        index,
        &address,
        &OpeningKey::random(&mut rand::rng()),
    )?;

    let signer = FrameSigner::Secp256k1(holder);
    let from = signer.address();
    let mut tx = FrameTx {
        chain_id,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: rpc::nonce_seq(&chain, from, &[U256::ZERO]).await?,
        sender: from,
        frames: vec![
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None).with_execution(20_000),
            Frame::sender(Some(vault))
                .with_data(
                    abi::enqueueCall {
                        sealed: sealed.to_vec().into(),
                    }
                    .abi_encode(),
                )
                .with_execution(ENQUEUE_EXECUTION)
                .with_state(ENQUEUE_STATE),
        ],
        signatures: vec![signer.placeholder(None)],
        fees: WALLET_FEES,
        blob_versioned_hashes: vec![],
    };
    sign_all(&mut tx, std::slice::from_ref(&signer))?;
    let mut line = json!({
        "step": "intent",
        "vault": vault,
        "holder": from,
        "index": index,
        "intentHash": digest(&sealed),
        "bytes": sealed.len(),
        "hash": tx.hash(),
    });
    if let Err(e) = rpc::send(&node, &tx).await {
        line["outcome"] = json!("Refused");
        line["node"] = json!(e.to_string());
        fail(&line, 1);
    }
    let r = rpc::wait_for_confirmed_receipt(
        &chain,
        tx.hash(),
        Duration::from_mins(5),
        Duration::from_secs(2),
    )
    .await?;
    line["block"] = json!(r.block_number);
    line["status"] = json!(r.status);
    let emitted = r
        .logs
        .iter()
        .filter(|l| l.address == vault && l.topics.first() == Some(&abi::Intent::SIGNATURE_HASH))
        .find_map(|l| abi::Intent::decode_raw_log(l.topics.iter().copied(), &l.data).ok())
        .map(|e| e.index.to::<u64>());
    line["emittedIndex"] = json!(emitted);
    if emitted != Some(index) {
        line["outcome"] = json!(if emitted.is_some() {
            "Raced"
        } else {
            "NotQueued"
        });
        fail(&line, 1);
    }
    line["outcome"] = json!("Queued");
    print(&line);
    Ok(())
}
