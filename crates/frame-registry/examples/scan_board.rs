//! `exp-frames` experiment 33's board, scanned from Rust on the ethrex Hegota testnet.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-registry --example scan_board [run]
//! ```
//!
//! The experiment derives Alice's and Bob's announcement keys from `PRIVATE_KEY` and a run label
//! (default `1`). With Bob's key, this finds Alice's offers among every message on the board;
//! with Alice's, Bob's answers. For each offer that was answered, it computes the two notes the
//! swap had to create from the decrypted terms alone, and checks that the registry inserted both
//! and that both nullifiers were used. Nothing secret is printed.

use std::env;

use alloy::{
    primitives::{Address, B256, U256, address, hex},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol_types::SolEvent,
};
use anyhow::{Context, ensure};
use kohaku_frame_kit::{
    constants::NONCE_MANAGER,
    rpc::{self, keyed_nonce_slot},
};
use kohaku_frame_registry::{
    announce::{Accept, Keys, Offer, board_messages, offer_id, scan},
    note::leaf,
    update::{abi::Inserted, word_field},
};

const BOARD: Address = address!("0x93DD748B72dA1b1B6F1d5ec78Cb91ee52F01727d");
const REGISTRY: Address = address!("0x755e6d982048bf6F97C0f9C1e2174233Add3c02c");
/// The fee each side of the experiment's swaps pays the registry.
const FEE: u64 = 10_000_000_000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let base = hex::decode(env::var("PRIVATE_KEY").context("PRIVATE_KEY derives the keys")?)?;
    let run = env::args().nth(1).unwrap_or_else(|| "1".to_owned());
    let alice = Keys::derive(&base, &format!("{run}/alice"))?;
    let bob = Keys::derive(&base, &format!("{run}/bob"))?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);

    let messages = board_messages(&provider, BOARD).await?;
    let offers: Vec<_> = scan(bob.secret, &messages)
        .into_iter()
        .filter_map(|(m, p)| Offer::decode(&p).map(|o| (m, o)))
        .collect();
    let answers: Vec<_> = scan(alice.secret, &messages)
        .into_iter()
        .filter_map(|(m, p)| Accept::decode(&p).map(|a| (m, a)))
        .collect();
    println!(
        "{} messages on the board; Bob's key opens {} offers, Alice's {} answers",
        messages.len(),
        offers.len(),
        answers.len()
    );

    let inserted: Vec<B256> = provider
        .get_logs(
            &Filter::new()
                .address(REGISTRY)
                .event_signature(Inserted::SIGNATURE_HASH)
                .from_block(0),
        )
        .await?
        .iter()
        .filter_map(|l| Inserted::decode_log_data(l.data()).ok().map(|e| e.leaf))
        .collect();
    let used = async |key: U256| -> anyhow::Result<bool> {
        let v = provider
            .get_storage_at(NONCE_MANAGER, keyed_nonce_slot(REGISTRY, key).into())
            .await?;
        Ok(!v.is_zero())
    };

    for (posted, offer) in &offers {
        let id = offer_id(&posted.message);
        println!(
            "offer {id} in {} (block {}): gives {} wei of {}, wants {} wei of {}, deadline {}",
            posted.tx,
            posted.block,
            offer.give.value,
            offer.give.app,
            offer.want.value,
            offer.want.app,
            offer.deadline
        );
        let Some((answer_posted, answer)) = answers.iter().find(|(_, a)| a.offer == id) else {
            println!("  no answer");
            continue;
        };
        println!(
            "  answered in {} (block {})",
            answer_posted.tx, answer_posted.block
        );
        // What the swap had to create, from the terms alone: Bob's note, of the asset Alice
        // wants, for Alice's receive inner; and Alice's, of the asset she gives, for Bob's.
        let to_alice = leaf(
            offer.want.app,
            word_field(offer.receive_inner.into()),
            offer.want.value - FEE,
        );
        let to_bob = leaf(
            offer.give.app,
            word_field(answer.receive_inner.into()),
            offer.give.value - FEE,
        );
        let settled =
            inserted.contains(&B256::from(to_alice)) && inserted.contains(&B256::from(to_bob));
        let spent = (used(offer.nullifier).await?, used(answer.nullifier).await?);
        println!(
            "  the swap's two notes inserted: {settled}; nullifiers used: offerer {}, acceptor {}",
            spent.0, spent.1
        );
        if settled {
            ensure!(
                spent == (true, true),
                "a settled swap left a nullifier unused"
            );
        }
    }
    Ok(())
}
