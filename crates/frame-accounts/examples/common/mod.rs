//! Shared by the examples: the funder's key, the node, the experiment contracts, and printing.
#![allow(dead_code)]

use std::env;

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{DynProvider, Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, anyhow};
use kohaku_frame_accounts::{Envelope, contracts::create2_address};
use kohaku_frame_kit::{
    Frame, FrameSigner, FrameTx,
    constants::CREATE2_DEPLOYER,
    rpc::{self, Executed, HEGOTA_RPC_URL},
    sign_all,
};
use serde::Deserialize;

/// The testnet's base fee is 7 wei: a 1 wei tip is enough.
pub const TIP: u128 = 1;

pub fn provider() -> anyhow::Result<DynProvider> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| HEGOTA_RPC_URL.to_owned());
    Ok(ProviderBuilder::new().connect_http(url.parse()?).erased())
}

/// `PRIVATE_KEY`: pays for everything the examples do, and seeds the keys they derive.
pub fn base_key() -> anyhow::Result<B256> {
    env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY funds the examples")?
        .parse()
        .context("PRIVATE_KEY is not a 32-byte hex key")
}

pub fn funder() -> anyhow::Result<FrameSigner> {
    Ok(FrameSigner::Secp256k1(PrivateKeySigner::from_bytes(
        &base_key()?,
    )?))
}

/// `keccak256(PRIVATE_KEY || label)`, as `exp-frames` derives its extra keys, so the examples
/// find the accounts the experiments created.
pub fn derive(label: &str) -> anyhow::Result<B256> {
    let mut buf = base_key()?.to_vec();
    buf.extend_from_slice(label.as_bytes());
    Ok(keccak256(buf))
}

pub fn fresh_address() -> Address {
    PrivateKeySigner::random().address()
}

pub async fn envelope(provider: &DynProvider, sender: Address) -> anyhow::Result<Envelope> {
    Ok(Envelope::fetch(provider, sender, vec![U256::ZERO], TIP).await?)
}

pub async fn has_code(provider: &DynProvider, address: Address) -> anyhow::Result<bool> {
    Ok(!provider.get_code_at(address).await?.is_empty())
}

/// `eth_call`, for reading the experiment contracts.
pub async fn read(provider: &DynProvider, to: Address, data: Vec<u8>) -> anyhow::Result<Bytes> {
    Ok(provider
        .call(TransactionRequest::default().to(to).input(data.into()))
        .await?)
}

/// Sign with `keys`, then simulate, send and wait, and print what happened.
pub async fn run(
    provider: &DynProvider,
    mut tx: FrameTx,
    keys: &[FrameSigner],
    label: &str,
    require_success: bool,
) -> anyhow::Result<Executed> {
    println!("\n=== {label} ===");
    sign_all(&mut tx, keys)?;
    let done = rpc::execute(provider, &tx, require_success).await?;
    print_receipt(&done);
    Ok(done)
}

pub fn print_receipt(done: &Executed) {
    let r = &done.receipt;
    println!(
        "{} block {} status {} gasUsed {} payer {}",
        done.hash, r.block_number, r.status, r.gas_used, r.payer
    );
    for (i, f) in r.frame_receipts.iter().enumerate() {
        let status = match f.status.to::<u8>() {
            0 => "FAILURE",
            1 => "SUCCESS",
            2 => "SKIPPED",
            _ => "?",
        };
        println!(
            "  frame {i}: {status} execution {} state {} logs {}",
            f.gas_used,
            f.state_gas_used,
            f.logs.len()
        );
    }
}

#[derive(Deserialize)]
struct ContractsJson {
    contracts: Vec<ContractJson>,
}

#[derive(Deserialize)]
struct ContractJson {
    name: String,
    deploy: Bytes,
    execution: u64,
    state: u64,
}

/// An experiment contract and the frame that deploys it.
pub struct Contract {
    pub address: Address,
    pub deploy: Frame,
}

/// Token A, Token B and `ToyDex` (experiment 03) and tUSD (experiment 04), as deployed.
pub fn contract(name: &str) -> anyhow::Result<Contract> {
    let json: ContractsJson = serde_json::from_str(include_str!("../contracts.json"))?;
    let c = json
        .contracts
        .into_iter()
        .find(|c| c.name == name)
        .ok_or_else(|| anyhow!("no contract {name}"))?;
    let salt = B256::from_slice(&c.deploy[..32]);
    Ok(Contract {
        address: create2_address(&c.deploy[32..], salt),
        deploy: Frame::sender(Some(CREATE2_DEPLOYER))
            .with_data(c.deploy)
            .with_execution(c.execution)
            .with_state(c.state),
    })
}
