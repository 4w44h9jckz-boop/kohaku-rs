//! What the four runner steps share: their inputs from the environment, and the one JSON line
//! each prints. Nothing secret is read from a flag or written to the output.

#![allow(dead_code)]

use std::{env, fs};

use alloy::{
    primitives::{Address, B256, keccak256},
    providers::{Provider, ProviderBuilder},
};
use anyhow::Context as _;
use kohaku_frame_kit::rpc;
use kohaku_frame_secrets::Seed;
use serde_json::Value;

pub fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

pub fn unhex(s: &str) -> anyhow::Result<Vec<u8>> {
    Ok(::hex::decode(s.trim().trim_start_matches("0x"))?)
}

/// `keccak256(b)`, for a record that names a value without holding it.
pub fn digest(b: &[u8]) -> B256 {
    keccak256(b)
}

/// `--name value` from the command line, else the environment variable `NAME`.
pub fn arg(name: &str) -> Option<String> {
    let flag = format!("--{name}");
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        if a == flag {
            return args.next();
        }
        if let Some(v) = a.strip_prefix(&format!("{flag}=")) {
            return Some(v.to_owned());
        }
    }
    env::var(name.to_uppercase().replace('-', "_"))
        .ok()
        .filter(|v| !v.is_empty())
}

pub fn required(name: &str) -> anyhow::Result<String> {
    arg(name).with_context(|| format!("--{name} or {}", name.to_uppercase().replace('-', "_")))
}

pub fn number<T: std::str::FromStr>(name: &str, default: T) -> anyhow::Result<T>
where
    T::Err: std::error::Error + Send + Sync + 'static,
{
    arg(name).map_or(Ok(default), |v| v.parse().with_context(|| name.to_owned()))
}

pub fn vault() -> anyhow::Result<Address> {
    Ok(required("vault")?.parse()?)
}

/// The mnemonic in `SEED_FILE`. Never printed.
pub fn load_seed() -> anyhow::Result<Seed> {
    let path = required("seed-file")?;
    Ok(Seed::from_mnemonic(fs::read_to_string(path)?.trim())?)
}

/// The chain to read from: `RPC_URL`, or the Hegota testnet.
pub fn chain() -> anyhow::Result<impl Provider> {
    let url = arg("rpc-url").unwrap_or_else(|| rpc::HEGOTA_RPC_URL.to_owned());
    Ok(ProviderBuilder::new().connect_http(url.parse()?))
}

/// The node a transaction is handed to: `SEND_RPC_URL`, or the chain's own.
pub fn node() -> anyhow::Result<impl Provider> {
    let url = arg("send-rpc-url")
        .or_else(|| arg("rpc-url"))
        .unwrap_or_else(|| rpc::HEGOTA_RPC_URL.to_owned());
    Ok(ProviderBuilder::new().connect_http(url.parse()?))
}

/// The step's one line.
pub fn print(v: &Value) {
    println!("{v}");
}

/// The step's one line, then a failing exit.
pub fn fail(v: &Value, code: i32) -> ! {
    println!("{v}");
    std::process::exit(code)
}
