//! Serve one account as an EIP-1193 provider over HTTP JSON-RPC.
//!
//! ```text
//! WALLET_KEY=0x... cargo run --release -p kohaku-frame-wallet --bin frame-wallet
//! ```
//!
//! - `WALLET_KEY`: the account's secp256k1 key. Read from the environment and never printed.
//! - `RPC_URL`: the node, the ethrex Hegota testnet by default.
//! - `LISTEN`: the address to serve on, `127.0.0.1:0` (any free port) by default.
//! - `SESSION_ACCOUNT_SALT`: if set, the account is the `SessionAccount` the key owns at this
//!   CREATE2 salt, rather than the key's own address with no code.
//!
//! The first line on standard output is `listening on http://<address>`.

use std::{env, io::Write as _};

use alloy::{
    primitives::B256,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::Context;
use kohaku_frame_accounts::session::SessionAccount;
use kohaku_frame_kit::{FrameSigner, rpc::HEGOTA_RPC_URL};
use kohaku_frame_wallet::{
    server,
    wallet::{Wallet, WalletAccount},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let key: PrivateKeySigner = env::var("WALLET_KEY")
        .context("WALLET_KEY is the account's key")?
        .parse()?;
    let url = env::var("RPC_URL").unwrap_or_else(|_| HEGOTA_RPC_URL.to_owned());
    let listen = env::var("LISTEN").unwrap_or_else(|_| "127.0.0.1:0".to_owned());
    let owner = key.address();
    let key = FrameSigner::Secp256k1(key);
    let account = match env::var("SESSION_ACCOUNT_SALT") {
        Ok(salt) => WalletAccount::Session(SessionAccount::new(owner, salt.parse::<B256>()?)),
        Err(_) => Wallet::eoa(&key),
    };
    let provider = ProviderBuilder::new().connect_http(url.parse()?).erased();
    let wallet = Wallet::new(provider, key, account).await?;
    eprintln!(
        "frame-wallet: account {} on chain {}",
        wallet.address(),
        wallet.chain_id()
    );
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    println!("listening on http://{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    server::serve(wallet, listener).await?;
    Ok(())
}
