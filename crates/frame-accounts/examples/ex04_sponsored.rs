//! Experiment 04, EIP-8141 Example 3: a user with no ETH at all.
//!
//! 1. The user mints 1,000 tUSD; the funder pays the gas as an `EoaSponsor`, signing the same
//!    transaction. `APPROVE(PAYMENT)` creates the user's account.
//! 2. The user sends 5 tUSD to a friend and pays the gas in tUSD to `TokenSponsor`, which quotes
//!    `max_cost * rate` and refunds what the transaction did not use in a post-op frame.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-accounts --example ex04_sponsored
//! ```

mod common;

use alloy::{
    primitives::{Address, U256, utils::parse_ether},
    providers::Provider,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use anyhow::ensure;
use kohaku_frame_accounts::{Eoa, EoaSponsor, TokenSponsor, TxPlan, calls, contracts::salt_of};
use kohaku_frame_kit::{
    Frame, FrameSigner,
    constants::{NEW_ACCOUNT_STATE_GAS, STORAGE_SET_STATE_GAS},
};

sol! {
    function mint(address to, uint256 amount);
    function balanceOf(address who) view returns (uint256);
}

/// Token base units per wei: 2,000 tUSD per ETH.
const RATE: u64 = 2000;

async fn tusd(
    provider: &alloy::providers::DynProvider,
    token: Address,
    who: Address,
) -> anyhow::Result<U256> {
    let out = common::read(provider, token, balanceOfCall { who }.abi_encode()).await?;
    Ok(U256::from_be_slice(&out))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = common::provider()?;
    let owner = common::funder()?;
    let token = common::contract("tUSD")?.address;
    let sponsor_address = TokenSponsor::address_of(
        token,
        U256::from(RATE),
        owner.address(),
        salt_of("exp-frames/04/token-sponsor/v1"),
    );
    ensure!(
        common::has_code(&provider, sponsor_address).await?,
        "TokenSponsor {sponsor_address} is not deployed: run exp-frames experiment 04's setup"
    );

    let user = FrameSigner::Secp256k1(PrivateKeySigner::random());
    let friend = common::fresh_address();
    println!("user {} (fresh, no ETH), friend {friend}", user.address());

    // 1. The funder pays for the user's first transaction.
    let account = Eoa::new((&user).into()).with_verify_execution(10_000);
    let mut payer = EoaSponsor::new((&owner).into()).with_state(NEW_ACCOUNT_STATE_GAS);
    let mint = Frame::sender(Some(token))
        .with_data(
            mintCall {
                to: user.address(),
                amount: parse_ether("1000")?,
            }
            .abi_encode(),
        )
        .with_execution(60_000)
        .with_state(2 * STORAGE_SET_STATE_GAS);
    let envelope = common::envelope(&provider, user.address()).await?;
    let tx = TxPlan::new(&account)
        .sponsored_by(&mut payer)
        .call(mint)
        .build(&envelope)?;
    common::run(
        &provider,
        tx,
        &[user.clone(), owner.clone()],
        "1. EOA-sponsored: the user mints 1000 tUSD, the funder pays",
        true,
    )
    .await?;

    // 2. Example 3: gas in tUSD.
    let before = tusd(&provider, token, sponsor_address).await?;
    let mut sponsor = TokenSponsor::new(sponsor_address, token, U256::from(RATE));
    let envelope = common::envelope(&provider, user.address()).await?;
    let tx = TxPlan::new(&account)
        .sponsored_by(&mut sponsor)
        .call(calls::erc20_transfer(token, friend, parse_ether("5")?))
        .build(&envelope)?;
    println!(
        "\nquote: fee {} tUSD base units = {RATE} x max_cost",
        sponsor.fee
    );
    let done = common::run(
        &provider,
        tx,
        std::slice::from_ref(&user),
        "2. Example 3: pay gas in tUSD, send 5 tUSD, refund in the post-op",
        true,
    )
    .await?;

    let kept = tusd(&provider, token, sponsor_address).await? - before;
    let paid_wei = done.receipt.gas_used * done.receipt.effective_gas_price;
    println!(
        "sponsor paid {paid_wei} wei, kept {kept} tUSD base units ({} wei at the rate), refunded {}",
        kept / U256::from(RATE),
        sponsor.fee - kept
    );
    println!(
        "user: {} wei of ETH, {} tUSD base units; friend {}",
        provider.get_balance(user.address()).await?,
        tusd(&provider, token, user.address()).await?,
        tusd(&provider, token, friend).await?
    );
    Ok(())
}
