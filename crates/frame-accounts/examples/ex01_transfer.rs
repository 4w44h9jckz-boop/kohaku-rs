//! Experiment 01, EIP-8141 Example 1a: an account with no code sends ETH, validated by the
//! protocol's default code. Once to a new account, which costs 183,600 state gas, then again to
//! the same, now existing, account.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-accounts --example ex01_transfer
//! ```

mod common;

use alloy::primitives::utils::parse_ether;
use kohaku_frame_accounts::{Eoa, FrameAccount, TxPlan, calls};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = common::provider()?;
    let funder = common::funder()?;
    let account = Eoa::new((&funder).into());
    let to = common::fresh_address();
    println!("from {} to {to}", account.address());

    for (exists, label) in [
        (false, "1a: to a new account"),
        (true, "1a: to the same account again"),
    ] {
        let envelope = common::envelope(&provider, account.address()).await?;
        let tx = TxPlan::new(&account)
            .call(calls::eth_transfer(to, parse_ether("0.001")?, exists))
            .build(&envelope)?;
        common::run(&provider, tx, std::slice::from_ref(&funder), label, true).await?;
    }
    Ok(())
}
