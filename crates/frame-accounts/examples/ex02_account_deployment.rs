//! Experiment 02, EIP-8141 Example 1b: a counterfactual `SimpleAccount` deploys itself at
//! `tx.sender` in a `DEFAULT` frame ahead of its own `VERIFY`, and sends ETH in the same
//! transaction. Then a second transaction from the deployed account, without the deploy frame.
//!
//! The account is the funder's own, under this crate's salt, so the first run deploys it and
//! later runs only send from it.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-accounts --example ex02_account_deployment
//! ```

mod common;

use alloy::{
    primitives::{U256, utils::parse_ether},
    providers::Provider,
};
use kohaku_frame_accounts::{Eoa, FrameAccount, SimpleAccount, TxPlan, calls, contracts::salt_of};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = common::provider()?;
    let owner = common::funder()?;
    let mut account = SimpleAccount::new(
        owner.address(),
        salt_of("kohaku-rs/frame-accounts/simple-account/v1"),
    );
    let address = account.address();
    account.deployed = common::has_code(&provider, address).await?;
    println!("account {address}, deployed: {}", account.deployed);

    if !account.deployed {
        // The account pays its own gas, so fund the counterfactual address first.
        let balance = provider.get_balance(address).await?;
        if balance < parse_ether("0.01")? {
            let funder = Eoa::new((&owner).into());
            let envelope = common::envelope(&provider, funder.address()).await?;
            let tx = TxPlan::new(&funder)
                .call(calls::eth_transfer(
                    address,
                    parse_ether("0.02")?,
                    balance > U256::ZERO,
                ))
                .build(&envelope)?;
            common::run(
                &provider,
                tx,
                std::slice::from_ref(&owner),
                "prefund the account",
                true,
            )
            .await?;
        }
        let envelope = common::envelope(&provider, address).await?;
        let tx = TxPlan::new(&account)
            .call(calls::eth_transfer(
                common::fresh_address(),
                parse_ether("0.001")?,
                false,
            ))
            .build(&envelope)?;
        common::run(
            &provider,
            tx,
            std::slice::from_ref(&owner),
            "1b: deploy at tx.sender, then send from it",
            true,
        )
        .await?;
        account.deployed = true;
    }

    let envelope = common::envelope(&provider, address).await?;
    let tx = TxPlan::new(&account)
        .call(calls::eth_transfer(
            common::fresh_address(),
            parse_ether("0.001")?,
            false,
        ))
        .build(&envelope)?;
    common::run(
        &provider,
        tx,
        std::slice::from_ref(&owner),
        "the deployed account validates on its own",
        true,
    )
    .await?;
    Ok(())
}
