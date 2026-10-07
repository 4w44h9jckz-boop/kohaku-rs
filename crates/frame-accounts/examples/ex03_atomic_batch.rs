//! Experiment 03, EIP-8141 Example 2: approve and swap in one transaction, with and without
//! `ATOMIC_BATCH_FLAG`.
//!
//! - A. the example as written: approve (batched with the swap), swap;
//! - B. a batch whose swap reverts: the approve is rolled back and the frame after the batch is
//!   `SKIPPED`;
//! - C. the same failure without the flag: the approve stays, a dangling allowance;
//!
//! then a last transaction clears the allowance so the example can run again.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-accounts --example ex03_atomic_batch
//! ```

mod common;

use alloy::{
    primitives::{Address, U256, utils::parse_ether},
    sol,
    sol_types::SolCall,
};
use kohaku_frame_accounts::{Eoa, FrameAccount, TxPlan, calls};
use kohaku_frame_kit::{Frame, FrameTx, constants::STORAGE_SET_STATE_GAS};

sol! {
    function swap(uint256 amountIn, uint256 minOut) returns (uint256);
    function mint(address to, uint256 amount);
    function balanceOf(address who) view returns (uint256);
    function allowance(address owner, address spender) view returns (uint256);
}

struct Setup {
    token_a: Address,
    token_b: Address,
    dex: Address,
}

async fn balances(
    provider: &alloy::providers::DynProvider,
    s: &Setup,
    trader: Address,
) -> anyhow::Result<(U256, U256, U256)> {
    let read = |to, data: Vec<u8>| common::read(provider, to, data);
    let a = read(s.token_a, balanceOfCall { who: trader }.abi_encode()).await?;
    let b = read(s.token_b, balanceOfCall { who: trader }.abi_encode()).await?;
    let allowance = read(
        s.token_a,
        allowanceCall {
            owner: trader,
            spender: s.dex,
        }
        .abi_encode(),
    )
    .await?;
    Ok((
        U256::from_be_slice(&a),
        U256::from_be_slice(&b),
        U256::from_be_slice(&allowance),
    ))
}

/// Deploy both tokens and the DEX, mint Token A to the trader and Token B into the DEX.
fn setup_frames(s: &Setup, trader: Address) -> anyhow::Result<Vec<Frame>> {
    let mint = |token, to| -> anyhow::Result<Frame> {
        Ok(Frame::sender(Some(token))
            .with_data(
                mintCall {
                    to,
                    amount: parse_ether("1000")?,
                }
                .abi_encode(),
            )
            .with_execution(100_000)
            .with_state(2 * STORAGE_SET_STATE_GAS))
    };
    Ok(vec![
        common::contract("Token A")?.deploy,
        common::contract("Token B")?.deploy,
        common::contract("ToyDex")?.deploy,
        mint(s.token_a, trader)?,
        mint(s.token_b, s.dex)?,
    ])
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = common::provider()?;
    let trader = common::funder()?;
    let account = Eoa::new((&trader).into());
    let s = Setup {
        token_a: common::contract("Token A")?.address,
        token_b: common::contract("Token B")?.address,
        dex: common::contract("ToyDex")?.address,
    };
    let keys = [trader.clone()];
    let send = async |label: &str, frames: Vec<Frame>, require_success: bool| {
        let envelope = common::envelope(&provider, account.address()).await?;
        let tx: FrameTx = TxPlan::new(&account).calls(frames).build(&envelope)?;
        common::run(&provider, tx, &keys, label, require_success).await
    };

    if !common::has_code(&provider, s.dex).await? {
        send(
            "setup: tokens, DEX, mints",
            setup_frames(&s, account.address())?,
            true,
        )
        .await?;
    }

    let show = async |label: &str| -> anyhow::Result<U256> {
        let (a, b, allowance) = balances(&provider, &s, account.address()).await?;
        println!("{label}: A {a} B {b} allowance {allowance}");
        Ok(allowance)
    };
    let amount = parse_ether("10")?;
    let approve = |value, atomic: bool| {
        let f = calls::erc20_approve(s.token_a, s.dex, value);
        if atomic { f.atomic() } else { f }
    };
    let swap_frame = |min_out, atomic: bool| {
        let f = Frame::sender(Some(s.dex))
            .with_data(
                swapCall {
                    amountIn: amount,
                    minOut: min_out,
                }
                .abi_encode(),
            )
            .with_execution(150_000)
            .with_state(2 * STORAGE_SET_STATE_GAS);
        if atomic { f.atomic() } else { f }
    };
    let stranger = common::fresh_address();
    let send_b = || calls::erc20_transfer(s.token_b, stranger, parse_ether("1").unwrap());

    if show("start").await? != U256::ZERO {
        send(
            "reset a leftover allowance",
            vec![approve(U256::ZERO, false)],
            true,
        )
        .await?;
    }
    send(
        "A. Example 2 as written: approve (batched) + swap",
        vec![approve(amount, true), swap_frame(amount, false)],
        true,
    )
    .await?;
    show("after A").await?;
    send(
        "B. atomic batch, swap reverts: approve, swap(minOut too high), send 1 B",
        vec![
            approve(amount, true),
            swap_frame(amount + U256::from(1), true),
            send_b(),
        ],
        false,
    )
    .await?;
    show("after B").await?;
    send(
        "C. no batch flag, swap reverts: approve, swap(minOut too high), send 1 B",
        vec![
            approve(amount, false),
            swap_frame(amount + U256::from(1), false),
            send_b(),
        ],
        false,
    )
    .await?;
    if show("after C").await? != U256::ZERO {
        send(
            "cleanup: clear the dangling allowance",
            vec![approve(U256::ZERO, false)],
            true,
        )
        .await?;
        show("after cleanup").await?;
    }
    Ok(())
}
