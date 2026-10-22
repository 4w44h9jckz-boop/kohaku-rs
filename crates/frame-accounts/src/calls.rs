//! Common calls, as `SENDER` frames with the gas they need.

use alloy::{
    primitives::{Address, U256},
    sol,
    sol_types::SolCall,
};
use kohaku_frame_kit::{
    Frame,
    constants::{NEW_ACCOUNT_STATE_GAS, STORAGE_SET_STATE_GAS},
};

sol! {
    function transfer(address to, uint256 amount) returns (bool);
    function approve(address spender, uint256 amount) returns (bool);
}

/// Send ETH. Creating the recipient's account costs 183,600 state gas, which execution gas
/// cannot pay for, so say whether it exists.
#[must_use]
pub fn eth_transfer(to: Address, value: U256, recipient_exists: bool) -> Frame {
    Frame::sender(Some(to))
        .with_value(value)
        .with_execution(30_000)
        .with_state(if recipient_exists {
            0
        } else {
            NEW_ACCOUNT_STATE_GAS
        })
}

/// `token.transfer(to, amount)`, with state gas for the recipient's balance slot.
#[must_use]
pub fn erc20_transfer(token: Address, to: Address, amount: U256) -> Frame {
    Frame::sender(Some(token))
        .with_data(transferCall { to, amount }.abi_encode())
        .with_execution(50_000)
        .with_state(STORAGE_SET_STATE_GAS)
}

/// `token.approve(spender, amount)`, with state gas for the allowance slot.
#[must_use]
pub fn erc20_approve(token: Address, spender: Address, amount: U256) -> Frame {
    Frame::sender(Some(token))
        .with_data(approveCall { spender, amount }.abi_encode())
        .with_execution(50_000)
        .with_state(STORAGE_SET_STATE_GAS)
}
