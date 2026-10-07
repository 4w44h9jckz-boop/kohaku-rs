//! The account and sponsor contracts, and deploying through the CREATE2 deployer.
//!
//! The Yul sources are in `contracts/`, copied from the `exp-frames` experiments that deployed
//! them, and the `.hex` files beside them are their creation code as solc 0.8.37 compiles them
//! (EVM version osaka, optimizer on, 200 runs). The tests check that this code, with the
//! experiments' arguments and salts, lands at the addresses the testnet has it at.

use alloy::primitives::{Address, B256, keccak256};
use kohaku_frame_kit::{
    Frame,
    constants::{CPSB, CREATE2_DEPLOYER, NEW_ACCOUNT_STATE_GAS},
};

fn code(hex_code: &str) -> Vec<u8> {
    hex::decode(hex_code.trim()).expect("embedded creation code is hex")
}

/// `SimpleAccount.yul`: one secp256k1 owner, checked with `SIGPARAM`. Initcode: code `||` owner.
#[must_use]
pub fn simple_account_code() -> Vec<u8> {
    code(include_str!("../contracts/SimpleAccount.hex"))
}

/// `Multisig.yul`: k of n secp256k1 or P256 owners, counted with `SIGPARAM`. Initcode: code `||`
/// owners `||` n `||` k, as 32-byte words.
#[must_use]
pub fn multisig_code() -> Vec<u8> {
    code(include_str!("../contracts/Multisig.hex"))
}

/// `TokenSponsor.yul`: pays gas for whoever pays it in one ERC-20, and refunds in a post-op.
/// Initcode: code `||` token `||` rate `||` owner, as 32-byte words.
#[must_use]
pub fn token_sponsor_code() -> Vec<u8> {
    code(include_str!("../contracts/TokenSponsor.hex"))
}

/// A deterministic salt from a label.
#[must_use]
pub fn salt_of(label: &str) -> B256 {
    keccak256(label.as_bytes())
}

/// Where the CREATE2 deployer puts `initcode` under `salt`.
#[must_use]
pub fn create2_address(initcode: &[u8], salt: B256) -> Address {
    CREATE2_DEPLOYER.create2_from_code(salt, initcode)
}

/// A 32-byte word holding an address, as the contracts read their arguments.
#[must_use]
pub fn word(a: Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a.as_slice());
    w
}

/// State gas for a deployment: the new account, plus a code deposit no larger than the initcode.
#[must_use]
pub fn deploy_state_gas(initcode: &[u8]) -> u64 {
    NEW_ACCOUNT_STATE_GAS + CPSB * initcode.len() as u64
}

fn deployer_calldata(initcode: &[u8], salt: B256) -> Vec<u8> {
    let mut data = Vec::with_capacity(32 + initcode.len());
    data.extend_from_slice(salt.as_slice());
    data.extend_from_slice(initcode);
    data
}

/// A `SENDER` frame deploying `initcode` from someone else's transaction. `extra_state` covers
/// what the constructor writes: 97,920 per fresh slot.
#[must_use]
pub fn deploy_frame(initcode: &[u8], salt: B256, extra_state: u64) -> Frame {
    Frame::sender(Some(CREATE2_DEPLOYER))
        .with_data(deployer_calldata(initcode, salt))
        .with_execution(300_000 + 20 * initcode.len() as u64)
        .with_state(deploy_state_gas(initcode) + extra_state)
}

/// The same deployment as a `DEFAULT` frame ahead of the sender's own `VERIFY`: EIP-8141's
/// Example 1b, an account deploying itself at `tx.sender`. It is part of the validation prefix,
/// so its execution budget is small, and its state gas counts against `MAX_VERIFY_STATE_GAS`
/// (500,000): that caps a self-deployed account at 206 bytes of code (experiment 05).
#[must_use]
pub fn self_deploy_frame(initcode: &[u8], salt: B256) -> Frame {
    Frame::entry_point(Some(CREATE2_DEPLOYER))
        .with_data(deployer_calldata(initcode, salt))
        .with_execution(80_000)
        .with_state(deploy_state_gas(initcode))
}
