//! The account and sponsor contracts, and deploying through the CREATE2 deployer.
//!
//! The Yul sources are in `contracts/`, copied from the `exp-frames` experiments that deployed
//! them, and the `.hex` files beside them are their creation code as solc 0.8.37 compiles them
//! (EVM version osaka, optimizer on, 200 runs). The tests check that this code, with the
//! experiments' arguments and salts, lands at the addresses the testnet has it at.

use alloy::primitives::{Address, B256, b256, keccak256};
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

/// `P256Account.yul`: `SimpleAccount.yul` with a P256 owner, `keccak256(qx || qy)[12..]`, checked
/// with `SIGPARAM`. Initcode: code `||` owner, as a 32-byte word.
#[must_use]
pub fn p256_account_code() -> Vec<u8> {
    code(include_str!("../contracts/P256Account.hex"))
}

/// `WebAuthnAccount.yul`: a passkey owner whose `WebAuthn` assertion the account checks itself,
/// with the SHA-256 and `P256VERIFY` precompiles. Initcode: code `||` qx `||` qy.
#[must_use]
pub fn webauthn_account_code() -> Vec<u8> {
    code(include_str!("../contracts/WebAuthnAccount.hex"))
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

/// `SessionAccount.yul`: an owner, and session keys limited to one target, one selector, a
/// deadline and a budget. Initcode: code `||` owner, as a 32-byte word.
#[must_use]
pub fn session_account_code() -> Vec<u8> {
    code(include_str!("../contracts/SessionAccount.hex"))
}

/// `CanonicalPaymaster.yul`: an instance of the EIP-8141 canonical paymaster, ethereum/EIPs#12041
/// as ethrex pins it. Initcode: code `||` signer, as a 32-byte word. The constructor writes the
/// signer to slot 0 and returns the PR's 355-byte runtime verbatim.
#[must_use]
pub fn canonical_paymaster_code() -> Vec<u8> {
    code(include_str!("../contracts/CanonicalPaymaster.hex"))
}

/// `keccak256` of the canonical paymaster's runtime. A node recognises an instance by this hash
/// and nothing else: `exp-frames` experiment 09 deployed a copy one unreachable byte longer, and
/// the mempool treated it as any other paymaster contract.
pub const CANONICAL_PAYMASTER_CODE_HASH: B256 =
    b256!("0xda42f0d11838c4c0c3129b8b8e93e9718127ad6b315e517e1088125707c4d45c");

/// Whether `runtime`, an account's code as `eth_getCode` returns it, is the canonical paymaster.
#[must_use]
pub fn is_canonical_paymaster(runtime: &[u8]) -> bool {
    keccak256(runtime) == CANONICAL_PAYMASTER_CODE_HASH
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
