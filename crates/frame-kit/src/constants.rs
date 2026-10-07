//! EIP-8141 as the ethrex Hegota testnet pins it (ethereum/EIPs@b75cbe6115), with EIP-8250 keyed
//! nonces (ethereum/EIPs@f3079a09e8) and EIP-8272 recent roots.

use alloy::primitives::{Address, address};

/// The transaction type byte.
pub const FRAME_TX_TYPE: u8 = 0x06;

/// Frame `mode` values.
pub mod mode {
    /// Execute as `ENTRY_POINT` (0xaa).
    pub const DEFAULT: u8 = 0;
    /// Static call; authorisation happens here through `APPROVE`. A revert invalidates the tx.
    pub const VERIFY: u8 = 1;
    /// Execute as `tx.sender`; requires `sender_approved`.
    pub const SENDER: u8 = 2;
}

/// `APPROVE` scope bits, also the low two bits of a `VERIFY` frame's `flags`.
pub mod approve {
    pub const NONE: u8 = 0x0;
    pub const PAYMENT: u8 = 0x1;
    pub const EXECUTION: u8 = 0x2;
    pub const EXECUTION_AND_PAYMENT: u8 = 0x3;
    pub const SCOPE_MASK: u8 = 0x3;
}

/// Chains a frame with the next one: if either reverts, both are reverted.
pub const ATOMIC_BATCH_FLAG: u8 = 0x4;

/// Signature `scheme` values.
pub mod scheme {
    pub const ARBITRARY: u8 = 0x0;
    pub const SECP256K1: u8 = 0x1;
    pub const P256: u8 = 0x2;
}

/// Per-frame receipt status.
pub mod frame_status {
    pub const FAILURE: u8 = 0;
    pub const SUCCESS: u8 = 1;
    pub const SKIPPED: u8 = 2;
}

// ---- gas ----

pub const FRAME_TX_INTRINSIC_COST: u64 = 12_000;
pub const FRAME_TX_PER_FRAME_COST: u64 = 475;
pub const TX_VALUE_COST: u64 = 6_000;
pub const STANDARD_TOKEN_COST: u64 = 4;
pub const TOTAL_COST_FLOOR_PER_TOKEN: u64 = 16;
/// EIP-7825 cap, applied to regular gas only.
pub const TX_MAX_GAS_LIMIT: u64 = 1 << 24;
pub const GAS_PER_BLOB: u64 = 131_072;

/// Verification gas charged per signature, by scheme.
#[must_use]
pub fn signature_gas(scheme: u8) -> Option<u64> {
    match scheme {
        scheme::ARBITRARY => Some(100),
        scheme::SECP256K1 => Some(2_800),
        scheme::P256 => Some(6_700),
        _ => None,
    }
}

/// EIP-8037 cost per state byte.
pub const CPSB: u64 = 1_530;
/// State gas to create an account, e.g. a value transfer to a fresh address: 183,600.
pub const NEW_ACCOUNT_STATE_GAS: u64 = 120 * CPSB;
/// State gas to set a fresh storage slot, and the first use of a keyed nonce: 97,920.
pub const STORAGE_SET_STATE_GAS: u64 = 64 * CPSB;

pub const MAX_FRAMES: usize = 64;
pub const MAX_NONCE_KEYS: usize = 16;

/// Public-mempool cap on the validation prefix, as the EIP writes it.
pub const MAX_VERIFY_GAS_SPEC: u64 = 100_000;
/// The testnet nodes run with `--mempool.max-verify-gas=500000`.
pub const MAX_VERIFY_GAS_TESTNET: u64 = 500_000;
pub const MAX_VERIFY_STATE_GAS: u64 = 500_000;

// ---- addresses ----

pub const ENTRY_POINT: Address = address!("0x00000000000000000000000000000000000000aa");
/// Expiry verifier, where the pinned EIP and the testnet install it. EIP master later moved it.
pub const EXPIRY_VERIFIER: Address = address!("0x0000000000000000000000000000000000008141");
/// EIP-8250 keyed-nonce storage.
pub const NONCE_MANAGER: Address = address!("0x0000000000000000000000000000000000008250");
/// EIP-8272 recent-roots predeploy.
pub const RECENT_ROOT: Address = address!("0x0000000000000000000000000000000000008272");
/// Arachnid's deterministic CREATE2 deployer: calldata is `salt || initcode`.
pub const CREATE2_DEPLOYER: Address = address!("0x4e59b44847b379578588920ca78fbf26c0b4956c");
