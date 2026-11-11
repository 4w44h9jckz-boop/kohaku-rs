//! A blind account: ETH held for blind tickets, paid out to whoever presents one, with one count
//! per key so that payouts under a key never exceed the purchases under it (`exp-frames`
//! experiment 59).
//!
//! A key is `chi = keccak256(D || epoch)`, the two as 32-byte words. A ticket's message, under
//! [`NAMESPACE`], is
//!
//! ```text
//! chain_id (32) || account (20) || D (32) || epoch (8) || serial (32) || binder (20)   144 bytes
//! ```
//!
//! A payout is a frame transaction whose sender and payer is the account, with two frames:
//! `VERIFY` (scope 3) carrying `D || epoch || binder || n || serial * n || sigma`, and a `SENDER`
//! frame to the account calling `payout(D, epoch, to, n)`. Its nonce keys are the tickets'
//! serials, sorted, at sequence 0, and the binder signs its signature hash. `sigma` is the sum of
//! the tickets' signatures: one public key signs every message, so the pairing stays two pairs.

use alloy::primitives::{Address, B256, U256, keccak256};
use commonware_cryptography::bls12381::primitives::{
    Error,
    group::{G1, G2},
    sharing::Sharing,
    variant::MinSig,
};
use kohaku_frame_accounts::contracts::{create2_address, deploy_frame};
use kohaku_frame_kit::{Fees, Frame, FrameSignature, FrameTx, constants::approve};

use crate::{
    blind,
    ticket::{g1_eip2537, g2_eip2537},
};

/// The namespace a blind account's tickets are signed under.
pub const NAMESPACE: &[u8] = b"BLIND_ACCOUNT_V1";
/// The length of [`AccountClaim::message`].
pub const MESSAGE_LEN: usize = 144;
/// The most tickets one payout carries: EIP-8250's sixteen nonce keys.
pub const MAX_TICKETS: usize = 16;
/// `buy(uint64)`.
pub const BUY: [u8; 4] = [0x21, 0x5a, 0xdc, 0x4a];
/// `payout(uint256,uint64,address,uint256)`.
pub const PAYOUT: [u8; 4] = [0x42, 0x3b, 0x21, 0xcd];
/// `claim()`.
pub const CLAIM: [u8; 4] = [0x4e, 0x71, 0xd9, 0x2d];
/// The payout frame's execution budget: the account's `VERIFY` requires at least 100,000, and the
/// payout holds 60,000 back from its call to the recipient.
pub const PAYOUT_EXECUTION: u64 = 150_000;
/// The payout frame's state budget: the count's slot, a credit's slot, and the recipient's account
/// if it is new.
pub const PAYOUT_STATE: u64 =
    2 * kohaku_frame_kit::constants::STORAGE_SET_STATE_GAS + kohaku_frame_kit::constants::NEW_ACCOUNT_STATE_GAS;
/// The most tickets one payout carries on the test network: each nonce key's first use costs
/// 97,920 state gas in the validation prefix, which is capped at 500,000.
pub const TESTNET_MAX_TICKETS: usize = 5;

/// `BlindAccount.yul` compiled, before its key.
///
/// # Panics
///
/// Never: the file is hex.
#[must_use]
pub fn blind_account_code() -> Vec<u8> {
    hex::decode(include_str!("../contracts/BlindAccount.hex").trim()).expect("hex")
}

/// `keccak256(D || epoch)`.
#[must_use]
pub fn chi(denomination: U256, epoch: u64) -> B256 {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(&denomination.to_be_bytes::<32>());
    b[56..].copy_from_slice(&epoch.to_be_bytes());
    keccak256(b)
}

/// The account's storage slot for `burned[chi]` (0), `minted[chi]` (1) or `owed[addr]` (2).
#[must_use]
pub fn slot(key: B256, which: u8) -> B256 {
    let mut b = [0u8; 64];
    b[..32].copy_from_slice(key.as_slice());
    b[63] = which;
    keccak256(b)
}

/// A blind account, deployed through the CREATE2 deployer under `salt`.
#[derive(Debug, Clone)]
pub struct BlindAccount {
    pub public: G2,
    pub salt: B256,
    /// Creation code other than [`blind_account_code`], for a variant under test.
    pub code: Option<Vec<u8>>,
}

impl BlindAccount {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        [self.code.clone().unwrap_or_else(blind_account_code), g2_eip2537(&self.public).to_vec()].concat()
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }

    /// A `SENDER` frame buying one ticket of `denomination` for `epoch`.
    #[must_use]
    pub fn buy_frame(&self, denomination: U256, epoch: u64) -> Frame {
        let mut data = BUY.to_vec();
        data.extend_from_slice(&U256::from(epoch).to_be_bytes::<32>());
        Frame::sender(Some(self.address()))
            .with_value(denomination)
            .with_data(data)
            .with_execution(60_000)
            .with_state(2 * kohaku_frame_kit::constants::STORAGE_SET_STATE_GAS)
    }
}

/// What a ticket says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountClaim {
    pub chain_id: u64,
    pub account: Address,
    pub denomination: U256,
    pub epoch: u64,
    /// Non-zero: the payout's nonce key.
    pub serial: U256,
    /// The one-time key that must sign the payout.
    pub binder: Address,
}

impl AccountClaim {
    #[must_use]
    pub fn message(&self) -> [u8; MESSAGE_LEN] {
        let mut m = [0u8; MESSAGE_LEN];
        m[..32].copy_from_slice(&U256::from(self.chain_id).to_be_bytes::<32>());
        m[32..52].copy_from_slice(self.account.as_slice());
        m[52..84].copy_from_slice(&self.denomination.to_be_bytes::<32>());
        m[84..92].copy_from_slice(&self.epoch.to_be_bytes());
        m[92..124].copy_from_slice(&self.serial.to_be_bytes::<32>());
        m[124..].copy_from_slice(self.binder.as_slice());
        m
    }

    #[must_use]
    pub fn chi(&self) -> B256 {
        chi(self.denomination, self.epoch)
    }
}

/// A claim and the issuers' signature on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountTicket {
    pub claim: AccountClaim,
    pub signature: G1,
}

impl AccountTicket {
    pub fn verify(&self, sharing: &Sharing<MinSig>) -> Result<(), Error> {
        blind::verify(sharing, NAMESPACE, &self.claim.message(), &self.signature)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PayoutError {
    #[error("a payout carries 1 to {MAX_TICKETS} tickets, not {0}")]
    Count(usize),
    #[error("the tickets differ in account, denomination, epoch, binder or chain")]
    Mixed,
    #[error("two tickets share a serial, or a serial is zero")]
    Serial,
}

/// The payout of `tickets` to `to`: its two frames, its nonce keys (the serials, sorted) at
/// sequence 0, and the binder's entry, unsigned.
pub fn payout_tx(tickets: &[AccountTicket], to: Address, fees: Fees) -> Result<FrameTx, PayoutError> {
    let n = tickets.len();
    if n == 0 || n > MAX_TICKETS {
        return Err(PayoutError::Count(n));
    }
    let c = tickets[0].claim;
    if tickets.iter().any(|t| {
        let o = t.claim;
        (o.chain_id, o.account, o.denomination, o.epoch, o.binder) != (c.chain_id, c.account, c.denomination, c.epoch, c.binder)
    }) {
        return Err(PayoutError::Mixed);
    }
    let mut sorted: Vec<&AccountTicket> = tickets.iter().collect();
    sorted.sort_by_key(|t| t.claim.serial);
    if sorted.windows(2).any(|w| w[0].claim.serial == w[1].claim.serial) || sorted[0].claim.serial.is_zero() {
        return Err(PayoutError::Serial);
    }
    let sigma = sorted.iter().skip(1).fold(sorted[0].signature, |acc, t| acc + &t.signature);

    let mut verify = Vec::with_capacity(189 + 32 * n);
    verify.extend_from_slice(&c.denomination.to_be_bytes::<32>());
    verify.extend_from_slice(&c.epoch.to_be_bytes());
    verify.extend_from_slice(c.binder.as_slice());
    verify.push(u8::try_from(n).map_err(|_| PayoutError::Count(n))?);
    for t in &sorted {
        verify.extend_from_slice(&t.claim.serial.to_be_bytes::<32>());
    }
    verify.extend_from_slice(&g1_eip2537(&sigma));

    let mut call = PAYOUT.to_vec();
    call.extend_from_slice(&c.denomination.to_be_bytes::<32>());
    call.extend_from_slice(&U256::from(c.epoch).to_be_bytes::<32>());
    call.extend_from_slice(to.into_word().as_slice());
    call.extend_from_slice(&U256::from(n).to_be_bytes::<32>());

    Ok(FrameTx {
        chain_id: c.chain_id,
        nonce_keys: sorted.iter().map(|t| t.claim.serial).collect(),
        nonce_seq: 0,
        sender: c.account,
        frames: vec![
            // EIP-8250 charges each keyed nonce's first use, 97,920 state gas, to the frame that
            // approves payment: here, this one.
            Frame::verify(approve::EXECUTION_AND_PAYMENT, None)
                .with_data(verify)
                .with_execution(110_000 + 25_000 * n as u64)
                .with_state(kohaku_frame_kit::constants::STORAGE_SET_STATE_GAS * n as u64),
            Frame::sender(Some(c.account))
                .with_data(call)
                .with_execution(PAYOUT_EXECUTION)
                .with_state(PAYOUT_STATE),
        ],
        signatures: vec![crate::bound::binder_entry(c.binder)],
        fees,
        blob_versioned_hashes: vec![],
    })
}

/// The binder's entry, as a signature entry: what [`kohaku_frame_kit::sign_all`] fills.
#[must_use]
pub fn binder_entry(binder: Address) -> FrameSignature {
    crate::bound::binder_entry(binder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_message_lays_out_as_the_contract_reads_it() {
        let c = AccountClaim {
            chain_id: 8141,
            account: Address::repeat_byte(0xaa),
            denomination: U256::from(10u64.pow(16)),
            epoch: 7,
            serial: U256::from(0x5e),
            binder: Address::repeat_byte(0xbb),
        };
        let m = c.message();
        assert_eq!(U256::from_be_slice(&m[..32]), U256::from(8141));
        assert_eq!(&m[32..52], c.account.as_slice());
        assert_eq!(U256::from_be_slice(&m[52..84]), c.denomination);
        assert_eq!(u64::from_be_bytes(m[84..92].try_into().unwrap()), 7);
        assert_eq!(U256::from_be_slice(&m[92..124]), U256::from(0x5e));
        assert_eq!(&m[124..], c.binder.as_slice());
    }

    #[test]
    fn the_code_is_there() {
        assert!(blind_account_code().len() > 1_000);
        assert_eq!(slot(B256::ZERO, 1), keccak256([[0u8; 63].as_slice(), &[1]].concat()));
    }
}
