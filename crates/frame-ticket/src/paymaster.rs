//! `TicketPaymaster.yul` (`exp-frames` experiment 36): sells tickets, and pays the gas of a
//! transaction that carries one.
//!
//! `contracts/TicketPaymaster.yul` is copied from that experiment, and `TicketPaymaster.hex` is
//! its creation code as solc 0.8.37 compiles it (EVM version osaka, optimizer on, 200 runs).

use alloy::{
    primitives::{Address, B256, U256, keccak256},
    sol,
};
use commonware_cryptography::bls12381::primitives::group::G2;
use kohaku_frame_accounts::{
    contracts::{create2_address, deploy_frame},
    sponsor::Sponsor,
};
use kohaku_frame_kit::{Frame, constants::approve};

use crate::ticket::{Ticket, g2_eip2537};

sol! {
    event Bought(address indexed buyer, uint256 count);
}

/// The paymaster's creation code, without its arguments.
///
/// # Panics
///
/// Never: the code is embedded hex.
#[must_use]
pub fn paymaster_code() -> Vec<u8> {
    hex::decode(include_str!("../contracts/TicketPaymaster.hex").trim())
        .expect("embedded creation code is hex")
}

/// A paymaster for one issuer key and one ticket price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketPaymaster {
    /// The issuers' group key.
    pub key: G2,
    /// What one ticket costs, and the most a transaction it pays for may cost.
    pub denomination: U256,
    pub salt: B256,
}

impl TicketPaymaster {
    /// Initcode: code `||` key (EIP-2537's G2) `||` denomination.
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = paymaster_code();
        code.extend_from_slice(&g2_eip2537(&self.key));
        code.extend_from_slice(&self.denomination.to_be_bytes::<32>());
        code
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    /// A `SENDER` frame deploying it through the CREATE2 deployer.
    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }

    /// A `SENDER` frame buying `count` tickets.
    #[must_use]
    pub fn buy_frame(&self, count: u64) -> Frame {
        Frame::sender(Some(self.address()))
            .with_value(self.denomination * U256::from(count))
            .with_execution(10_000)
    }

    /// The salt that names a paymaster for `label`.
    #[must_use]
    pub fn salt_of(label: &str) -> B256 {
        keccak256(label.as_bytes())
    }
}

/// Pays with a ticket: one `VERIFY(PAYMENT)` frame to the paymaster, its data the ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketSponsor {
    pub paymaster: Address,
    pub data: Vec<u8>,
    pub verify_execution: u64,
    /// 183,600 when `APPROVE(PAYMENT)` creates the sender's account: a fresh sender does not
    /// exist until its first transaction.
    pub state: u64,
}

impl TicketSponsor {
    /// Room for the check, which `exp-frames` experiment 36 measured at 122,006: the pairing
    /// alone is 102,900 under EIP-2537's prices.
    pub const VERIFY_EXECUTION: u64 = 130_000;
    pub const NEW_ACCOUNT_STATE: u64 = 183_600;

    /// The sponsor for a fresh sender's first transaction.
    #[must_use]
    pub fn new(paymaster: Address, ticket: &Ticket) -> Self {
        Self {
            paymaster,
            data: ticket.pay_data(),
            verify_execution: Self::VERIFY_EXECUTION,
            state: Self::NEW_ACCOUNT_STATE,
        }
    }
}

impl Sponsor for TicketSponsor {
    fn payment_frames(&self) -> Vec<Frame> {
        vec![
            Frame::verify(approve::PAYMENT, Some(self.paymaster))
                .with_data(self.data.clone())
                .with_execution(self.verify_execution)
                .with_state(self.state),
        ]
    }
}
