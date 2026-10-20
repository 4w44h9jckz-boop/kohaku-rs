//! `DeviceRecoveryAccount.yul` (`exp-frames` experiment 31): an owner key that m of the owner's
//! own n devices can replace, after a delay the current owner can use to cancel. Nobody else
//! holds anything. The account stores only `keccak256(salt || m || devices)`, and the devices'
//! transaction reveals the list in its `VERIFY` frame's data.
//!
//! ```text
//! signed by        VERIFY data                 frames after VERIFY
//! the owner        empty                       anything
//! m devices        salt || m || devices        exactly one: SENDER -> self 0x01 || newOwner
//! pending owner    empty                       exactly one: SENDER -> self 0x02
//! ```
//!
//! When a finish comes before the unlock time, what happens depends on the [`TimeRule`] the
//! account was deployed with. Under [`TimeRule::Eip`] it is admitted, included, and its finish
//! frame reverts. Under [`TimeRule::Ethrex`] the pending owner's `VERIFY` calls the expiry
//! verifier with `unlock - 1` and requires it to refuse, so the finish is refused at admission.
//! That relies on ethrex allowing `TIMESTAMP` in a call to `0x8141` from `VERIFY`, which the EIP's
//! wording does not: on a client that follows the EIP, such an account could never be recovered.

use alloy::primitives::{Address, B256, Bytes, keccak256};
use kohaku_frame_kit::{
    Frame, FrameSignature,
    constants::{STORAGE_SET_STATE_GAS, scheme},
};

use crate::{
    account::FrameAccount,
    contracts::{create2_address, deploy_frame, device_recovery_account_code, word},
};

/// Which rule decides that a finish is too early.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeRule {
    /// In execution: an early finish is included and reverts.
    Eip,
    /// In `VERIFY`, through the expiry verifier: an early finish is refused at admission, on
    /// ethrex only.
    Ethrex,
}

/// The owner's devices, as the devices' `VERIFY` frame reveals them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Devices {
    pub salt: B256,
    /// How many must sign.
    pub m: u8,
    pub devices: Vec<Address>,
}

impl Devices {
    /// `salt || m || devices`.
    #[must_use]
    pub fn reveal(&self) -> Bytes {
        let mut out = Vec::with_capacity(33 + 20 * self.devices.len());
        out.extend_from_slice(self.salt.as_slice());
        out.push(self.m);
        for d in &self.devices {
            out.extend_from_slice(d.as_slice());
        }
        out.into()
    }

    /// What the account stores: `keccak256(salt || m || devices)`.
    #[must_use]
    pub fn commitment(&self) -> B256 {
        keccak256(self.reveal())
    }
}

/// A `DeviceRecoveryAccount`, deployed by someone else (its code is over 800 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRecoveryAccount {
    /// The owner it was deployed with; recoveries change the owner in storage, not this.
    pub owner: Address,
    pub commitment: B256,
    /// Seconds between a start and the earliest finish.
    pub delay: u64,
    pub rule: TimeRule,
    pub salt: B256,
}

/// The operations, as the account's `SENDER` frames to itself.
pub mod op {
    pub const START: u8 = 0x01;
    pub const FINISH: u8 = 0x02;
    pub const CANCEL: u8 = 0x03;
    pub const SET_DEVICES: u8 = 0x04;
}

impl DeviceRecoveryAccount {
    /// Every path's `VERIFY` budget: the devices' path checks a list, the pending owner's may
    /// call the expiry verifier.
    pub const VERIFY_EXECUTION: u64 = 40_000;
    pub const OP_EXECUTION: u64 = 50_000;

    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = device_recovery_account_code();
        code.extend_from_slice(&word(self.owner));
        code.extend_from_slice(self.commitment.as_slice());
        code.extend_from_slice(&alloy::primitives::U256::from(self.delay).to_be_bytes::<32>());
        let lower_bound: u8 = match self.rule {
            TimeRule::Eip => 0,
            TimeRule::Ethrex => 1,
        };
        code.extend_from_slice(&alloy::primitives::U256::from(lower_bound).to_be_bytes::<32>());
        code
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    /// A `SENDER` frame deploying this account from someone else's transaction: its constructor
    /// writes three fresh slots.
    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 3 * STORAGE_SET_STATE_GAS)
    }

    fn op_frame(&self, data: Vec<u8>) -> Frame {
        Frame::sender(Some(self.address()))
            .with_data(data)
            .with_execution(Self::OP_EXECUTION)
    }

    /// The devices' frame: hand the account to `next` once the delay is over.
    #[must_use]
    pub fn start(&self, next: Address) -> Frame {
        let mut data = vec![op::START];
        data.extend_from_slice(next.as_slice());
        self.op_frame(data)
    }

    /// The pending owner's frame, once the delay is over.
    #[must_use]
    pub fn finish(&self) -> Frame {
        self.op_frame(vec![op::FINISH])
    }

    /// The owner's frame cancelling a pending recovery.
    #[must_use]
    pub fn cancel(&self) -> Frame {
        self.op_frame(vec![op::CANCEL])
    }

    /// The owner's frame replacing the device commitment, after a recovery has revealed it.
    #[must_use]
    pub fn set_devices(&self, devices: &Devices) -> Frame {
        let mut data = vec![op::SET_DEVICES];
        data.extend_from_slice(devices.commitment().as_slice());
        self.op_frame(data)
    }

    /// The account, signed for by its current owner or by the pending owner.
    #[must_use]
    pub fn signed_by(&self, key: Address) -> RecoverySigner {
        RecoverySigner {
            account: self.address(),
            verify_data: Bytes::new(),
            signers: vec![key],
        }
    }

    /// The account, signed for by `devices`, which reveal themselves in `VERIFY`'s data.
    #[must_use]
    pub fn signed_by_devices(&self, devices: &Devices) -> RecoverySigner {
        let mut signers = devices.devices.clone();
        signers.sort();
        signers.truncate(usize::from(devices.m));
        RecoverySigner {
            account: self.address(),
            verify_data: devices.reveal(),
            signers,
        }
    }
}

/// A [`DeviceRecoveryAccount`] as one of its signers sees it, for [`crate::TxPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoverySigner {
    account: Address,
    verify_data: Bytes,
    /// In ascending order, as the account requires of the devices.
    signers: Vec<Address>,
}

impl FrameAccount for RecoverySigner {
    fn address(&self) -> Address {
        self.account
    }

    fn verify_frame(&self, scope: u8) -> Frame {
        Frame::verify(scope, None)
            .with_execution(DeviceRecoveryAccount::VERIFY_EXECUTION)
            .with_data(self.verify_data.clone())
    }

    fn signature_entries(&self) -> Vec<FrameSignature> {
        self.signers
            .iter()
            .map(|&s| FrameSignature {
                scheme: scheme::SECP256K1,
                signer: Some(s),
                ..FrameSignature::default()
            })
            .collect()
    }
}
