//! `DependencyFramePool.yul`: `exp-frames` experiment 06's keyed pool, admitting EIP-8288
//! dependency frames just before the withdrawal frame, so that a withdrawal can carry a
//! leanSPHINCS-bound ticket's binder on a chain that runs EIP-8288. Experiment 06's own pool
//! counts its frames exactly and refuses such a withdrawal in its `VERIFY`.

use alloy::primitives::{Address, B256};
use kohaku_frame_accounts::contracts::{create2_address, deploy_frame};
use kohaku_frame_kit::Frame;

/// `DependencyFramePool.yul`'s creation code, without its arguments.
///
/// # Panics
///
/// Never: the code is embedded hex.
#[must_use]
pub fn dependency_pool_code() -> Vec<u8> {
    hex::decode(include_str!("../contracts/DependencyFramePool.hex").trim())
        .expect("embedded creation code is hex")
}

/// A pool with another pool's verifier, hasher, denomination, mode and history, and its own
/// EIP-8272 salt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyPool {
    /// The five words before the salt at the end of a deployed `FramePool`'s code.
    pub settings: [u8; 160],
    /// The salt the pool files its roots under, which is also its CREATE2 salt here.
    pub salt: B256,
}

impl DependencyPool {
    /// The settings of a deployed pool, from its runtime code: its last 192 bytes are
    /// `verifier || hasher || denomination || mode || history || salt`.
    #[must_use]
    pub fn like(runtime: &[u8], salt: B256) -> Option<Self> {
        let n = runtime.len();
        let tail = runtime.get(n.checked_sub(192)?..n - 32)?;
        Some(Self { settings: tail.try_into().ok()?, salt })
    }

    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut c = dependency_pool_code();
        c.extend_from_slice(&self.settings);
        c.extend_from_slice(self.salt.as_slice());
        c
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    /// Its deployment; the constructor writes nothing.
    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }
}
