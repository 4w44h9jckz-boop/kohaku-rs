//! The registry, its verifier and the applications, and where they deploy.
//!
//! The Yul sources in `contracts/` are copied from `exp-frames` experiment 32, and the `.hex`
//! files beside them are their creation code as solc 0.8.37 compiles them (EVM version osaka,
//! optimizer on, 200 runs). `kernel.vkey.json` is the kernel's verifying key, which the verifier
//! carries appended to its code.

use alloy::primitives::{Address, B256, U256, keccak256};
use kohaku_frame_accounts::contracts::{create2_address, deploy_frame, word};
use kohaku_frame_kit::{Frame, constants::STORAGE_SET_STATE_GAS};
use serde::Deserialize;

use crate::groth16::VerifyingKey;

fn code(hex_code: &str) -> Vec<u8> {
    hex::decode(hex_code.trim()).expect("embedded creation code is hex")
}

/// `OwnedStateRegistry.yul`. Initcode: code `||` hasher `||` verifier `||` root salt.
#[must_use]
pub fn registry_code() -> Vec<u8> {
    code(include_str!("../contracts/OwnedStateRegistry.hex"))
}

/// `Groth16Verifier.yul`. Initcode: code `||` the key's words (`VerifyingKey::words`).
#[must_use]
pub fn verifier_code() -> Vec<u8> {
    code(include_str!("../contracts/Groth16Verifier.hex"))
}

/// The kernel's verifying key, as snarkjs exported it.
///
/// # Panics
///
/// Never: the key is embedded, and a test parses it.
#[must_use]
pub fn kernel_key() -> VerifyingKey {
    #[derive(Deserialize)]
    struct Json {
        #[serde(rename = "nPublic")]
        n_public: usize,
        vk_alpha_1: Vec<String>,
        vk_beta_2: Vec<Vec<String>>,
        vk_gamma_2: Vec<Vec<String>>,
        vk_delta_2: Vec<Vec<String>>,
        #[serde(rename = "IC")]
        ic: Vec<Vec<String>>,
    }
    let j: Json = serde_json::from_str(include_str!("../contracts/kernel.vkey.json"))
        .expect("embedded verifying key is JSON");
    let n = |s: &String| U256::from_str_radix(s, 10).expect("a decimal field element");
    let g1 = |p: &[String]| [n(&p[0]), n(&p[1])];
    // EIP-197's order: x1, x0, y1, y0.
    let g2 = |p: &[Vec<String>]| [n(&p[0][1]), n(&p[0][0]), n(&p[1][1]), n(&p[1][0])];
    assert_eq!(j.ic.len(), j.n_public + 1);
    VerifyingKey {
        alpha: g1(&j.vk_alpha_1),
        beta: g2(&j.vk_beta_2),
        gamma: g2(&j.vk_gamma_2),
        delta: g2(&j.vk_delta_2),
        ic: j.ic.iter().map(|p| g1(p)).collect(),
    }
}

/// The verifier for `key`, deployed through the CREATE2 deployer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verifier {
    pub key: VerifyingKey,
    pub salt: B256,
}

impl Verifier {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = verifier_code();
        code.extend_from_slice(&self.key.words());
        code
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }
}

/// An `OwnedStateRegistry`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registry {
    /// Tornado Cash's `MiMC` hasher.
    pub hasher: Address,
    pub verifier: Address,
    /// The EIP-8272 salt its roots are filed under.
    pub root_salt: B256,
    /// The CREATE2 salt.
    pub salt: B256,
}

impl Registry {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let mut code = registry_code();
        code.extend_from_slice(&word(self.hasher));
        code.extend_from_slice(&word(self.verifier));
        code.extend_from_slice(self.root_salt.as_slice());
        code
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        deploy_frame(&self.initcode(), self.salt, 0)
    }

    /// `keccak256(registry || root_salt)`: the EIP-8272 source id of its roots.
    #[must_use]
    pub fn source_id(&self) -> B256 {
        let mut buf = [0u8; 52];
        buf[..20].copy_from_slice(self.address().as_slice());
        buf[20..].copy_from_slice(self.root_salt.as_slice());
        keccak256(buf)
    }
}

/// An application's rule, which the registry asks at every deposit and update. Each answer
/// reads nothing but the application's code, except [`Rule::Stored`]'s, the control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// `FixedPool.yul`: notes of exactly `denomination`, spent whole with no change note.
    FixedPool { denomination: U256 },
    /// `Balance.yul`: any deposit above zero; at most `cap` out per update, change allowed.
    Balance { cap: U256 },
    /// `StoredRule.yul`: as `Balance`, with the cap in its own storage, which `VERIFY` may not
    /// read. Its updates are refused at admission.
    Stored { cap: U256 },
}

impl Rule {
    /// Whether the application accepts a deposit of `value`.
    #[must_use]
    pub fn accepts(&self, value: U256) -> bool {
        match self {
            Self::FixedPool { denomination } => value == *denomination,
            Self::Balance { .. } | Self::Stored { .. } => value > U256::ZERO,
        }
    }

    /// Whether the application allows an update taking `withdrawn` out, with or without change.
    #[must_use]
    pub fn allows(&self, withdrawn: U256, change: bool) -> bool {
        match self {
            Self::FixedPool { denomination } => withdrawn == *denomination && !change,
            Self::Balance { cap } | Self::Stored { cap } => withdrawn <= *cap,
        }
    }
}

/// An application: a rule, deployed under a salt. Its address is its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Application {
    pub rule: Rule,
    pub salt: B256,
}

impl Application {
    #[must_use]
    pub fn initcode(&self) -> Vec<u8> {
        let (hex_code, arg) = match self.rule {
            Rule::FixedPool { denomination } => {
                (include_str!("../contracts/FixedPool.hex"), denomination)
            }
            Rule::Balance { cap } => (include_str!("../contracts/Balance.hex"), cap),
            Rule::Stored { cap } => (include_str!("../contracts/StoredRule.hex"), cap),
        };
        let mut c = code(hex_code);
        c.extend_from_slice(&arg.to_be_bytes::<32>());
        c
    }

    #[must_use]
    pub fn address(&self) -> Address {
        create2_address(&self.initcode(), self.salt)
    }

    /// A `SENDER` frame deploying it; `StoredRule`'s constructor writes one fresh slot.
    #[must_use]
    pub fn deploy_frame(&self) -> Frame {
        let extra = match self.rule {
            Rule::Stored { .. } => STORAGE_SET_STATE_GAS,
            _ => 0,
        };
        deploy_frame(&self.initcode(), self.salt, extra)
    }
}
