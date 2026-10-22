//! Notes of the registry, and each application's nullifiers.
//!
//! ```text
//! inner     = H(nullifierSecret, secret)
//! leaf      = H(tag, inner, state)          tag = the application's address, state < 2^64
//! nullifier = H(tag, nullifierSecret)
//! ```
//!
//! `H` is circomlib's `MiMCSponge(n, 220, 1)` with key 0 ([`kohaku_tornadocash::mimc_sponge`]).
//! The tag is in all three, so the same secrets are two unrelated notes, with two unrelated
//! nullifiers, in two applications.

use alloy::primitives::{Address, U256, keccak256};
use kohaku_tornadocash::{Field, mimc_sponge};

/// BN254's scalar field.
pub const FIELD: U256 = U256::from_limbs([
    0x43e1_f593_f000_0001,
    0x2833_e848_79b9_7091,
    0xb850_45b6_8181_585d,
    0x3064_4e72_e131_a029,
]);

/// A field element from any 256-bit value, reduced.
///
/// # Panics
///
/// Never: the value is reduced below the modulus first.
#[must_use]
pub fn field(x: U256) -> Field {
    Field::try_from(x.reduce_mod(FIELD)).expect("reduced below the modulus")
}

/// An application's tag: its address as a field element.
#[must_use]
pub fn tag(app: Address) -> Field {
    field(U256::from_be_slice(app.as_slice()))
}

/// What opens a note: the owner's alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Secrets {
    pub nullifier_secret: Field,
    pub secret: Field,
}

impl Secrets {
    /// Secrets from a seed and a label, as `exp-frames` experiment 32 derives them:
    /// `keccak256(seed || "exp-frames/32/note/<label>/nullifier")` mod p, and `.../secret`.
    #[must_use]
    pub fn derive(seed: &[u8], label: &str) -> Self {
        let part = |p: &str| {
            let mut buf = seed.to_vec();
            buf.extend_from_slice(format!("exp-frames/32/note/{label}/{p}").as_bytes());
            field(U256::from_be_bytes(keccak256(buf).0))
        };
        Self {
            nullifier_secret: part("nullifier"),
            secret: part("secret"),
        }
    }

    /// `H(nullifierSecret, secret)`: what a deposit names, and what a sender of a change note
    /// needs from its owner.
    #[must_use]
    pub fn inner(&self) -> Field {
        mimc_sponge(&[self.nullifier_secret, self.secret])
    }

    /// The nullifier these secrets give in `app`.
    #[must_use]
    pub fn nullifier(&self, app: Address) -> Field {
        mimc_sponge(&[tag(app), self.nullifier_secret])
    }
}

/// `H(tag, inner, state)`.
#[must_use]
pub fn leaf(app: Address, inner: Field, state: u64) -> Field {
    mimc_sponge(&[tag(app), inner, field(U256::from(state))])
}

/// A note of the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Note {
    pub app: Address,
    pub secrets: Secrets,
    /// Wei the registry holds for it.
    pub state: u64,
}

impl Note {
    #[must_use]
    pub fn leaf(&self) -> Field {
        leaf(self.app, self.secrets.inner(), self.state)
    }

    #[must_use]
    pub fn nullifier(&self) -> Field {
        self.secrets.nullifier(self.app)
    }
}
