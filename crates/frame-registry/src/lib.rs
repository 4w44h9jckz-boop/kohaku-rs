//! A registry for the private owned state of many applications, as `exp-frames` experiment 32
//! deployed it on the ethrex Hegota testnet.
//!
//! One tree holds every application's notes, and the registry is its own frame-transaction
//! sender. A note's owner updates it with a kernel proof checked in the registry's `VERIFY`,
//! with the note's nullifier as the transaction's nonce key: no relayer, no signature. The
//! nullifier is derived from the application's tag, so the same secrets in two applications
//! give two unrelated nullifiers.
//!
//! - [`note`]: notes, leaves and each application's nullifiers.
//! - [`update`]: a deposit frame, the kernel's input for a spend, and the update transaction.
//! - [`contracts`]: the registry, the verifier and the applications, and their addresses.
//! - [`groth16`]: the verifier's check, in Rust.

pub mod contracts;
pub mod groth16;
pub mod note;
pub mod update;

pub use contracts::{Application, Registry, Rule, Verifier};
pub use note::{Note, Secrets};
pub use update::{Spend, Update, update_tx};
