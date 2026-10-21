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
//! - [`announce`]: encrypted announcements on a board, and a swap's offer and answer.
//! - [`custody`]: `exp-frames` experiment 40's vaulted registry, each application's value in a
//!   vault of its own, bound into what a withdrawal proves.
//!
//! Version 2 of the registry (`exp-frames` experiment 33) adds a deadline to every proof and
//! makes a pair of updates a fair swap: each names the other's nullifier and change note.

pub mod announce;
pub mod contracts;
pub mod custody;
pub mod groth16;
pub mod note;
pub mod update;

pub use contracts::{Application, Board, Registry, Rule, Verifier, Version};
pub use note::{Note, Secrets};
pub use update::{Spend, Update, update_tx};
