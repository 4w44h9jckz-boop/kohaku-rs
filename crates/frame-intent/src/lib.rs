//! An exact list of a frame transaction's writes, compared with an intent the user picks from a
//! template (`exp-frames` experiment 58).
//!
//! 1. [`writes`]: the list a patched `ethrex_simulateFrameTransaction` returns.
//! 2. [`template`]: the user's intent, from a template and its parameters, expanded through the
//!    [`layout`] registry into the writes it allows.
//! 3. [`check`]: the exact comparison, with the fee and the nonce exempt by kind, and the verdict.
//! 4. [`encode`]: on a pass, the intent in experiment 54's two signed forms, and the transaction
//!    signed with its check frame.
//!
//! No language model is involved anywhere.

pub mod check;
pub mod encode;
pub mod layout;
pub mod template;
pub mod writes;

pub use check::{Status, Verdict, check};
pub use layout::{Contract, Registry};
pub use template::{Intent, expand};
pub use writes::Simulation;
