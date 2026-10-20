//! A private read's answer, checked by the reader and signed by the server (`exp-frames`
//! experiment 39).
//!
//! Experiment 37's reader (`kohaku-ticket-read`) took the server's answers on its word. Here each
//! record of the PIR table carries the account's branch in the state trie, the reader checks it
//! against a block header it fetched itself, and the server signs every answer, so a wrong one is
//! evidence that a third party can check from public data.
//!
//! - [`trie`]: an account read out of the state trie from nodes taken by their hashes.
//! - [`header`]: a block header, fetched and hashed again by whoever checks against it.
//! - [`table`]: the account table with branches in its records, and the trie's shared top.
//! - [`statement`]: what the server signs, and the commitment to its hint.
//! - [`server`]: the read server, which signs its answers.
//! - [`client`]: the reader that checks, and a backend for `kohaku-pir-rpc`'s router.
//! - [`evidence`]: a signed wrong answer made evidence, and the third party who judges it.

pub mod client;
pub mod evidence;
pub mod header;
pub mod server;
pub mod statement;
pub mod table;
pub mod trie;

pub use client::{Checked, CheckedLookup, CheckedReader};
pub use evidence::{Evidence, Verdict, judge};
pub use header::Header;
pub use server::{Manifest, Server};
pub use table::{CheckedTable, Entry};
