//! Private reads of account state, paid with blind tickets (`exp-frames` experiment 37).
//!
//! A reader buys tickets as a private sender does (`kohaku-frame-ticket`), in public, from the
//! same committee, and spends one per read at a server that answers private reads: a ticket and
//! a PIR query in, an answer out. The server checks the ticket before it does any work, keeps
//! its own spent set, and learns neither who reads nor what.
//!
//! - [`pir`]: single-server PIR in the style of `SimplePIR`.
//! - [`table`]: the account table, in hashed buckets.
//! - [`ticket`]: the read ticket.
//! - [`server`]: the read server.
//! - [`client`]: the reader, and a backend for `kohaku-pir-rpc`'s router.

pub mod client;
pub mod pir;
pub mod server;
pub mod table;
pub mod ticket;

pub use client::{Reader, TicketLookup};
pub use server::{Manifest, Server};
pub use table::{Account, Table};
pub use ticket::{ReadClaim, ReadTicket};
