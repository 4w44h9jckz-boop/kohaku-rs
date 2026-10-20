//! Blind tickets: prepaid, unlinkable payment for a frame transaction's gas (`exp-frames`
//! experiment 36).
//!
//! A buyer pays a paymaster for tickets on chain. A committee of issuers, which holds the
//! ticket key only in shares, signs one blinded point per ticket bought. The buyer unblinds the
//! answers into the committee's ordinary BLS signature on a slot it chose, a fresh sender at
//! one nonce, and that sender's transaction carries the signature to the paymaster's `VERIFY`.
//! The issuers saw only uniformly random points, so nothing they hold matches a ticket to its
//! spend.
//!
//! - [`blind`]: blinding, an issuer's answer, unblinding, on Commonware's public API.
//! - [`issuers`]: the committee, its key made by Commonware's DKG.
//! - [`ticket`]: the message a ticket signs and the bytes a transaction carries.
//! - [`paymaster`]: the paymaster's code, a purchase, and the pay frame.

pub mod blind;
pub mod issuers;
pub mod paymaster;
pub mod ticket;

pub use issuers::{Committee, Issuer};
pub use paymaster::{TicketPaymaster, TicketSponsor};
pub use ticket::{Claim, Slot, Ticket};
