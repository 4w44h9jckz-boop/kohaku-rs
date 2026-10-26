//! What an opening holds, and how the owner checks it.
//!
//! The note is the privacy pool's (`exp-e2e-frames` experiment 01's circuit, unchanged): a
//! commitment `C = pedersen(n || s)` over a 31-byte nullifier `n` and a 31-byte secret `s`. Nobody
//! but the owner ever knows the whole of it.
//!
//! - The owner derives `s` from its seed and gives the note's payer only the point
//!   `B(s) = P(0 || s) - P(0 || 0)`, where `P` is Pedersen's point. Pedersen is a sum of 4-bit
//!   window terms, and `s` starts on a window boundary, so `B(s)` is exactly `s`'s share of the
//!   commitment's point.
//! - Each of the committee's three members picks its own windows of `n`: member 0 windows 0 to 20,
//!   member 1 windows 21 to 41, member 2 windows 42 to 61 (window `w` is bits `4w` to `4w + 3`,
//!   little-endian). It sets every other bit of its part to zero. So no member knows `n`, and
//!   `C = x(A(n_0) + A(n_1) + A(n_2) - 2 A(0) + B(s))` with `A(x) = P(x || 0)`.
//! - Each member seals its part `n_j` to the owner ([`Part`], 48 bytes). An update publishes the
//!   three, in member order. The owner opens them, ORs the parts into `n`, and checks
//!   `pedersen(n || s) = C` at the note's leaf ([`assemble`], [`check`]).
//!
//! Any failure is a garbage opening ([`Garbage`]): the owner learns on the day it is published,
//! not on the day it needs it.

use alloy::primitives::Address;
use kohaku_frame_secrets::derive::Seed;
use kohaku_tornadocash::{
    BabyJubJubPoint, Field, Note, Nullifier, Secret, pack_point, pedersen_point,
};

use crate::{
    Context, ExitError, MESSAGE_LEN, OPENING_LEN, OpeningKey, open, opening_key, vault_label,
};

/// The committee's size.
pub const MEMBERS: usize = 3;
/// Each member's windows of the nullifier, first and last.
pub const WINDOWS: [(usize, usize); MEMBERS] = [(0, 20), (21, 41), (42, 61)];
/// An update's published openings: one sealed part from each member, in member order.
pub const OPENINGS_LEN: usize = MEMBERS * MESSAGE_LEN;

/// `exit/<vault>/secret/<j>`: the secret half of the owner's j-th note, the first 31 bytes of
/// `K(label)`. It never leaves the owner's device.
///
/// # Panics
///
/// Never: 31 of `K`'s 32 bytes.
#[must_use]
pub fn note_secret(seed: &Seed, vault: Address, j: u32) -> Secret {
    let k = seed.key(&format!("exit/{}/secret/{j}", vault_label(vault)));
    Secret::new(k[..31].try_into().expect("31 of 32 bytes"))
}

/// `B(s) = P(0 || s) - P(0 || 0)`: the secret's share of a commitment's point.
#[must_use]
pub fn secret_point(s: &Secret) -> BabyJubJubPoint {
    let mut data = [0u8; 62];
    let zero = pedersen_point(&data);
    data[31..].copy_from_slice(s.as_bytes());
    pedersen_point(&data).add(&zero.neg())
}

/// What the owner gives the payer of its j-th note, like an address: the key its openings are
/// sealed to, and its secret's point. Neither opens or spends anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Receive {
    /// The opening key, compressed.
    pub key: [u8; 33],
    /// `B(s)`, packed as circomlib packs a point.
    pub secret_point: [u8; 32],
}

/// The owner's receiving address for its j-th note, under opening key `o`.
pub fn receive(seed: &Seed, vault: Address, o: u32, j: u32) -> Result<Receive, ExitError> {
    Ok(Receive {
        key: opening_key(seed, vault, o)?.public,
        secret_point: pack_point(&secret_point(&note_secret(seed, vault, j))),
    })
}

/// One member's part of a note's opening, as sealed:
/// `n_j (31) || member (1) || leaf (uint32be) || update (uint64be) || 4 zero bytes`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Part {
    pub member: u8,
    pub part: [u8; 31],
    pub leaf: u32,
    pub update: u64,
}

impl std::fmt::Debug for Part {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Part")
            .field("member", &self.member)
            .field("leaf", &self.leaf)
            .field("update", &self.update)
            .finish_non_exhaustive()
    }
}

impl Part {
    #[must_use]
    pub fn encode(&self) -> [u8; OPENING_LEN] {
        let mut out = [0u8; OPENING_LEN];
        out[..31].copy_from_slice(&self.part);
        out[31] = self.member;
        out[32..36].copy_from_slice(&self.leaf.to_be_bytes());
        out[36..44].copy_from_slice(&self.update.to_be_bytes());
        out
    }

    /// `None` if the padding is not zero.
    #[must_use]
    pub fn decode(b: &[u8; OPENING_LEN]) -> Option<Self> {
        if b[44..] != [0u8; 4] {
            return None;
        }
        Some(Self {
            part: b[..31].try_into().ok()?,
            member: b[31],
            leaf: u32::from_be_bytes(b[32..36].try_into().ok()?),
            update: u64::from_be_bytes(b[36..44].try_into().ok()?),
        })
    }
}

/// The bits of a nullifier that `member` picks.
#[must_use]
pub fn member_mask(member: usize) -> [u8; 31] {
    let (lo, hi) = WINDOWS[member];
    let mut mask = [0u8; 31];
    for bit in 4 * lo..4 * (hi + 1) {
        mask[bit / 8] |= 1 << (bit % 8);
    }
    mask
}

/// Splits a nullifier into the members' parts: what an honest committee publishes.
#[must_use]
pub fn split(n: &[u8; 31]) -> [[u8; 31]; MEMBERS] {
    std::array::from_fn(|m| {
        let mask = member_mask(m);
        std::array::from_fn(|i| n[i] & mask[i])
    })
}

/// Why an opening is garbage.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Garbage {
    #[error("the update published {0} bytes of openings, not {OPENINGS_LEN}")]
    Length(usize),
    #[error("only {0} of the {MEMBERS} parts open with the owner's key")]
    Parts(usize),
    #[error("part {0} is malformed")]
    Malformed(usize),
    #[error("part {position} names member {member}")]
    Member { position: usize, member: u8 },
    #[error("member {0}'s part has bits outside its windows")]
    Windows(usize),
    #[error("the parts name different leaves or updates")]
    Disagree,
    #[error("the parts name update {named}, published as update {published}")]
    Update { named: u64, published: u64 },
    #[error("pedersen(n || s) is not the commitment at leaf {0}")]
    Commitment(u32),
}

impl Garbage {
    /// The kind, as a word a record can carry.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Garbage::Length(_) => "length",
            Garbage::Parts(_) => "parts",
            Garbage::Malformed(_) => "malformed",
            Garbage::Member { .. } => "member",
            Garbage::Windows(_) => "windows",
            Garbage::Disagree => "disagree",
            Garbage::Update { .. } => "update",
            Garbage::Commitment(_) => "commitment",
        }
    }
}

/// The owner's view of a note from one update's openings: its nullifier, assembled, and where
/// the note sits. `Debug` shows the leaf and update only.
#[derive(Clone, PartialEq, Eq)]
pub struct Opening {
    pub nullifier: Nullifier,
    pub leaf: u32,
    pub update: u64,
}

impl std::fmt::Debug for Opening {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opening")
            .field("leaf", &self.leaf)
            .field("update", &self.update)
            .finish_non_exhaustive()
    }
}

/// One update's openings, for `key`: `None` if none of the three parts opens with it (the update
/// is someone else's), the assembled opening if all three do and agree, and garbage otherwise.
#[must_use]
pub fn assemble(
    key: &OpeningKey,
    context: &Context,
    openings: &[u8],
) -> Option<Result<Opening, Garbage>> {
    if openings.len() != OPENINGS_LEN {
        // Not ours to judge unless something of it opens.
        let any = openings
            .chunks(MESSAGE_LEN)
            .any(|m| open(key, context, m).is_some());
        return any.then_some(Err(Garbage::Length(openings.len())));
    }
    let opened: Vec<Option<[u8; OPENING_LEN]>> = openings
        .chunks(MESSAGE_LEN)
        .map(|m| open(key, context, m))
        .collect();
    let count = opened.iter().filter(|o| o.is_some()).count();
    if count == 0 {
        return None;
    }
    Some(assemble_opened(context, &opened, count))
}

fn assemble_opened(
    context: &Context,
    opened: &[Option<[u8; OPENING_LEN]>],
    count: usize,
) -> Result<Opening, Garbage> {
    if count != MEMBERS {
        return Err(Garbage::Parts(count));
    }
    let mut n = [0u8; 31];
    let mut at: Option<(u32, u64)> = None;
    for (position, plain) in opened.iter().enumerate() {
        let part = plain
            .as_ref()
            .and_then(Part::decode)
            .ok_or(Garbage::Malformed(position))?;
        if usize::from(part.member) != position {
            return Err(Garbage::Member {
                position,
                member: part.member,
            });
        }
        let mask = member_mask(position);
        if part.part.iter().zip(mask).any(|(b, m)| b & !m != 0) {
            return Err(Garbage::Windows(position));
        }
        match at {
            None => at = Some((part.leaf, part.update)),
            Some(x) if x != (part.leaf, part.update) => return Err(Garbage::Disagree),
            Some(_) => {}
        }
        for (b, p) in n.iter_mut().zip(part.part) {
            *b |= p;
        }
    }
    let (leaf, update) = at.expect("three parts");
    if update != context.update {
        return Err(Garbage::Update {
            named: update,
            published: context.update,
        });
    }
    Ok(Opening {
        nullifier: Nullifier::new(n),
        leaf,
        update,
    })
}

/// The note, if the opening and the owner's secret make the commitment the vault holds at the
/// opening's leaf.
pub fn check(
    opening: &Opening,
    secret: &Secret,
    commitment_at_leaf: Field,
) -> Result<Note, Garbage> {
    let note = Note::new(opening.nullifier, *secret);
    if note.commitment() == commitment_at_leaf {
        Ok(note)
    } else {
        Err(Garbage::Commitment(opening.leaf))
    }
}
