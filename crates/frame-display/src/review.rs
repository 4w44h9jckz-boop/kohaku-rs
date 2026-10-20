//! What a device shows: the lines of a review, and the gaps, what it could not show and why.

use std::fmt::Write as _;

use alloy::primitives::{B256, Bytes};
use serde::Serialize;

/// What the signature commits to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Signs {
    /// The canonical signature hash: every frame, the fees and the other entries.
    SigHash { hash: B256 },
    /// The execution digest E: every frame but the payer's, and no fees.
    ExecutionDigest { digest: B256 },
    /// A 32-byte `msg` the device cannot derive from what it was given.
    Opaque { msg: Bytes },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum Section {
    Signature,
    Account,
    Nonce,
    Validation,
    Payment,
    Execution,
    Blobs,
}

/// One line of the review.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Line {
    pub section: Section,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<usize>,
    pub label: String,
    pub value: String,
    /// Where the line comes from: `EIP-8141`, `EIP-8250`, an ERC-7730 file's `$id`, an account
    /// or deployer descriptor, the wallet's own data, or `raw` when nothing describes it.
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum GapKind {
    /// A frame's target, or its function, has no descriptor: the data is shown raw.
    NoDescriptor,
    /// Only a hash of the value is in what the device was given.
    HashOnly,
    /// The transaction commits to it but does not carry it.
    NotInTransaction,
    /// It is in account storage.
    State,
    /// The device cannot tell what the signature commits to.
    Opaque,
    /// No descriptor binds the sender, and the signature is not over the whole transaction.
    Account,
    /// The account's descriptor says it will refuse the transaction.
    Refusal,
}

/// Something the device could not show.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<usize>,
    pub kind: GapKind,
    /// Whether, because of it, the signer cannot tell what their signature allows. A gap that is
    /// not blind is context the account or the protocol enforces anyway.
    pub blind: bool,
    pub why: String,
}

/// A device's review of one signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Review {
    pub signs: Signs,
    /// The execution frames' intents, joined with " and " as ERC-7730 joins a batch.
    pub intent: String,
    pub lines: Vec<Line>,
    pub gaps: Vec<Gap>,
}

impl Review {
    /// The gaps that leave the signer blind.
    pub fn blind(&self) -> impl Iterator<Item = &Gap> {
        self.gaps.iter().filter(|g| g.blind)
    }

    /// The review as a device would list it.
    #[must_use]
    pub fn to_text(&self) -> String {
        let mut out = format!("  intent: {}\n", self.intent);
        let mut section = None;
        for l in &self.lines {
            if section != Some(l.section) {
                section = Some(l.section);
                let _ = writeln!(out, "  [{:?}]", l.section);
            }
            let frame = l.frame.map(|f| format!("frame {f}: ")).unwrap_or_default();
            let _ = writeln!(out, "    {frame}{}: {}   ({})", l.label, l.value, l.source);
        }
        for g in &self.gaps {
            let frame = g.frame.map(|f| format!("frame {f}: ")).unwrap_or_default();
            let blind = if g.blind { "BLIND " } else { "" };
            let _ = writeln!(out, "  gap: {blind}{:?}: {frame}{}", g.kind, g.why);
        }
        out
    }
}
