//! The frame container: how a device reviews a type-0x06 transaction, or the execution digest's
//! typed data, from what it is given and the descriptors, without the account's code.
//!
//! Of the six things ERC-7730 has no place for, five follow from the transaction by EIP-8141's
//! rules, with no descriptor: what the signature covers, the `VERIFY` frames' allowed scopes,
//! the payer and the maximum cost, the atomic batches and the nonce, read under the fork's
//! EIP-8250 revision. The sixth splits: the expiry frame is the protocol's, but a deploy frame
//! needs its deployer's descriptor, because its calldata is not ABI.
//!
//! The account's own code enters twice. What its `VERIFY` frame does with a signature matters
//! when the signature is not over the whole transaction, as with E; and the calls it makes to
//! itself are its own. Both come from its account descriptor. `SENDER` and `DEFAULT` frames to
//! other contracts take those contracts' ERC-7730 files unchanged, with `@.from` the sender or
//! the entry point by mode, `@.to` the frame's target and `@.value` its value.

use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use kohaku_frame_kit::{
    Eip8250, FrameTx,
    constants::{ATOMIC_BATCH_FLAG, ENTRY_POINT, EXPIRY_VERIFIER, approve, mode, scheme},
    digest::{execution_digest, is_pay_frame, nonce_keys_hash},
    gas,
    tx::Frame,
};

use crate::{
    descriptor::{AccountDescriptor, Format, Metadata, MsgRule, SignerRule, VerifyRule, json_val},
    format::{self, Applied, Book, Container, date, ether},
    registry::Registry,
    review::{Gap, GapKind, Line, Review, Section, Signs},
    typed::ExecutionMessage,
    value::{LayoutError, Val, Values},
};

/// The fork's rules a device must know: they are not in any descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rules {
    pub eip8250: Eip8250,
    pub expiry_verifier: Address,
}

impl Rules {
    /// The ethrex Hegota testnet: EIP-8250 at `f3079a09e8`, the expiry verifier at `0x8141`.
    pub const HEGOTA_TESTNET: Self = Self {
        eip8250: Eip8250::F3079a0,
        expiry_verifier: EXPIRY_VERIFIER,
    };

    /// EIP-8250 at master `1a086d5c`, with the testnet's expiry verifier.
    pub const EIP8250_MASTER: Self = Self {
        eip8250: Eip8250::Master,
        expiry_verifier: EXPIRY_VERIFIER,
    };

    /// The nonce keys that select the account's legacy nonce.
    #[must_use]
    pub fn legacy_keys(self) -> Vec<U256> {
        match self.eip8250 {
            Eip8250::F3079a0 => vec![U256::ZERO],
            Eip8250::Master => Vec::new(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RenderError {
    #[error("the transaction has no signature entry {0}")]
    Entry(usize),
}

/// The nonce, as the device has it.
enum Nonce {
    Keys(Vec<U256>),
    Hash(B256),
}

/// Everything a review reads, from a transaction or from typed data.
struct View<'a> {
    chain_id: u64,
    sender: Address,
    nonce: Nonce,
    nonce_seq: u64,
    frames: Vec<Frame>,
    blobs: Vec<B256>,
    /// The transaction, when the device has it: fees, payer frame, other entries.
    tx: Option<&'a FrameTx>,
    signs: Signs,
    /// The entry signed, and its resolved signer, when the device has the transaction.
    entry: Option<(usize, Address, u8)>,
}

impl View<'_> {
    fn msg(&self) -> Option<MsgRule> {
        match self.signs {
            Signs::SigHash { .. } => Some(MsgRule::SigHash),
            Signs::ExecutionDigest { .. } => Some(MsgRule::FrameExecution),
            Signs::Opaque { .. } => None,
        }
    }

    fn target(&self, f: &Frame) -> Address {
        f.target.unwrap_or(self.sender)
    }
}

/// How the device knows what the sender runs.
enum Binding<'a> {
    Account {
        desc: &'a AccountDescriptor,
        args: Values,
        via: String,
    },
    /// The sender is the signing key's own address: EIP-8141's default code.
    DefaultCode,
    Unknown,
}

impl Binding<'_> {
    fn owner(&self) -> Option<Address> {
        let Self::Account { args, .. } = self else {
            return None;
        };
        args.iter().find_map(|(n, v)| match (n.as_str(), v) {
            ("owner", Val::Address(a)) => Some(*a),
            _ => None,
        })
    }
}

/// Names the sender "your account"; everything else as the registry does.
struct SenderBook<'a> {
    registry: &'a Registry,
    sender: Address,
}

impl Book for SenderBook<'_> {
    fn name(&self, chain_id: u64, a: Address) -> Option<String> {
        if a == self.sender {
            return Some("your account".to_owned());
        }
        if a == ENTRY_POINT {
            return Some("the entry point".to_owned());
        }
        self.registry.name(chain_id, a)
    }

    fn token(&self, chain_id: u64, a: Address) -> Option<&crate::descriptor::Token> {
        self.registry.token(chain_id, a)
    }
}

struct Out {
    lines: Vec<Line>,
    gaps: Vec<Gap>,
    intents: Vec<String>,
}

impl Out {
    fn line(
        &mut self,
        section: Section,
        frame: Option<usize>,
        label: &str,
        value: impl Into<String>,
        source: impl Into<String>,
    ) {
        self.lines.push(Line {
            section,
            frame,
            label: label.to_owned(),
            value: value.into(),
            source: source.into(),
        });
    }

    fn gap(&mut self, frame: Option<usize>, kind: GapKind, blind: bool, why: impl Into<String>) {
        self.gaps.push(Gap {
            frame,
            kind,
            blind,
            why: why.into(),
        });
    }
}

/// Review signature entry `entry` of `tx`, as the device holding that entry's key would.
pub fn render(
    tx: &FrameTx,
    entry: usize,
    registry: &Registry,
    rules: Rules,
) -> Result<Review, RenderError> {
    let sig = tx.signatures.get(entry).ok_or(RenderError::Entry(entry))?;
    let signer = sig.signer.unwrap_or(tx.sender);
    let signs = if sig.msg.is_empty() {
        Signs::SigHash {
            hash: tx.sig_hash(),
        }
    } else if sig.msg.as_ref() == execution_digest(tx).as_slice() {
        Signs::ExecutionDigest {
            digest: execution_digest(tx),
        }
    } else {
        Signs::Opaque {
            msg: sig.msg.clone(),
        }
    };
    let view = View {
        chain_id: tx.chain_id,
        sender: tx.sender,
        nonce: Nonce::Keys(tx.nonce_keys.clone()),
        nonce_seq: tx.nonce_seq,
        frames: tx.frames.clone(),
        blobs: tx.blob_versioned_hashes.clone(),
        tx: Some(tx),
        signs,
        entry: Some((entry, signer, sig.scheme)),
    };
    Ok(review(&view, registry, rules))
}

/// Review a `FrameExecution` message given as typed data alone, without the transaction.
#[must_use]
pub fn render_typed(message: &ExecutionMessage, registry: &Registry, rules: Rules) -> Review {
    let view = View {
        chain_id: message.chain_id,
        sender: message.sender,
        nonce: Nonce::Hash(message.nonce_keys_hash),
        nonce_seq: message.nonce_seq,
        frames: message.frames.clone(),
        blobs: message.blob_versioned_hashes.clone(),
        tx: None,
        signs: Signs::ExecutionDigest {
            digest: message.digest,
        },
        entry: None,
    };
    review(&view, registry, rules)
}

fn review(view: &View<'_>, registry: &Registry, rules: Rules) -> Review {
    let book = SenderBook {
        registry,
        sender: view.sender,
    };
    let mut out = Out {
        lines: Vec::new(),
        gaps: Vec::new(),
        intents: Vec::new(),
    };
    let binding = bind(view, registry);
    signature(view, &binding, &book, &mut out);
    account(view, &binding, &mut out);
    nonce(view, rules, &mut out);
    validation(view, &binding, &book, rules, &mut out);
    payment(view, &book, &mut out);
    execution(view, &binding, registry, &book, &mut out);
    blobs(view, &mut out);
    let intent = if out.intents.is_empty() {
        "No calls".to_owned()
    } else {
        out.intents.join(" and ")
    };
    Review {
        signs: view.signs.clone(),
        intent,
        lines: out.lines,
        gaps: out.gaps,
    }
}

fn scheme_name(s: u8) -> &'static str {
    match s {
        scheme::SECP256K1 => "secp256k1",
        scheme::P256 => "P256",
        scheme::ARBITRARY => "arbitrary",
        _ => "unknown scheme",
    }
}

fn scope_name(s: u8) -> &'static str {
    match s & approve::SCOPE_MASK {
        approve::PAYMENT => "payment",
        approve::EXECUTION => "execution",
        approve::EXECUTION_AND_PAYMENT => "execution and payment",
        _ => "nothing",
    }
}

fn short(b: B256) -> String {
    let h = b.to_string();
    format!("{}...{}", &h[..10], &h[h.len() - 4..])
}

fn name(book: &dyn Book, chain_id: u64, a: Address) -> String {
    book.name(chain_id, a)
        .unwrap_or_else(|| a.to_checksum(None))
}

fn signature(view: &View<'_>, binding: &Binding<'_>, book: &dyn Book, out: &mut Out) {
    const EIP: &str = "EIP-8141";
    match &view.signs {
        Signs::SigHash { hash } => out.line(Section::Signature, None, "Signs", format!("the whole transaction: every frame, the fees and who else signs (signature hash {})", short(*hash)), EIP),
        Signs::ExecutionDigest { digest } => out.line(
            Section::Signature,
            None,
            "Signs",
            format!("the execution digest E: every frame but the payer's, and not the fees ({})", short(*digest)),
            "FrameExecution, exp-frames experiment 27",
        ),
        Signs::Opaque { msg } => {
            out.line(Section::Signature, None, "Signs", format!("an explicit digest 0x{}", alloy::primitives::hex::encode(msg)), EIP);
            out.gap(None, GapKind::Opaque, true, "the entry's msg is neither empty nor this transaction's E, so the device cannot tell what it commits to");
        }
    }
    if let Some((i, signer, s)) = view.entry {
        let who = if signer == view.sender {
            "the account's own key".to_owned()
        } else if Some(signer) == binding.owner() {
            format!("the owner key {}", signer.to_checksum(None))
        } else {
            name(book, view.chain_id, signer)
        };
        out.line(
            Section::Signature,
            None,
            "Signer",
            format!("{who}, entry {i}, {}", scheme_name(s)),
            EIP,
        );
    }
    if let Some(tx) = view.tx {
        for (j, s) in tx.signatures.iter().enumerate() {
            if Some(j) == view.entry.map(|e| e.0) {
                continue;
            }
            let over = if s.msg.is_empty() {
                "the signature hash"
            } else {
                "an explicit digest"
            };
            let who = name(book, view.chain_id, s.signer.unwrap_or(tx.sender));
            out.line(
                Section::Signature,
                None,
                "Also signed by",
                format!("{who}, entry {j}, over {over}"),
                EIP,
            );
        }
    }
}

/// The deploy frame that deploys the sender, if any: its index, the descriptor its code
/// matches, and the arguments.
fn deploy_of_sender<'a>(
    view: &View<'_>,
    registry: &'a Registry,
) -> Option<(usize, Option<(&'a AccountDescriptor, Values)>)> {
    view.frames.iter().enumerate().find_map(|(i, f)| {
        if f.mode == mode::VERIFY {
            return None;
        }
        let to = view.target(f);
        let d = registry.deployer(view.chain_id, to)?;
        let (salt, initcode) = d.split(&f.data)?;
        (to.create2(salt, keccak256(initcode)) == view.sender).then(|| {
            (
                i,
                registry
                    .accounts
                    .iter()
                    .find_map(|a| a.match_initcode(initcode).map(|args| (a, args))),
            )
        })
    })
}

fn bind<'a>(view: &View<'_>, registry: &'a Registry) -> Binding<'a> {
    if let Some((i, Some((desc, args)))) = deploy_of_sender(view, registry) {
        return Binding::Account {
            desc,
            args,
            via: format!("deployed by frame {i}"),
        };
    }
    if let Some(w) = registry.wallet_account(view.chain_id, view.sender)
        && let Some(desc) = registry.implementation(&w.implementation)
    {
        let args = w
            .args
            .iter()
            .filter_map(|(k, v)| json_val(v).map(|v| (k.clone(), v)))
            .collect();
        return Binding::Account {
            desc,
            args,
            via: "in your wallet's accounts".to_owned(),
        };
    }
    match view.entry {
        Some((_, signer, _)) if signer == view.sender => Binding::DefaultCode,
        _ => Binding::Unknown,
    }
}

fn account(view: &View<'_>, binding: &Binding<'_>, out: &mut Out) {
    let sender = view.sender.to_checksum(None);
    let (value, source) = match binding {
        Binding::Account { desc, via, .. } => {
            let owner = binding
                .owner()
                .map(|o| format!(", owner {}", o.to_checksum(None)))
                .unwrap_or_default();
            (
                format!("{sender}: {}{owner}, {via}", desc.id()),
                format!("account: {}", desc.id()),
            )
        }
        Binding::DefaultCode => (
            format!(
                "{sender}: no code, so EIP-8141's default code, assuming the key signed no EIP-7702 delegation"
            ),
            "EIP-8141".to_owned(),
        ),
        Binding::Unknown => (
            format!("{sender}: no descriptor binds it"),
            "raw".to_owned(),
        ),
    };
    out.line(Section::Account, None, "Account", value, source);
    out.line(
        Section::Account,
        None,
        "Chain",
        view.chain_id.to_string(),
        "EIP-8141",
    );
}

fn nonce(view: &View<'_>, rules: Rules, out: &mut Out) {
    let legacy = rules.legacy_keys();
    let revision = match rules.eip8250 {
        Eip8250::F3079a0 => "EIP-8250 at f3079a09e8",
        Eip8250::Master => "EIP-8250 at 1a086d5c",
    };
    let seq = view.nonce_seq;
    match &view.nonce {
        Nonce::Keys(keys) if *keys == legacy => out.line(
            Section::Nonce,
            None,
            "Nonce",
            format!("the account nonce, {seq}"),
            revision,
        ),
        Nonce::Keys(keys) => {
            let list = keys
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            out.line(
                Section::Nonce,
                None,
                "Nonce",
                format!("keys [{list}] at sequence {seq}, in NONCE_MANAGER"),
                revision,
            );
        }
        Nonce::Hash(h) if *h == nonce_keys_hash(&legacy) => out.line(
            Section::Nonce,
            None,
            "Nonce",
            format!("the account nonce, {seq}"),
            revision,
        ),
        Nonce::Hash(h) => {
            out.line(
                Section::Nonce,
                None,
                "Nonce",
                format!("keys with hash {} at sequence {seq}", short(*h)),
                revision,
            );
            out.gap(None, GapKind::HashOnly, false, "the typed data carries the nonce keys' hash, not the keys: the device can name the replay domain only if the wallet sends the keys beside it");
        }
    }
}

fn validation(
    view: &View<'_>,
    binding: &Binding<'_>,
    book: &dyn Book,
    rules: Rules,
    out: &mut Out,
) {
    for (i, f) in view.frames.iter().enumerate() {
        if f.mode != mode::VERIFY {
            continue;
        }
        let allowed = f.flags & approve::SCOPE_MASK;
        let target = view.target(f);
        if target == rules.expiry_verifier {
            match <[u8; 8]>::try_from(f.data.as_ref()) {
                Ok(d) if allowed == 0 => out.line(
                    Section::Validation,
                    Some(i),
                    "Valid until",
                    date(U256::from(u64::from_be_bytes(d))),
                    "EIP-8141 expiry verifier",
                ),
                _ => out.line(
                    Section::Validation,
                    Some(i),
                    "Expiry",
                    "malformed: the transaction is invalid",
                    "EIP-8141 expiry verifier",
                ),
            }
        } else if is_pay_frame(f) && view.tx.is_none() {
            out.line(
                Section::Validation,
                Some(i),
                "Pay frame",
                "a payer approves payment; who, and its limits and data, are not signed",
                "FrameExecution, exp-frames experiment 27",
            );
        } else if target == view.sender {
            sender_verify(view, binding, i, allowed, out);
        } else if allowed & approve::PAYMENT != 0 {
            out.line(
                Section::Validation,
                Some(i),
                "Payer approves",
                name(book, view.chain_id, target),
                "EIP-8141",
            );
        } else {
            out.line(
                Section::Validation,
                Some(i),
                "Checked by",
                format!(
                    "{}, which approves nothing",
                    name(book, view.chain_id, target)
                ),
                "EIP-8141",
            );
        }
    }
}

fn rule_for(
    desc: &AccountDescriptor,
    owner: Option<Address>,
    entry: usize,
    signer: Option<Address>,
    msg: MsgRule,
) -> Option<&VerifyRule> {
    desc.verify.iter().find(|r| {
        r.entry == entry
            && r.msg == msg
            && match (r.signer, signer) {
                (SignerRule::Owner, Some(s)) => Some(s) == owner,
                (SignerRule::Other, Some(s)) => Some(s) != owner,
                // From typed data alone the device does not know which key signs; it signs as
                // the owner, the one key whose signature over E an account accepts here.
                (SignerRule::Owner, None) => true,
                (SignerRule::Other, None) => false,
            }
    })
}

fn sender_verify(view: &View<'_>, binding: &Binding<'_>, i: usize, allowed: u8, out: &mut Out) {
    let entry = view.entry.map_or(0, |e| e.0);
    let signer = view.entry.map(|e| e.1);
    let may = format!("your account; it may approve {}", scope_name(allowed));
    match binding {
        Binding::DefaultCode => {
            let read = usize::from(allowed & approve::EXECUTION == 0);
            out.line(Section::Validation, Some(i), "Approves", may, "EIP-8141");
            let reads_ours = read == entry;
            let ok = matches!(view.signs, Signs::SigHash { .. })
                && view.entry.is_some_and(|e| e.2 == scheme::SECP256K1);
            if reads_ours && ok {
                out.line(
                    Section::Validation,
                    Some(i),
                    "With",
                    "your secp256k1 signature over the signature hash (default code)",
                    "EIP-8141",
                );
            } else if reads_ours {
                out.gap(Some(i), GapKind::Refusal, false, "the default code accepts only a secp256k1 entry with an empty msg: this signature cannot approve");
            }
        }
        Binding::Account { desc, .. } => {
            let source = format!("account: {}", desc.id());
            out.line(Section::Validation, Some(i), "Approves", may, "EIP-8141");
            let Some(msg) = view.msg() else { return };
            match rule_for(desc, binding.owner(), entry, signer, msg) {
                Some(rule) => {
                    out.line(
                        Section::Validation,
                        Some(i),
                        "With",
                        rule.intent.clone(),
                        source.clone(),
                    );
                    if let Some(req) = &rule.requires {
                        out.line(
                            Section::Validation,
                            Some(i),
                            "Also checks",
                            req.clone(),
                            source.clone(),
                        );
                    }
                    if !rule.can_approve(allowed) {
                        out.gap(Some(i), GapKind::Refusal, false, format!("{} approves no {} on this signature: the transaction will be refused", desc.id(), scope_name(allowed)));
                    }
                    if let Some(state) = &rule.state {
                        out.gap(Some(i), GapKind::State, false, format!("the account checks {state}; the device has none of it, and the account enforces it"));
                    }
                }
                None if desc.verify.iter().any(|r| r.entry == entry) => {
                    out.gap(
                        Some(i),
                        GapKind::Refusal,
                        false,
                        format!(
                            "no rule of {} approves this signer's {msg:?} signature",
                            desc.id()
                        ),
                    );
                }
                None => out.line(
                    Section::Validation,
                    Some(i),
                    "With",
                    format!("{} does not read your entry", desc.id()),
                    source,
                ),
            }
        }
        Binding::Unknown => {
            out.line(Section::Validation, Some(i), "Approves", may, "EIP-8141");
            if !matches!(view.signs, Signs::SigHash { .. }) {
                out.gap(Some(i), GapKind::Account, true, "no descriptor says this account reads E: a 32-byte msg means whatever the account's code makes it mean");
            }
        }
    }
}

fn payment(view: &View<'_>, book: &dyn Book, out: &mut Out) {
    let value: U256 = view
        .frames
        .iter()
        .filter(|f| f.mode == mode::SENDER)
        .map(|f| f.value)
        .sum();
    if !value.is_zero() {
        out.line(
            Section::Payment,
            None,
            "Value sent",
            format!("{} from your account", ether(value)),
            "EIP-8141",
        );
    }
    let Some(tx) = view.tx else {
        out.line(
            Section::Payment,
            None,
            "Payer and fees",
            "not signed: whoever completes the transaction chooses and pays them",
            "FrameExecution, exp-frames experiment 27",
        );
        return;
    };
    let payer = tx
        .frames
        .iter()
        .find(|f| f.mode == mode::VERIFY && f.flags & approve::PAYMENT != 0)
        .map(|f| f.target.unwrap_or(tx.sender));
    let max = gas::max_cost(tx, tx.fees.max_fee_per_blob_gas);
    let cost = match max {
        Ok(c) => format!(
            "at most {} ({} gas at up to {} gwei)",
            ether(c),
            gas::max_gas(tx).unwrap_or_default(),
            format::decimal(U256::from(tx.fees.max_fee_per_gas), 9)
        ),
        Err(e) => format!("unknown: {e}"),
    };
    let who = match payer {
        Some(p) if p == tx.sender => "your account".to_owned(),
        Some(p) => format!("{}; you pay no gas", name(book, tx.chain_id, p)),
        None => "none: no frame may approve payment, so the transaction is invalid".to_owned(),
    };
    if matches!(view.signs, Signs::ExecutionDigest { .. }) {
        out.line(
            Section::Payment,
            None,
            "Payer",
            format!("not signed: any payer may complete it (here {who})"),
            "FrameExecution, exp-frames experiment 27",
        );
        out.line(
            Section::Payment,
            None,
            "Fees",
            format!("not signed (here {cost}, paid by the payer)"),
            "FrameExecution, exp-frames experiment 27",
        );
    } else {
        out.line(Section::Payment, None, "Payer", who, "EIP-8141");
        out.line(Section::Payment, None, "Max fee", cost, "EIP-8141");
    }
}

/// The atomic batches: maximal runs `[i, j]` where frames `i..j` carry the flag.
fn batches(frames: &[Frame]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, f) in frames.iter().enumerate() {
        let flagged = f.flags & ATOMIC_BATCH_FLAG != 0 && f.mode != mode::VERIFY;
        match (start, flagged) {
            (None, true) => start = Some(i),
            (Some(s), false) => {
                out.push((s, i));
                start = None;
            }
            _ => {}
        }
    }
    out
}

/// The validation prefix's end: the first frame that may approve payment, inclusive.
fn prefix_end(frames: &[Frame]) -> usize {
    frames
        .iter()
        .position(|f| f.mode == mode::VERIFY && f.flags & approve::PAYMENT != 0)
        .map_or(frames.len(), |i| i + 1)
}

fn execution(
    view: &View<'_>,
    binding: &Binding<'_>,
    registry: &Registry,
    book: &SenderBook<'_>,
    out: &mut Out,
) {
    let calls: Vec<usize> = (0..view.frames.len())
        .filter(|&i| view.frames[i].mode != mode::VERIFY)
        .collect();
    for &i in &calls {
        call(view, binding, registry, book, i, out);
    }
    let end = prefix_end(&view.frames);
    let (prefix, after): (Vec<usize>, Vec<usize>) = calls.iter().partition(|&&i| i < end);
    if !prefix.is_empty() {
        let list = prefix
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        out.line(
            Section::Execution,
            None,
            "Before payment",
            format!("frame {list} runs in the validation prefix, before a payer is approved"),
            "EIP-8141",
        );
    }
    let groups = batches(&view.frames);
    for (s, e) in &groups {
        out.line(
            Section::Execution,
            None,
            "Atomic",
            format!("frames {s} to {e} all succeed or all revert"),
            "EIP-8141",
        );
    }
    let alone: Vec<String> = after
        .iter()
        .filter(|&&i| !groups.iter().any(|(s, e)| (*s..=*e).contains(&i)))
        .map(ToString::to_string)
        .collect();
    if after.len() > 1 && alone.len() > 1 {
        out.line(
            Section::Execution,
            None,
            "Independent",
            format!(
                "frames {} each stand alone: one can fail while the others succeed",
                alone.join(", ")
            ),
            "EIP-8141",
        );
    }
}

fn applied(out: &mut Out, i: usize, a: Applied, source: &str) {
    for (label, value) in a.fields {
        out.line(Section::Execution, Some(i), &label, value, source);
    }
    out.intents.push(a.intent);
}

fn call(
    view: &View<'_>,
    binding: &Binding<'_>,
    registry: &Registry,
    book: &SenderBook<'_>,
    i: usize,
    out: &mut Out,
) {
    let f = &view.frames[i];
    let to = view.target(f);
    let from = if f.mode == mode::SENDER {
        view.sender
    } else {
        ENTRY_POINT
    };
    let container = Container {
        chain_id: view.chain_id,
        from,
        to,
        value: f.value,
    };
    let caller = if f.mode == mode::SENDER {
        "SENDER, as your account"
    } else {
        "DEFAULT, as the entry point, not your account"
    };
    out.line(
        Section::Execution,
        Some(i),
        "Runs",
        format!("{caller}, calling {}", name(book, view.chain_id, to)),
        "EIP-8141",
    );
    if f.mode == mode::SENDER && !f.value.is_zero() {
        out.line(
            Section::Execution,
            Some(i),
            "Value",
            ether(f.value),
            "EIP-8141",
        );
    }

    if let Some(d) = registry.deployer(view.chain_id, to)
        && let Some((salt, initcode)) = d.split(&f.data)
    {
        deploy(
            view,
            registry,
            i,
            to.create2(salt, keccak256(initcode)),
            initcode,
            &d.context.id,
            out,
        );
        return;
    }
    if f.data.is_empty() {
        let what = if f.value.is_zero() {
            format!("Call {} with no data", name(book, view.chain_id, to))
        } else {
            format!(
                "Send {} to {}",
                ether(f.value),
                name(book, view.chain_id, to)
            )
        };
        out.intents.push(what);
        return;
    }
    let shown = if to == view.sender {
        match binding {
            Binding::Account { desc, .. } if f.mode == mode::SENDER => select(
                desc.select(&f.data),
                container,
                &desc.metadata,
                book,
                desc.id(),
                "this call to itself",
            )
            .map(|a| (a, format!("account: {}", desc.id()))),
            _ => Err("a call to your own account that no account descriptor describes".to_owned()),
        }
    } else if let Some(d) = registry.contract(view.chain_id, to) {
        let selector = alloy::primitives::hex::encode(&f.data[..f.data.len().min(4)]);
        select(
            d.select(&f.data),
            container,
            &d.metadata,
            book,
            d.id(),
            &format!("selector 0x{selector}"),
        )
        .map(|a| (a, format!("ERC-7730: {}", d.id())))
    } else {
        Err(format!("no ERC-7730 file binds {}", to.to_checksum(None)))
    };
    match shown {
        Ok((a, source)) => applied(out, i, a, &source),
        Err(why) => fallback(out, i, &f.data, why),
    }
}

/// A descriptor's selected format, applied; or why the data stays raw.
fn select(
    selected: Result<Option<(&Format, Values)>, LayoutError>,
    container: Container,
    metadata: &Metadata,
    book: &dyn Book,
    id: &str,
    what: &str,
) -> Result<Applied, String> {
    match selected {
        Ok(Some((fmt, values))) => {
            format::apply(fmt, &values, container, metadata, book).map_err(|e| format!("{id}: {e}"))
        }
        Ok(None) => Err(format!("{id} has no format for {what}")),
        Err(e) => Err(format!("{id}: {e}")),
    }
}

/// ERC-7730's fallback: the raw data, and a gap.
fn fallback(out: &mut Out, i: usize, data: &Bytes, why: String) {
    let hex = alloy::primitives::hex::encode(data);
    let shown = if hex.len() > 72 {
        format!("0x{}... ({} bytes)", &hex[..72], data.len())
    } else {
        format!("0x{hex}")
    };
    out.line(Section::Execution, Some(i), "Data", shown, "raw");
    out.intents.push(format!("Unknown call in frame {i}"));
    out.gap(Some(i), GapKind::NoDescriptor, true, why);
}

fn deploy(
    view: &View<'_>,
    registry: &Registry,
    i: usize,
    at: Address,
    initcode: &[u8],
    deployer: &str,
    out: &mut Out,
) {
    let source = format!("deployer: {deployer}");
    let matched = registry
        .accounts
        .iter()
        .find_map(|a| a.match_initcode(initcode).map(|args| (a, args)));
    let whose = if at == view.sender {
        "your account".to_owned()
    } else {
        at.to_checksum(None)
    };
    if let Some((desc, args)) = matched {
        let shown: Vec<String> = args
            .iter()
            .map(|(n, v)| format!("{n} {}", v.raw()))
            .collect();
        out.line(
            Section::Execution,
            Some(i),
            "Deploys",
            format!("{whose}: {} with {}", desc.id(), shown.join(", ")),
            source,
        );
        out.intents.push(format!("Deploy {whose} as {}", desc.id()));
    } else {
        out.line(
            Section::Execution,
            Some(i),
            "Deploys",
            format!(
                "{whose}: code with initcode hash {}",
                short(keccak256(initcode))
            ),
            source,
        );
        out.intents.push(format!("Deploy {whose}"));
        out.gap(
            Some(i),
            GapKind::NoDescriptor,
            at == view.sender,
            "no account descriptor matches the initcode",
        );
    }
}

fn blobs(view: &View<'_>, out: &mut Out) {
    if view.blobs.is_empty() {
        return;
    }
    let list = view
        .blobs
        .iter()
        .map(|b| short(*b))
        .collect::<Vec<_>>()
        .join(", ");
    out.line(
        Section::Blobs,
        None,
        "Blobs",
        format!("{}: {list}", view.blobs.len()),
        "EIP-8141",
    );
    out.gap(None, GapKind::NotInTransaction, false, "the blobs' contents travel beside the transaction; the frames see only their versioned hashes");
}
