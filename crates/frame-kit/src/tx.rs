//! The type-0x06 envelope: types, RLP, the transaction hash and the signature hash.
//!
//! ```text
//! 0x06 || rlp([chain_id, nonce_keys, nonce_seq, sender, frames, signatures, fees,
//!              blob_versioned_hashes])
//! frame     = [mode, flags, target, [limits.execution, limits.state], value, data]
//! signature = [scheme, signer, msg, signature]
//! fees      = [max_priority_fee_per_gas, max_fee_per_gas, max_fee_per_blob_gas]
//! ```
//!
//! An empty `target` or `signer` resolves to `tx.sender`.

use alloy::{
    primitives::{Address, B256, Bytes, U256, keccak256},
    rlp::{self, BufMut, Decodable, Encodable, Header},
};

use crate::constants::{ATOMIC_BATCH_FLAG, FRAME_TX_TYPE, approve, mode};

/// A frame's two gas budgets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameLimits {
    /// Execution-gas budget (`limits.execution`).
    pub execution: u64,
    /// EIP-8037 state-gas budget (`limits.state`).
    pub state: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frame {
    pub mode: u8,
    pub flags: u8,
    /// `None` resolves to `tx.sender`.
    pub target: Option<Address>,
    pub limits: FrameLimits,
    pub value: U256,
    pub data: Bytes,
}

impl Frame {
    /// A `VERIFY` frame that may `APPROVE` with `scope`. `target: None` is the sender's own code.
    #[must_use]
    pub fn verify(scope: u8, target: Option<Address>) -> Self {
        Self {
            mode: mode::VERIFY,
            flags: scope & approve::SCOPE_MASK,
            target,
            ..Self::default()
        }
    }

    /// A `SENDER` frame: runs with `caller = tx.sender`.
    #[must_use]
    pub fn sender(target: Option<Address>) -> Self {
        Self {
            mode: mode::SENDER,
            target,
            ..Self::default()
        }
    }

    /// A `DEFAULT` frame: runs with `caller = ENTRY_POINT`.
    #[must_use]
    pub fn entry_point(target: Option<Address>) -> Self {
        Self {
            mode: mode::DEFAULT,
            target,
            ..Self::default()
        }
    }

    /// The expiry verifier: invalidates the transaction once `block.timestamp > deadline`.
    #[must_use]
    pub fn expiry(deadline: u64) -> Self {
        Self::verify(approve::NONE, Some(crate::constants::EXPIRY_VERIFIER))
            .with_execution(5_000)
            .with_data(deadline.to_be_bytes().to_vec())
    }

    #[must_use]
    pub fn with_execution(mut self, gas: u64) -> Self {
        self.limits.execution = gas;
        self
    }

    #[must_use]
    pub fn with_state(mut self, gas: u64) -> Self {
        self.limits.state = gas;
        self
    }

    #[must_use]
    pub fn with_value(mut self, value: U256) -> Self {
        self.value = value;
        self
    }

    #[must_use]
    pub fn with_data(mut self, data: impl Into<Bytes>) -> Self {
        self.data = data.into();
        self
    }

    /// Chain this frame with the next: if either reverts, both are reverted.
    #[must_use]
    pub fn atomic(mut self) -> Self {
        self.flags |= ATOMIC_BATCH_FLAG;
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameSignature {
    pub scheme: u8,
    /// `None` resolves to `tx.sender`; must be `None` for `ARBITRARY`.
    pub signer: Option<Address>,
    /// Empty: the entry signs the signature hash. Otherwise an explicit 32-byte digest.
    pub msg: Bytes,
    /// `SECP256K1`: `y_parity || r || s`. `P256`: `r || s || qx || qy`.
    pub signature: Bytes,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Fees {
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub max_fee_per_blob_gas: u128,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrameTx {
    pub chain_id: u64,
    /// EIP-8250 nonce keys. `[0]` is the legacy account nonce.
    pub nonce_keys: Vec<U256>,
    pub nonce_seq: u64,
    pub sender: Address,
    pub frames: Vec<Frame>,
    pub signatures: Vec<FrameSignature>,
    pub fees: Fees,
    pub blob_versioned_hashes: Vec<B256>,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("not a type-0x06 transaction")]
    NotFrameTx,
    #[error("RLP: {0}")]
    Rlp(#[from] rlp::Error),
    #[error("{0}: expected a list")]
    ExpectedList(&'static str),
    #[error("{0}: trailing bytes")]
    Trailing(&'static str),
    #[error("{0}: expected an empty string or 20 bytes, got {1} bytes")]
    Address(&'static str, usize),
    #[error("sender is empty")]
    EmptySender,
}

// ---- encoding ----

/// Collects the RLP items of one list, then writes them behind their header.
#[derive(Default)]
struct List(Vec<u8>);

impl List {
    fn item(mut self, item: &(impl Encodable + ?Sized)) -> Self {
        item.encode(&mut self.0);
        self
    }

    /// Append `items` as one nested list.
    fn items<T: Encodable>(self, items: impl IntoIterator<Item = T>) -> Self {
        self.raw(&Self::of(items).finish())
    }

    fn of<T: Encodable>(items: impl IntoIterator<Item = T>) -> Self {
        items
            .into_iter()
            .fold(Self::default(), |list, item| list.item(&item))
    }

    fn raw(mut self, encoded: &[u8]) -> Self {
        self.0.extend_from_slice(encoded);
        self
    }

    fn finish(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.0.len() + 9);
        Header {
            list: true,
            payload_length: self.0.len(),
        }
        .encode(&mut out);
        out.put_slice(&self.0);
        out
    }
}

/// An address, or the empty string for `None`.
fn opt_address(a: Option<Address>) -> Bytes {
    a.map_or_else(Bytes::new, |a| Bytes::copy_from_slice(a.as_slice()))
}

fn encode_frame(f: &Frame) -> Vec<u8> {
    List::default()
        .item(&f.mode)
        .item(&f.flags)
        .item(&opt_address(f.target))
        .raw(
            &List::default()
                .item(&f.limits.execution)
                .item(&f.limits.state)
                .finish(),
        )
        .item(&f.value)
        .item(&f.data)
        .finish()
}

fn encode_signature(s: &FrameSignature, elide: bool) -> Vec<u8> {
    let signature = if elide && s.msg.is_empty() {
        &Bytes::new()
    } else {
        &s.signature
    };
    List::default()
        .item(&s.scheme)
        .item(&opt_address(s.signer))
        .item(&s.msg)
        .item(signature)
        .finish()
}

impl FrameTx {
    /// The RLP list, with every empty-`msg` signature's bytes elided when `elide`.
    fn envelope(&self, elide: bool) -> Vec<u8> {
        let mut frames = List::default();
        for f in &self.frames {
            frames = frames.raw(&encode_frame(f));
        }
        let mut signatures = List::default();
        for s in &self.signatures {
            signatures = signatures.raw(&encode_signature(s, elide));
        }
        List::default()
            .item(&self.chain_id)
            .items(&self.nonce_keys)
            .item(&self.nonce_seq)
            .item(&self.sender)
            .raw(&frames.finish())
            .raw(&signatures.finish())
            .raw(
                &List::default()
                    .item(&self.fees.max_priority_fee_per_gas)
                    .item(&self.fees.max_fee_per_gas)
                    .item(&self.fees.max_fee_per_blob_gas)
                    .finish(),
            )
            .items(&self.blob_versioned_hashes)
            .finish()
    }

    /// The RLP payload, without the type byte.
    #[must_use]
    pub fn encode_payload(&self) -> Vec<u8> {
        self.envelope(false)
    }

    /// `0x06 || rlp(payload)`: what `eth_sendRawTransaction` takes.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut out = vec![FRAME_TX_TYPE];
        out.extend(self.envelope(false));
        out.into()
    }

    /// The transaction hash: `keccak256` of the full serialized envelope.
    #[must_use]
    pub fn hash(&self) -> B256 {
        keccak256(self.encode())
    }

    /// The canonical signature hash (`compute_sig_hash`, `TXPARAM(0x08)`): the envelope with the
    /// bytes of every empty-`msg` signature elided. Frame data is committed verbatim, so a
    /// signature covers every frame, including the ones other parties add.
    #[must_use]
    pub fn sig_hash(&self) -> B256 {
        let mut out = vec![FRAME_TX_TYPE];
        out.extend(self.envelope(true));
        keccak256(out)
    }

    /// `rlp(nonce_keys) || rlp(nonce_seq)`: the EIP-8250 nonce bytes, priced as calldata.
    #[must_use]
    pub fn nonce_calldata(&self) -> Vec<u8> {
        let mut out = List::of(&self.nonce_keys).finish();
        self.nonce_seq.encode(&mut out);
        out
    }

    /// Parse a raw `0x06...` transaction. Structural only: canonical RLP, no validity checks.
    pub fn decode(raw: &[u8]) -> Result<Self, DecodeError> {
        let Some((&FRAME_TX_TYPE, mut rest)) = raw.split_first() else {
            return Err(DecodeError::NotFrameTx);
        };
        let mut env = list(&mut rest, "envelope")?;
        done(rest, "transaction")?;

        let chain_id = u64::decode(&mut env)?;
        let mut keys = list(&mut env, "nonce_keys")?;
        let mut nonce_keys = Vec::new();
        while !keys.is_empty() {
            nonce_keys.push(U256::decode(&mut keys)?);
        }
        let nonce_seq = u64::decode(&mut env)?;
        let sender = decode_opt_address(&mut env, "sender")?.ok_or(DecodeError::EmptySender)?;

        let mut frames_rlp = list(&mut env, "frames")?;
        let mut frames = Vec::new();
        while !frames_rlp.is_empty() {
            let mut f = list(&mut frames_rlp, "frame")?;
            let mode = u8::decode(&mut f)?;
            let flags = u8::decode(&mut f)?;
            let target = decode_opt_address(&mut f, "frame.target")?;
            let mut limits = list(&mut f, "frame.limits")?;
            let limits_out = FrameLimits {
                execution: u64::decode(&mut limits)?,
                state: u64::decode(&mut limits)?,
            };
            done(limits, "frame.limits")?;
            let value = U256::decode(&mut f)?;
            let data = Bytes::decode(&mut f)?;
            done(f, "frame")?;
            frames.push(Frame {
                mode,
                flags,
                target,
                limits: limits_out,
                value,
                data,
            });
        }

        let mut sigs_rlp = list(&mut env, "signatures")?;
        let mut signatures = Vec::new();
        while !sigs_rlp.is_empty() {
            let mut s = list(&mut sigs_rlp, "signature")?;
            let scheme = u8::decode(&mut s)?;
            let signer = decode_opt_address(&mut s, "signature.signer")?;
            let msg = Bytes::decode(&mut s)?;
            let signature = Bytes::decode(&mut s)?;
            done(s, "signature")?;
            signatures.push(FrameSignature {
                scheme,
                signer,
                msg,
                signature,
            });
        }

        let mut fees_rlp = list(&mut env, "fees")?;
        let fees = Fees {
            max_priority_fee_per_gas: u128::decode(&mut fees_rlp)?,
            max_fee_per_gas: u128::decode(&mut fees_rlp)?,
            max_fee_per_blob_gas: u128::decode(&mut fees_rlp)?,
        };
        done(fees_rlp, "fees")?;

        let mut blobs = list(&mut env, "blob_versioned_hashes")?;
        let mut blob_versioned_hashes = Vec::new();
        while !blobs.is_empty() {
            blob_versioned_hashes.push(B256::decode(&mut blobs)?);
        }
        done(env, "envelope")?;

        Ok(Self {
            chain_id,
            nonce_keys,
            nonce_seq,
            sender,
            frames,
            signatures,
            fees,
            blob_versioned_hashes,
        })
    }
}

// ---- decoding helpers ----

/// Take one list off `buf` and return its payload.
fn list<'a>(buf: &mut &'a [u8], what: &'static str) -> Result<&'a [u8], DecodeError> {
    let header = Header::decode(buf)?;
    if !header.list {
        return Err(DecodeError::ExpectedList(what));
    }
    if buf.len() < header.payload_length {
        return Err(rlp::Error::InputTooShort.into());
    }
    let (payload, rest) = buf.split_at(header.payload_length);
    *buf = rest;
    Ok(payload)
}

fn done(rest: &[u8], what: &'static str) -> Result<(), DecodeError> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(DecodeError::Trailing(what))
    }
}

fn decode_opt_address(buf: &mut &[u8], what: &'static str) -> Result<Option<Address>, DecodeError> {
    let bytes = Bytes::decode(buf)?;
    match bytes.len() {
        0 => Ok(None),
        20 => Ok(Some(Address::from_slice(&bytes))),
        n => Err(DecodeError::Address(what, n)),
    }
}
