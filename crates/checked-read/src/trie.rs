//! An account read out of the state trie, from a bag of nodes taken by their hashes.
//!
//! [`account`] walks from a state root along `keccak256(address)`, taking each node from
//! [`Nodes`] by its hash. A node's hash is its name, so where a node came from does not matter:
//! a branch split between a set every reader downloads once and a record fetched privately is
//! checked exactly as one `eth_getProof` branch is.

use std::collections::HashMap;

use alloy::{
    primitives::{Address, B256, Bytes, KECCAK256_EMPTY, U256, keccak256},
    rlp::{self, Decodable, Encodable},
};

use crate::table::VALUE;

/// An account as the state trie holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountState {
    pub nonce: u64,
    pub balance: U256,
    pub storage_root: B256,
    pub code_hash: B256,
}

impl AccountState {
    /// The RLP list `[nonce, balance, storage_root, code_hash]`, the leaf's value.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        self.nonce.encode(&mut payload);
        self.balance.encode(&mut payload);
        self.storage_root.encode(&mut payload);
        self.code_hash.encode(&mut payload);
        list(&payload)
    }

    pub fn decode(mut buf: &[u8]) -> Result<Self, TrieError> {
        let h = rlp::Header::decode(&mut buf)?;
        if !h.list {
            return Err(TrieError::Malformed("an account that is not a list"));
        }
        Ok(Self {
            nonce: u64::decode(&mut buf)?,
            balance: U256::decode(&mut buf)?,
            storage_root: B256::decode(&mut buf)?,
            code_hash: B256::decode(&mut buf)?,
        })
    }

    /// Whether `value`, a table record's `delegate (20) || balance (12) || nonce (8)`, is this
    /// account: the same balance and nonce, and code that is empty for a zero delegate and the
    /// EIP-7702 designator `0xef0100 || delegate` otherwise.
    #[must_use]
    pub fn is(&self, value: &[u8; VALUE]) -> bool {
        let delegate = Address::from_slice(&value[..20]);
        let code_hash = if delegate.is_zero() {
            KECCAK256_EMPTY
        } else {
            keccak256([&[0xef, 0x01, 0x00][..], delegate.as_slice()].concat())
        };
        self.balance == U256::from_be_slice(&value[20..32])
            && self.nonce.to_be_bytes() == value[32..]
            && self.code_hash == code_hash
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TrieError {
    #[error("no node {0} among those given")]
    Missing(B256),
    #[error("malformed: {0}")]
    Malformed(&'static str),
    #[error(transparent)]
    Rlp(#[from] rlp::Error),
}

/// Trie nodes by their hashes.
#[derive(Debug, Clone, Default)]
pub struct Nodes(HashMap<B256, Vec<u8>>);

impl Nodes {
    pub fn insert(&mut self, node: &[u8]) {
        self.0.insert(keccak256(node), node.to_vec());
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<T: AsRef<[u8]>> FromIterator<T> for Nodes {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut n = Self::default();
        for node in iter {
            n.insert(node.as_ref());
        }
        n
    }
}

/// An item of an RLP list: a string's payload, or a nested list's whole encoding.
enum Item<'a> {
    Str(&'a [u8]),
    List(&'a [u8]),
}

fn items(mut buf: &[u8]) -> Result<Vec<Item<'_>>, TrieError> {
    let h = rlp::Header::decode(&mut buf)?;
    if !h.list || buf.len() < h.payload_length {
        return Err(TrieError::Malformed("a node that is not a list"));
    }
    let mut payload = &buf[..h.payload_length];
    let mut out = vec![];
    while !payload.is_empty() {
        let start = payload;
        let h = rlp::Header::decode(&mut payload)?;
        if payload.len() < h.payload_length {
            return Err(TrieError::Malformed("an item past its node"));
        }
        let header = start.len() - payload.len();
        out.push(if h.list {
            Item::List(&start[..header + h.payload_length])
        } else {
            Item::Str(&payload[..h.payload_length])
        });
        payload = &payload[h.payload_length..];
    }
    Ok(out)
}

/// The nibbles of a hex-prefix path, and whether it ends a leaf.
fn hex_prefix(enc: &[u8]) -> Result<(bool, Vec<u8>), TrieError> {
    let first = *enc.first().ok_or(TrieError::Malformed("an empty path"))?;
    let leaf = first & 0x20 != 0;
    let mut nibbles = vec![];
    if first & 0x10 != 0 {
        nibbles.push(first & 0x0f);
    }
    for b in &enc[1..] {
        nibbles.extend([b >> 4, b & 0x0f]);
    }
    Ok((leaf, nibbles))
}

fn path(address: Address) -> Vec<u8> {
    keccak256(address)
        .iter()
        .flat_map(|b| [b >> 4, b & 0x0f])
        .collect()
}

/// `address`'s account under `root`, from `nodes`: `Some` if a branch proves it, `None` if one
/// proves it absent, an error if a node on the way is missing or malformed.
pub fn account(
    root: B256,
    address: Address,
    nodes: &Nodes,
) -> Result<Option<AccountState>, TrieError> {
    if root == alloy::trie::EMPTY_ROOT_HASH {
        return Ok(None);
    }
    let key = path(address);
    let mut at = 0;
    let mut raw: &[u8] = nodes.0.get(&root).ok_or(TrieError::Missing(root))?;
    loop {
        let node = items(raw)?;
        let next = match node.as_slice() {
            [children @ .., _value] if children.len() == 16 => {
                let Some(&nibble) = key.get(at) else {
                    return Err(TrieError::Malformed("a branch at the end of the key"));
                };
                at += 1;
                &children[usize::from(nibble)]
            }
            [Item::Str(enc), rest] => {
                let (leaf, nibbles) = hex_prefix(enc)?;
                if leaf {
                    return match rest {
                        Item::Str(v) if key[at..] == nibbles[..] => {
                            Ok(Some(AccountState::decode(v)?))
                        }
                        Item::Str(_) => Ok(None),
                        Item::List(_) => Err(TrieError::Malformed("a leaf whose value is a list")),
                    };
                }
                if !key[at..].starts_with(&nibbles) {
                    return Ok(None);
                }
                at += nibbles.len();
                rest
            }
            _ => return Err(TrieError::Malformed("a node of neither 17 nor 2 items")),
        };
        raw = match next {
            Item::Str([]) => return Ok(None),
            Item::Str(h) if h.len() == 32 => {
                let h = B256::from_slice(h);
                nodes.0.get(&h).ok_or(TrieError::Missing(h))?
            }
            Item::List(inline) => inline,
            Item::Str(_) => return Err(TrieError::Malformed("a child that is no hash")),
        };
    }
}

/// `leaf`, a leaf node, with its value replaced by `account`: the node a server would have to
/// forge to put a different account under the same path.
pub fn reencode_leaf(leaf: &[u8], account: &AccountState) -> Result<Vec<u8>, TrieError> {
    let node = items(leaf)?;
    let [Item::Str(enc), Item::Str(_)] = node.as_slice() else {
        return Err(TrieError::Malformed("not a leaf"));
    };
    if !hex_prefix(enc)?.0 {
        return Err(TrieError::Malformed("not a leaf"));
    }
    let mut payload = vec![];
    enc.encode(&mut payload);
    account.encode().as_slice().encode(&mut payload);
    Ok(list(&payload))
}

/// The nodes of an encoded RLP list of nodes laid end to end, as a record carries them.
pub fn split_nodes(mut buf: &[u8]) -> Result<Vec<Bytes>, TrieError> {
    let mut out = vec![];
    while !buf.is_empty() {
        let start = buf;
        let h = rlp::Header::decode(&mut buf)?;
        if !h.list || buf.len() < h.payload_length {
            return Err(TrieError::Malformed("a node that is not a list"));
        }
        let len = start.len() - buf.len() + h.payload_length;
        out.push(Bytes::copy_from_slice(&start[..len]));
        buf = &buf[h.payload_length..];
    }
    Ok(out)
}

/// An RLP list around an already encoded payload.
#[must_use]
pub fn list(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut out);
    out.extend_from_slice(payload);
    out
}
