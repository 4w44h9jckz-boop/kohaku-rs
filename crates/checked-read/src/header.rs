//! A block header, fetched by whoever checks against it and hashed again from its fields.
//!
//! The reader fetches the header it trusts from a node of its own choosing, never from the server
//! that answered. Its RLP is rebuilt from the JSON fields, in the order the Hegota testnet hashes
//! them (Prague's fields, then `blockAccessListHash` of EIP-7928 and `slotNumber` of EIP-7843), and
//! must hash to the block hash the node reported. So the state root is the one the chain's hash
//! commits to, and anyone holding the RLP can match it with any other source for the block.

use alloy::{
    primitives::{B256, Bytes, U256, keccak256},
    rlp::{self, Decodable, Encodable},
};
use serde_json::{Value, json};

use crate::trie::list;

/// The fields, in hashing order, and whether each is a quantity (minimal big-endian) rather
/// than fixed bytes.
const FIELDS: [(&str, bool); 23] = [
    ("parentHash", false),
    ("sha3Uncles", false),
    ("miner", false),
    ("stateRoot", false),
    ("transactionsRoot", false),
    ("receiptsRoot", false),
    ("logsBloom", false),
    ("difficulty", true),
    ("number", true),
    ("gasLimit", true),
    ("gasUsed", true),
    ("timestamp", true),
    ("extraData", false),
    ("mixHash", false),
    ("nonce", false),
    ("baseFeePerGas", true),
    ("withdrawalsRoot", false),
    ("blobGasUsed", true),
    ("excessBlobGas", true),
    ("parentBeaconBlockRoot", false),
    ("requestsHash", false),
    ("blockAccessListHash", false),
    ("slotNumber", true),
];

/// A header the holder has hashed itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub number: u64,
    pub hash: B256,
    pub state_root: B256,
    pub rlp: Bytes,
}

#[derive(Debug, thiserror::Error)]
pub enum HeaderError {
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error("the node returned no block {0}")]
    NoBlock(u64),
    #[error("a header without {0}")]
    Field(&'static str),
    #[error("the header's fields hash to {computed}, the node says {reported}")]
    Hash { computed: B256, reported: B256 },
    #[error(transparent)]
    Rlp(#[from] rlp::Error),
}

impl Header {
    /// A header from its RLP. Its hash is computed, not taken.
    pub fn decode(raw: &[u8]) -> Result<Self, HeaderError> {
        let mut buf = raw;
        let h = rlp::Header::decode(&mut buf)?;
        if !h.list {
            return Err(rlp::Error::UnexpectedString.into());
        }
        let mut fields: Vec<Bytes> = vec![];
        while !buf.is_empty() {
            fields.push(Bytes::decode(&mut buf)?);
        }
        let state_root = fields.get(3).ok_or(HeaderError::Field("stateRoot"))?;
        let number = fields.get(8).ok_or(HeaderError::Field("number"))?;
        if state_root.len() != 32 || number.len() > 8 {
            return Err(rlp::Error::UnexpectedLength.into());
        }
        Ok(Self {
            number: U256::from_be_slice(number).to(),
            hash: keccak256(raw),
            state_root: B256::from_slice(state_root),
            rlp: Bytes::copy_from_slice(raw),
        })
    }

    /// The header of block `number`, from the node at `url`: its fields hashed again, and
    /// refused unless they hash to the hash the node reported.
    pub async fn fetch(url: &str, number: u64) -> Result<Self, HeaderError> {
        let block: Value = reqwest::Client::new()
            .post(url)
            .json(&json!({
                "jsonrpc": "2.0", "id": 1, "method": "eth_getBlockByNumber",
                "params": [format!("{number:#x}"), false],
            }))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let block = &block["result"];
        if block.is_null() {
            return Err(HeaderError::NoBlock(number));
        }
        let mut payload = vec![];
        for (name, quantity) in FIELDS {
            let s = block[name].as_str().ok_or(HeaderError::Field(name))?;
            let bytes = hex_bytes(s).ok_or(HeaderError::Field(name))?;
            if quantity {
                let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
                bytes[first..].encode(&mut payload);
            } else {
                bytes.as_slice().encode(&mut payload);
            }
        }
        let header = Self::decode(&list(&payload))?;
        let reported: B256 = block["hash"]
            .as_str()
            .and_then(|h| h.parse().ok())
            .ok_or(HeaderError::Field("hash"))?;
        if header.hash != reported {
            return Err(HeaderError::Hash {
                computed: header.hash,
                reported,
            });
        }
        Ok(header)
    }
}

/// `0x`-prefixed hex, a quantity's odd length allowed.
fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x")?;
    if s.len() % 2 == 1 {
        hex::decode(format!("0{s}")).ok()
    } else {
        hex::decode(s).ok()
    }
}
