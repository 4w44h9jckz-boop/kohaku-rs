//! How many notes would satisfy a statement, before the wallet proves it (`exp-frames`
//! experiment 35). A proof reveals nothing beyond its statement, but a statement that fits few
//! notes points at its prover, so the wallet shows the crowd first.
//!
//! Three statement kinds, each counted from public chain data alone:
//!
//! - **a deposit into a pool before a date**: a Tornado Cash pool's `nextIndex()` at the last
//!   block before the date ([`deposits_before`]);
//! - **an unspent note worth at least T**: an ETH pool holds exactly its denomination per
//!   unspent note, so the sum of balance / denomination over the pools of at least T
//!   ([`unspent_at_least`]);
//! - **a deposit in an association set**: the labels of the set whose root an association-set
//!   provider published on chain, with the whole tree at an IPFS CID. [`AssociationSet::verify`]
//!   recomputes every level with Poseidon and checks the root, so the count does not rest on
//!   whoever served the tree.
//!
//! What it cannot count: a balance over all accounts. That needs the state's account range,
//! which an ordinary RPC does not serve.

use alloy::{
    eips::BlockId,
    primitives::{Address, U256, address, uint},
    providers::Provider,
    rpc::types::{Filter, TransactionRequest},
    sol_types::{SolCall, SolEvent},
};
use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};

use crate::poseidon::poseidon2;

/// Tornado Cash's and Privacy Pools' interfaces, as tornado-core and privacy-pools-core define
/// them.
pub mod abi {
    alloy::sol! {
        function nextIndex() view returns (uint32);
        event RootUpdated(uint256 _root, string _ipfsCID, uint256 _timestamp);
        event Deposited(address indexed _depositor, uint256 _commitment, uint256 _label, uint256 _value, uint256 _precommitmentHash);
    }
}

/// A fixed-denomination ETH pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthPool {
    pub address: Address,
    pub denomination: U256,
}

/// Tornado Cash's four ETH pools on mainnet (tornado-cli `config.js`, netId 1).
pub const TORNADO_ETH: [EthPool; 4] = [
    EthPool {
        address: address!("0x12D66f87A04A9E220743712cE6d9bB1B5616B8Fc"),
        denomination: uint!(100_000_000_000_000_000_U256),
    },
    EthPool {
        address: address!("0x47CE0C6eD5B0Ce3d3A51fdb1C52DC66a7c3c2936"),
        denomination: uint!(1_000_000_000_000_000_000_U256),
    },
    EthPool {
        address: address!("0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF"),
        denomination: uint!(10_000_000_000_000_000_000_U256),
    },
    EthPool {
        address: address!("0xA160cdAB225685dA1d56aa342Ad8841c3b53f291"),
        denomination: uint!(100_000_000_000_000_000_000_U256),
    },
];

#[derive(Debug, thiserror::Error)]
pub enum DisclosureError {
    #[error(transparent)]
    Transport(#[from] alloy::transports::TransportError),
    #[error("{0}")]
    Malformed(&'static str),
    #[error("the association set's level {0} does not hash from the one below")]
    Level(usize),
    #[error("the association set does not hash to the root on chain")]
    Root,
}

/// The last block before `timestamp`, at or below `head`.
pub async fn block_before<P: Provider>(
    provider: &P,
    timestamp: u64,
    head: u64,
) -> Result<u64, DisclosureError> {
    let (mut lo, mut hi) = (1, head);
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        let block = provider
            .get_block_by_number(mid.into())
            .await?
            .ok_or(DisclosureError::Malformed("a block the node does not have"))?;
        if block.header.timestamp < timestamp {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    Ok(lo)
}

/// The pool's deposits made before `timestamp`: `(the last block before it, the count)`.
pub async fn deposits_before<P: Provider>(
    provider: &P,
    pool: Address,
    timestamp: u64,
    head: u64,
) -> Result<(u64, u64), DisclosureError> {
    let block = block_before(provider, timestamp, head).await?;
    Ok((block, next_index(provider, pool, block).await?))
}

/// A Tornado Cash pool's `nextIndex()` at `block`: how many deposits it had.
pub async fn next_index<P: Provider>(
    provider: &P,
    pool: Address,
    block: u64,
) -> Result<u64, DisclosureError> {
    let out = provider
        .call(
            TransactionRequest::default()
                .to(pool)
                .input(abi::nextIndexCall {}.abi_encode().into()),
        )
        .block(BlockId::number(block))
        .await?;
    let n = abi::nextIndexCall::abi_decode_returns(&out)
        .map_err(|_| DisclosureError::Malformed("nextIndex()"))?;
    Ok(u64::from(n))
}

/// Unspent notes worth at least `threshold` at `block`, over `pools`.
pub async fn unspent_at_least<P: Provider>(
    provider: &P,
    pools: &[EthPool],
    threshold: U256,
    block: u64,
) -> Result<u64, DisclosureError> {
    let mut n = 0u64;
    for p in pools.iter().filter(|p| p.denomination >= threshold) {
        let balance = provider
            .get_balance(p.address)
            .block_id(BlockId::number(block))
            .await?;
        n += (balance / p.denomination).to::<u64>();
    }
    Ok(n)
}

/// The latest association-set root an entrypoint published in `from..=to`: `(root, CID, block)`.
pub async fn latest_association_root<P: Provider>(
    provider: &P,
    entrypoint: Address,
    from: u64,
    to: u64,
) -> Result<Option<(U256, String, u64)>, DisclosureError> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(entrypoint)
                .event_signature(abi::RootUpdated::SIGNATURE_HASH)
                .from_block(from)
                .to_block(to),
        )
        .await?;
    Ok(logs.last().and_then(|l| {
        let e = abi::RootUpdated::decode_log_data(l.data()).ok()?;
        Some((e._root, e._ipfsCID, l.block_number?))
    }))
}

/// An association set as its provider publishes it: a `LeanIMT`'s levels, leaves first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssociationSet {
    pub levels: Vec<Vec<U256>>,
}

impl AssociationSet {
    /// Parse the provider's JSON export and check it against `root`: each level must hash from
    /// the one below (a node is the Poseidon hash of its two children, or its only child), and
    /// the top must be `root`.
    pub fn verify(export: &[u8], root: U256) -> Result<Self, DisclosureError> {
        let raw: Vec<Vec<String>> = serde_json::from_slice(export)
            .map_err(|_| DisclosureError::Malformed("the set's export"))?;
        let levels = raw
            .iter()
            .map(|l| {
                l.iter()
                    .map(|x| U256::from_str_radix(x, 10))
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| DisclosureError::Malformed("a node of the set"))?;
        let fr = |x: U256| {
            Fr::from_bigint(BigInt(x.into_limbs()))
                .ok_or(DisclosureError::Malformed("a node outside the field"))
        };
        let first = levels
            .first()
            .ok_or(DisclosureError::Malformed("an empty set"))?;
        let mut below = first
            .iter()
            .map(|&x| fr(x))
            .collect::<Result<Vec<_>, _>>()?;
        for (i, level) in levels.iter().enumerate().skip(1) {
            let up: Vec<Fr> = below
                .chunks(2)
                .map(|c| {
                    if c.len() == 2 {
                        poseidon2(c[0], c[1])
                    } else {
                        c[0]
                    }
                })
                .collect();
            let got: Vec<U256> = up
                .iter()
                .map(|f| U256::from_limbs(f.into_bigint().0))
                .collect();
            if &got != level {
                return Err(DisclosureError::Level(i));
            }
            below = up;
        }
        let top = levels.last().and_then(|l| l.first()).copied();
        if levels.last().map(Vec::len) != Some(1) || top != Some(root) {
            return Err(DisclosureError::Root);
        }
        Ok(Self { levels })
    }

    /// The set's labels.
    #[must_use]
    pub fn labels(&self) -> &[U256] {
        &self.levels[0]
    }
}

/// How the wallet words a crowd before the user proves a statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crowd {
    /// Fewer than 10: the statement all but names its prover.
    Identifies,
    /// Fewer than 100.
    Few,
    Many,
}

impl Crowd {
    #[must_use]
    pub fn of(count: u64) -> Self {
        match count {
            0..10 => Self::Identifies,
            10..100 => Self::Few,
            _ => Self::Many,
        }
    }

    /// The line the wallet shows.
    #[must_use]
    pub fn warning(self, count: u64) -> String {
        match self {
            Self::Identifies => {
                format!("only {count} could make this statement: it would all but name you")
            }
            Self::Few => format!("only {count} could make this statement: it narrows you down"),
            Self::Many => format!("{count} could make this statement"),
        }
    }
}
