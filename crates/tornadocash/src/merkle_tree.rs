use std::sync::OnceLock;

use alloy::primitives::keccak256;
use ark_bn254::Fr;
use ark_ff::{BigInt, PrimeField};
use kohaku_merkle_tree::{MerkleTreeError, hasher::Hasher};
use ruint::{aliases::U256, uint};

use crate::{
    crypto::mimc::mimc_sponge_hash,
    syncer::event::{Deposit, SyncEvent},
};

const DEPTH: usize = 20;

/// `MerkleTree` type used in Tornado Cash.
pub type MerkleTree = kohaku_merkle_tree::MerkleTree<DEPTH, TornadoHasher>;

/// `MerkleProof` type used in Tornado Cash.
pub type MerkleProof = kohaku_merkle_tree::proof::MerkleProof<DEPTH>;

/// `MerkleTree` extension trait for Tornado Cash.
pub trait MerkleTreeExt {
    /// Splices the given events into the Merkle tree.
    fn splice_events(
        &self,
        events: &[SyncEvent],
    ) -> impl Future<Output = Result<(), MerkleTreeError>>;
}

/// Hasher used in Tornado Cash Merkle tree.
///
/// Follows the hashing scheme used in Tornado Cash. Reference implementation:
/// [contracts/Classic/MerkleTreeWithHistory.sol](https://github.com/tornado-dao/tornado-contracts/blob/cc57528ae13e762c36ae715f37e018528d6e0605/contracts/Classic/MerkleTreeWithHistory.sol#L57)
#[derive(Copy, Clone)]
pub struct TornadoHasher;

const FIELD_SIZE: U256 =
    uint!(21888242871839275222246405745257275088548364400416034343698204186575808495617_U256);

impl Hasher for TornadoHasher {
    fn hash(l: U256, r: U256) -> U256 {
        let l: Fr = BigInt::from(l).into();
        let r: Fr = BigInt::from(r).into();
        mimc_sponge_hash(l, r).into_bigint().into()
    }

    fn zero() -> U256 {
        static ZERO: OnceLock<U256> = OnceLock::new();
        *ZERO.get_or_init(|| {
            let hash = keccak256(b"tornado");
            let hash_u256 = U256::from_be_bytes(*hash);
            hash_u256 % FIELD_SIZE
        })
    }
}

impl MerkleTreeExt for MerkleTree {
    async fn splice_events(&self, events: &[SyncEvent]) -> Result<(), MerkleTreeError> {
        let deposits: Vec<&Deposit> = events
            .iter()
            .filter_map(|e| match e {
                SyncEvent::Deposit(d) => Some(d),
                SyncEvent::Withdrawal(_) => None,
            })
            .collect();

        let Some(first_leaf_index) = deposits.first().map(|d| d.leaf_index) else {
            return Ok(());
        };

        for (offset, d) in deposits.iter().enumerate() {
            let expected = first_leaf_index + offset as u32;
            if d.leaf_index != expected {
                return Err(MerkleTreeError::Other(format!(
                    "non-contiguous deposit events: expected leaf {expected}, got {}",
                    d.leaf_index
                )));
            }
        }

        let commitments: Vec<U256> = deposits.into_iter().map(|d| d.commitment.into()).collect();
        self.splice(first_leaf_index as usize, &commitments).await
    }
}
