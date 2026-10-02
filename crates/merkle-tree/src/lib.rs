use std::collections::HashMap;

use kohaku_kv_store::{Store, backend::StoreError};
use ruint::aliases::U256;

use crate::{hasher::Hasher, store::MerkleTreeStoreExt};

pub mod hasher;
pub mod proof;
mod store;

/// A binary Merkle tree with a fixed depth `D` and hash function `H`.
#[derive(Clone)]
pub struct MerkleTree<const D: usize, H: Hasher> {
    store: Store,
    phantom: std::marker::PhantomData<H>,
}

#[derive(Debug, thiserror::Error)]
pub enum MerkleTreeError {
    #[error("Merkle tree is full")]
    TreeFull,
    #[error("Missing leaf element")]
    MissingLeaf(U256),
    #[error("Index {0} is out of bounds")]
    IndexOutOfBounds(usize),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("Other: {0}")]
    Other(String),
}

impl<const D: usize, H: Hasher> MerkleTree<D, H> {
    /// Creates a new Merkle tree backed by `store`.
    ///
    /// If `store` already contains a tree, it will be used; otherwise, a new empty tree will be
    /// created.
    pub fn new(store: Store) -> Self {
        Self {
            store,
            phantom: std::marker::PhantomData,
        }
    }

    /// Returns the tree's root hash.
    ///
    /// # Errors
    /// Returns an error if the store fails to read the root node.
    pub async fn root(&self) -> Result<U256, MerkleTreeError> {
        Ok(match self.store.node(D as u8, 0).await? {
            Some(root) => root,
            None => zero_hashes::<D, H>(D)[D],
        })
    }

    /// Returns the inclusion proof for the given leaf.
    ///
    /// # Errors
    /// Returns an error if the leaf is not found in the tree.
    pub async fn leaf_proof(&self, leaf: U256) -> Result<proof::MerkleProof<D>, MerkleTreeError> {
        let len = self.store.leaf_count().await?;
        for index in 0..len {
            if self.store.node(0, index).await? == Some(leaf) {
                return self.proof(index as usize).await;
            }
        }

        Err(MerkleTreeError::MissingLeaf(leaf))
    }

    /// Returns the inclusion proof for the leaf at the given index.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds.
    pub async fn proof(&self, index: usize) -> Result<proof::MerkleProof<D>, MerkleTreeError> {
        let len = self.store.leaf_count().await? as usize;
        if index >= len {
            return Err(MerkleTreeError::IndexOutOfBounds(index));
        }

        let zeros = zero_hashes::<D, H>(D);
        let mut path = [0u8; D];
        let mut siblings = [U256::ZERO; D];
        let mut idx = index;

        for level in 0..D {
            path[level] = (idx % 2) as u8;

            let sibling_idx = (idx ^ 1) as u64;
            siblings[level] = match self.store.node(level as u8, sibling_idx).await? {
                Some(node) => node,
                None => zeros[level],
            };

            idx /= 2;
        }

        let element = self
            .store
            .node(0, index as u64)
            .await?
            .ok_or(MerkleTreeError::IndexOutOfBounds(index))?;

        Ok(proof::MerkleProof {
            root: self.root().await?,
            leaf: element,
            path,
            siblings,
        })
    }

    /// Inserts a single leaf at `index`. If a leaf already exists at that index, it is
    /// replaced.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds or the tree is full.
    pub async fn insert(&self, index: usize, leaf: U256) -> Result<(), MerkleTreeError> {
        self.splice(index, &[leaf]).await
    }

    /// Splices in `leaves` starting at `index`. If any leaves already exist at those indices,
    /// they are replaced.
    ///
    /// # Errors
    /// Returns an error if the index is out of bounds or the tree is full.
    pub async fn splice(&self, index: usize, leaves: &[U256]) -> Result<(), MerkleTreeError> {
        if leaves.is_empty() {
            return Ok(());
        }

        let len = self.store.leaf_count().await? as usize;
        if index > len {
            return Err(MerkleTreeError::IndexOutOfBounds(index));
        }

        let capacity = 2usize.checked_pow(D as u32).unwrap_or(usize::MAX);
        let new_len = (index + leaves.len()).max(len);
        if new_len > capacity {
            return Err(MerkleTreeError::TreeFull);
        }

        let zeros = zero_hashes::<D, H>(D);
        let mut pending: HashMap<(u8, u64), U256> = HashMap::new();
        for (offset, &leaf) in leaves.iter().enumerate() {
            pending.insert((0, (index + offset) as u64), leaf);
        }

        let mut range_start = index;
        let mut range_end = index + leaves.len();
        let mut child_len = len;

        for level in 1..=D {
            let start = range_start / 2;
            let end = range_end.div_ceil(2);

            for parent_idx in start..end {
                let mut children = [zeros[level - 1]; 2];
                for (k, child) in children.iter_mut().enumerate() {
                    let child_idx = (parent_idx * 2 + k) as u64;
                    *child = if let Some(&node) = pending.get(&((level - 1) as u8, child_idx)) {
                        node
                    } else if (child_idx as usize) < child_len {
                        self.store
                            .node((level - 1) as u8, child_idx)
                            .await?
                            .unwrap_or(zeros[level - 1])
                    } else {
                        zeros[level - 1]
                    };
                }
                pending.insert(
                    (level as u8, parent_idx as u64),
                    H::hash(children[0], children[1]),
                );
            }

            range_start = start;
            range_end = end;
            child_len = child_len.div_ceil(2);
        }

        let nodes: Vec<(u8, u64, U256)> = pending
            .into_iter()
            .map(|((level, node_index), hash)| (level, node_index, hash))
            .collect();
        self.store.commit(new_len as u64, &nodes).await?;

        Ok(())
    }
}

/// Computes the hash of a fully-empty subtree at each height from `0` to `levels` (inclusive),
/// where height `0` is the hasher's zero leaf value.
fn zero_hashes<const D: usize, H: Hasher>(levels: usize) -> Vec<U256> {
    let mut zeros = Vec::with_capacity(levels + 1);
    zeros.push(H::zero());
    for i in 1..=levels {
        zeros.push(H::hash(zeros[i - 1], zeros[i - 1]));
    }
    zeros
}

#[cfg(test)]
mod tests {
    use kohaku_kv_store::memory::MemoryStore;

    use super::*;
    use crate::hasher::Hasher;

    #[derive(Copy, Clone)]
    struct TestHasher;

    impl Hasher for TestHasher {
        fn hash(a: U256, b: U256) -> U256 {
            a ^ b.rotate_left(1)
        }

        fn zero() -> U256 {
            U256::ZERO
        }
    }

    fn tree() -> MerkleTree<3, TestHasher> {
        MerkleTree::new(MemoryStore::new().into())
    }

    #[tokio::test]
    async fn empty_tree_root_is_deterministic() {
        let a = tree();
        let b = tree();
        assert_eq!(a.root().await.unwrap(), b.root().await.unwrap());
    }

    #[tokio::test]
    async fn insert_and_splice_produce_same_root() {
        let leaves = [U256::from(1), U256::from(2), U256::from(3)];

        let inserted = tree();
        for (i, &l) in leaves.iter().enumerate() {
            inserted.insert(i, l).await.unwrap();
        }

        let spliced = tree();
        spliced.splice(0, &leaves).await.unwrap();

        assert_eq!(
            inserted.root().await.unwrap(),
            spliced.root().await.unwrap()
        );
    }

    #[tokio::test]
    async fn partial_overlap_splice_extends_correctly() {
        let leaves = [U256::from(1), U256::from(2), U256::from(3)];
        let full = tree();
        full.splice(0, &leaves).await.unwrap();

        let root_before = full.root().await.unwrap();
        full.splice(0, &leaves).await.unwrap();

        assert_eq!(full.root().await.unwrap(), root_before);
    }

    #[tokio::test]
    async fn reinserting_the_same_leaf_is_a_no_op() {
        let tree = tree();
        tree.insert(0, U256::from(1)).await.unwrap();
        let root_before = tree.root().await.unwrap();

        tree.insert(0, U256::from(1)).await.unwrap();
        assert_eq!(tree.root().await.unwrap(), root_before);
    }

    #[tokio::test]
    async fn reinserting_a_different_leaf_replaces_it() {
        let tree = tree();
        tree.insert(0, U256::from(1)).await.unwrap();
        let root_before = tree.root().await.unwrap();

        tree.insert(0, U256::from(2)).await.unwrap();

        assert_ne!(tree.root().await.unwrap(), root_before);
        assert_eq!(
            tree.leaf_proof(U256::from(2)).await.unwrap().leaf,
            U256::from(2)
        );
    }

    #[tokio::test]
    async fn insert_beyond_capacity_errors() {
        let tree = MerkleTree::<2, TestHasher>::new(MemoryStore::new().into());
        tree.splice(
            0,
            &[U256::from(1), U256::from(2), U256::from(3), U256::from(4)],
        )
        .await
        .unwrap();

        assert!(matches!(
            tree.insert(4, U256::from(5)).await,
            Err(MerkleTreeError::TreeFull)
        ));
    }

    #[tokio::test]
    async fn leaf_proof_missing_leaf_errors() {
        let tree = tree();
        tree.insert(0, U256::from(1)).await.unwrap();

        assert!(matches!(
            tree.leaf_proof(U256::from(9)).await,
            Err(MerkleTreeError::MissingLeaf(_))
        ));
    }

    #[tokio::test]
    async fn proof_out_of_bounds_errors() {
        let tree = tree();
        tree.insert(0, U256::from(1)).await.unwrap();

        assert!(matches!(
            tree.proof(5).await,
            Err(MerkleTreeError::IndexOutOfBounds(5))
        ));
    }
}
