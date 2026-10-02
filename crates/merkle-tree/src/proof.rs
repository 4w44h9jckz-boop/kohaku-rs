use std::array::from_fn;

use crate::{element::Element, hasher::Hasher};

/// A Merkle proof for a leaf element in a Merkle tree of depth `DEPTH` and arity `ARITY`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof<const DEPTH: usize, const ARITY: usize, E> {
    pub leaf: E,
    /// The full child row at each level, including the node on the path itself.
    pub siblings: [[E; ARITY]; DEPTH],
    /// The index of the node within its parent's children at each level, in `0..ARITY`.
    pub path: [u8; DEPTH],
    pub root: E,
}

impl<const DEPTH: usize, const ARITY: usize, E: Element> MerkleProof<DEPTH, ARITY, E> {
    pub fn new(leaf: E, siblings: [[E; ARITY]; DEPTH], path: [u8; DEPTH], root: E) -> Self {
        Self {
            leaf,
            siblings,
            path,
            root,
        }
    }
}

impl<const DEPTH: usize, const ARITY: usize, E: Element + Eq> MerkleProof<DEPTH, ARITY, E> {
    /// Verifies the Merkle inclusion proof.
    pub fn verify<H: Hasher<ARITY, E>>(&self) -> bool {
        let mut hash = self.leaf.clone();
        for (level, &sibling_idx) in self.path.iter().enumerate() {
            let mut children = self.siblings[level].clone();
            children[sibling_idx as usize] = hash;
            hash = H::hash(children);
        }
        hash == self.root
    }
}

impl<const DEPTH: usize, E: Element + Eq> MerkleProof<DEPTH, 2, E> {
    /// Returns the siblings of the node on the path to the root, excluding the node itself.
    ///
    /// Only available for binary trees. Use `siblings` for trees of arbitrary arity.
    pub fn sibling_paths(&self) -> [E; DEPTH] {
        from_fn(|level| {
            let s = &self.siblings[level];
            s[1 - self.path[level] as usize].clone()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_paths_returns_siblings() {
        let proof = MerkleProof::new(1u64, [[1, 2], [3, 4], [5, 6]], [0, 1, 0], 7u64);
        assert_eq!(proof.sibling_paths(), [2, 3, 6]);
    }
}
