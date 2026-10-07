#![doc = include_str!("../README.md")]

pub mod withdrawal;

use alloy::primitives::{Address, B256, Bytes, U256};
use kohaku_merkle_tree::hasher::Hasher;
use kohaku_tornadocash::{
    Asset, Field, Note, Payer, Pool, Withdrawal, WithdrawalError,
    merkle_tree::{MerkleTree, TornadoHasher},
};
use rand::CryptoRng;
use serde::{Deserialize, Serialize};

/// Height of the Tornado Cash Merkle tree, fixed by the circuit.
pub const LEVELS: usize = 20;

/// The empty-subtree hashes `zeros[0..=LEVELS]` of the Tornado Cash tree: `zeros[0]` is
/// `keccak256("tornado") mod p` and `zeros[i + 1] = MiMCSponge(zeros[i], zeros[i])`.
///
/// A pool contract that maintains the tree on chain needs these as constants.
#[must_use]
pub fn zeros() -> [Field; LEVELS + 1] {
    let mut zeros = [TornadoHasher::zero(); LEVELS + 1];
    for i in 1..=LEVELS {
        zeros[i] = TornadoHasher::hash([zeros[i - 1], zeros[i - 1]]);
    }
    zeros
}

/// The six public inputs of the Tornado Cash withdrawal circuit, in the circuit's order.
///
/// A frame-native pool reads all six from the withdrawal frame's calldata during `VERIFY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicInputs {
    pub root: B256,
    pub nullifier_hash: B256,
    pub recipient: Address,
    pub relayer: Address,
    pub fee: U256,
    pub refund: U256,
}

/// A withdrawal proof for a pool whose tree holds `leaves`, in insertion order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FramePoolProof {
    pub leaf_index: usize,
    pub commitment: B256,
    pub inputs: PublicInputs,
    /// The proof as Tornado's `Verifier.verifyProof` takes it: eight 32-byte words.
    pub proof: Bytes,
}

#[derive(Debug, thiserror::Error)]
pub enum FramePoolError {
    #[error("the note's commitment is not among the leaves")]
    MissingLeaf,
    #[error("Merkle tree error: {0}")]
    Tree(#[from] kohaku_merkle_tree::MerkleTreeError),
    #[error("Withdrawal error: {0}")]
    Withdrawal(#[from] WithdrawalError),
}

/// Prove that `note` is one of `leaves` and bind the proof to `recipient`, `relayer` and `fee`.
///
/// The circuit is Tornado Cash's, unchanged: what makes the pool frame-native is the contract
/// that checks the proof, not the proof.
///
/// # Errors
/// Returns an error if the note's commitment is not among `leaves` or proving fails.
pub fn prove(
    note: Note,
    leaves: &[Field],
    recipient: Address,
    payer: Payer,
    rng: &mut impl CryptoRng,
) -> Result<FramePoolProof, FramePoolError> {
    let commitment = note.commitment();
    let leaf_index = leaves
        .iter()
        .position(|l| *l == commitment)
        .ok_or(FramePoolError::MissingLeaf)?;
    let tree = MerkleTree::from_leaves(leaves)?;
    let merkle_proof = tree.proof(leaf_index)?;

    // `Withdrawal` only carries the pool for its address; nothing here reads it.
    let pool = Pool {
        chain_id: 0,
        address: Address::ZERO,
        asset: Asset::ETH,
        amount_wei: 0,
        deployed_block: 0,
        paymaster: None,
    };
    let proven = Withdrawal::new(&pool, note, recipient)
        .with_payer(payer)
        .prove(&merkle_proof, rng)?;

    Ok(FramePoolProof {
        leaf_index,
        commitment: commitment.into(),
        inputs: PublicInputs {
            root: proven.root.into(),
            nullifier_hash: proven.note.nullifier_hash().into(),
            recipient,
            relayer: payer.address,
            fee: payer.fee,
            refund: payer.refund,
        },
        proof: proven.proof_bytes(),
    })
}

#[cfg(test)]
mod tests {
    use ruint::uint;

    use super::*;

    #[test]
    fn zeros_match_tornado() {
        // MerkleTreeWithHistory.zeros(i) in tornadocash/tornado-core (master), which hard-codes them.
        let expected = [
            (
                0,
                uint!(0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c_U256),
            ),
            (
                1,
                uint!(0x256a6135777eee2fd26f54b8b7037a25439d5235caee224154186d2b8a52e31d_U256),
            ),
            (
                19,
                uint!(0x198622acbd783d1b0d9064105b1fc8e4d8889de95c4c519b3f635809fe6afc05_U256),
            ),
            (
                20,
                uint!(0x29d7ed391256ccc3ea596c86e933b89ff339d25ea8ddced975ae2fe30b5296d4_U256),
            ),
        ];
        let zeros = zeros();
        for (i, z) in expected {
            let zero: U256 = zeros[i].into();
            assert_eq!(zero, z, "zeros({i})");
        }
        let empty_root: U256 = MerkleTree::new().root().unwrap().into();
        let top: U256 = zeros[LEVELS].into();
        assert_eq!(top, empty_root);
    }
}
