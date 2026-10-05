#![doc = include_str!("../README.md")]

use kohaku_tornadocash::{Deposit, Field, NoteString, Pool};
use thiserror::Error;

mod dyn_keychain;
pub mod recovery;
#[cfg(feature = "signature")]
pub mod signature;

pub use dyn_keychain::DynKeychain;

/// A deterministic keychain for tornadocash wallets.
#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
pub trait Keychain: Send + Sync {
    /// Gets the secret and nullifier for a given pool and nonce.
    ///
    /// The secret and nullifier must be derived deterministically from the pool and nonce.
    ///
    /// # Errors
    /// Returns an error if the material cannot be derived.
    async fn note(&self, pool: &Pool, nonce: u64) -> Result<NoteString, KeychainError>;

    /// Gets the deposit commitment for a given pool and nonce.
    ///
    /// # Errors
    /// Returns an error if the material cannot be derived.
    async fn commitment(&self, pool: &Pool, nonce: u64) -> Result<Field, KeychainError> {
        let note = self.note(pool, nonce).await?;
        Ok(note.commitment())
    }

    /// Gets the nullifier hash for a given pool and nonce.
    ///
    /// # Errors
    /// Returns an error if the material cannot be derived.
    async fn nullifier_hash(&self, pool: &Pool, nonce: u64) -> Result<Field, KeychainError> {
        let note = self.note(pool, nonce).await?;
        Ok(note.nullifier_hash())
    }

    /// Returns a deposit for `pool` at `nonce`.
    ///
    /// # Errors
    /// Returns an error if the backend cannot derive the material.
    async fn deposit(&self, pool: &Pool, nonce: u64) -> Result<Deposit, KeychainError> {
        let note = self.note(pool, nonce).await?;
        Ok(Deposit::new(pool, note.note))
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum KeychainError {
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl KeychainError {
    pub fn other<E: std::error::Error + Send + Sync + 'static>(err: E) -> Self {
        Self::Other(Box::new(err))
    }
}
