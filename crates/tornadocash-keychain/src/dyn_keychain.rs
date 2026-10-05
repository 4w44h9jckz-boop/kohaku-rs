use std::sync::Arc;

use kohaku_tornadocash::{Field, NoteString, Pool};

use crate::{Keychain, KeychainError};

/// Dyn-compatible keychain wrapper.
#[derive(Clone)]
pub struct DynKeychain(Arc<dyn Keychain>);

impl DynKeychain {
    pub fn new(backend: impl Keychain + 'static) -> Self {
        Self(Arc::new(backend))
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl Keychain for DynKeychain {
    async fn note(&self, pool: &Pool, nonce: u64) -> Result<NoteString, KeychainError> {
        self.0.note(pool, nonce).await
    }
    async fn commitment(&self, pool: &Pool, nonce: u64) -> Result<Field, KeychainError> {
        self.0.commitment(pool, nonce).await
    }
    async fn nullifier_hash(&self, pool: &Pool, nonce: u64) -> Result<Field, KeychainError> {
        self.0.nullifier_hash(pool, nonce).await
    }
}
