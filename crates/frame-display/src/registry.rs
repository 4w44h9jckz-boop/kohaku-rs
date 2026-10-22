//! The descriptors a device has, and the wallet's own data, loaded from one directory:
//!
//! ```text
//! erc7730/*.json    ERC-7730 files, one per contract
//! accounts/*.json   account descriptors, one per implementation
//! system/*.json     deployer descriptors
//! wallet.json       the wallet's token list, address book and accounts
//! ```

use std::{fs, path::Path};

use alloy::primitives::{Address, B256, keccak256};
use serde::de::DeserializeOwned;

use crate::{
    descriptor::{
        AccountDescriptor, DeployerDescriptor, Erc7730, Token, WalletAccount, WalletData,
    },
    format::Book,
};

#[derive(Debug, thiserror::Error)]
pub enum LoadError {
    #[error("{0}: {1}")]
    Io(String, std::io::Error),
    #[error("{0}: {1}")]
    Json(String, serde_json::Error),
}

/// Every descriptor, and the hash of every file read.
#[derive(Debug, Clone, Default)]
pub struct Registry {
    pub contracts: Vec<Erc7730>,
    pub accounts: Vec<AccountDescriptor>,
    pub deployers: Vec<DeployerDescriptor>,
    pub wallet: WalletData,
    /// Each file's path under the directory and `keccak256` of its bytes.
    pub files: Vec<(String, B256)>,
}

fn read<T: DeserializeOwned>(
    root: &Path,
    rel: &str,
    files: &mut Vec<(String, B256)>,
) -> Result<T, LoadError> {
    let bytes = fs::read(root.join(rel)).map_err(|e| LoadError::Io(rel.to_owned(), e))?;
    files.push((rel.to_owned(), keccak256(&bytes)));
    serde_json::from_slice(&bytes).map_err(|e| LoadError::Json(rel.to_owned(), e))
}

fn json_files(root: &Path, dir: &str) -> Result<Vec<String>, LoadError> {
    let Ok(entries) = fs::read_dir(root.join(dir)) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for e in entries {
        let name = e
            .map_err(|e| LoadError::Io(dir.to_owned(), e))?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if Path::new(&name)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        {
            out.push(format!("{dir}/{name}"));
        }
    }
    out.sort();
    Ok(out)
}

impl Registry {
    pub fn load(root: &Path) -> Result<Self, LoadError> {
        let mut r = Self::default();
        let mut files = Vec::new();
        for rel in json_files(root, "erc7730")? {
            r.contracts.push(read(root, &rel, &mut files)?);
        }
        for rel in json_files(root, "accounts")? {
            r.accounts.push(read(root, &rel, &mut files)?);
        }
        for rel in json_files(root, "system")? {
            r.deployers.push(read(root, &rel, &mut files)?);
        }
        if root.join("wallet.json").exists() {
            r.wallet = read(root, "wallet.json", &mut files)?;
        }
        r.files = files;
        Ok(r)
    }

    #[must_use]
    pub fn contract(&self, chain_id: u64, address: Address) -> Option<&Erc7730> {
        self.contracts.iter().find(|d| d.binds(chain_id, address))
    }

    #[must_use]
    pub fn implementation(&self, id: &str) -> Option<&AccountDescriptor> {
        self.accounts.iter().find(|a| a.id() == id)
    }

    #[must_use]
    pub fn deployer(&self, chain_id: u64, address: Address) -> Option<&DeployerDescriptor> {
        self.deployers.iter().find(|d| d.binds(chain_id, address))
    }

    #[must_use]
    pub fn wallet_account(&self, chain_id: u64, address: Address) -> Option<&WalletAccount> {
        self.wallet
            .accounts
            .iter()
            .find(|a| a.chain_id == chain_id && a.address == address)
    }
}

impl Book for Registry {
    fn name(&self, chain_id: u64, address: Address) -> Option<String> {
        if let Some(n) = self
            .wallet
            .names
            .iter()
            .find(|n| n.chain_id == chain_id && n.address == address)
        {
            return Some(n.name.clone());
        }
        if let Some(t) = self.token(chain_id, address) {
            return Some(t.name.clone());
        }
        if let Some(d) = self.contract(chain_id, address) {
            return d.metadata.name().map(str::to_owned);
        }
        self.deployer(chain_id, address)
            .map(|d| d.metadata.name().unwrap_or(&d.context.id).to_owned())
    }

    fn token(&self, chain_id: u64, address: Address) -> Option<&Token> {
        self.wallet
            .tokens
            .iter()
            .find(|t| t.chain_id == chain_id && t.address == address)
    }
}
