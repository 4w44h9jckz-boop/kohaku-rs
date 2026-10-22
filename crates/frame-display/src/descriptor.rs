//! The descriptors: ERC-7730 files for the contracts a frame calls, read as they stand, and the
//! two kinds `exp-frames` experiment 38 adds beside them, for what ERC-7730 has no binding for.
//!
//! - [`Erc7730`]: the subset of ERC-7730 v2 a contract call needs. `context.contract.deployments`
//!   binds it; `display.formats` is keyed by ABI fragment; fields take the formats `raw`,
//!   `addressName`, `tokenAmount`, `amount`, `date` and `enum`, and the paths `@.from`, `@.to`,
//!   `@.value`, `@.chainId`, `$.metadata.constants.*` and the fragment's own parameter names.
//! - [`AccountDescriptor`]: one per account implementation. It binds by code, not by address:
//!   the creation code a deploy frame carries or the runtime code a host can supply, each
//!   followed by ABI-encoded arguments. It says, in `verify`, what the account's `VERIFY` frame
//!   approves for a given signature entry, and, in `display.formats`, how to show the calls the
//!   account makes to itself, keyed by ABI or packed fragment.
//! - [`DeployerDescriptor`]: a deployer whose calldata is not ABI, such as the CREATE2 deployer's
//!   `salt || initcode`.

use std::collections::BTreeMap;

use alloy::primitives::{Address, Bytes, U256};
use serde::Deserialize;
use serde_json::Value;

use crate::value::{AbiLayout, LayoutError, PackedLayout, Val, Values};

/// A `chainId` and `address` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Deployment {
    pub chain_id: u64,
    pub address: Address,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    #[serde(default)]
    pub owner: Option<String>,
    #[serde(default)]
    pub contract_name: Option<String>,
    #[serde(default)]
    pub constants: BTreeMap<String, Value>,
    #[serde(default)]
    pub enums: BTreeMap<String, BTreeMap<String, String>>,
}

impl Metadata {
    /// The name a wallet shows for the bound contract.
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        self.contract_name.as_deref().or(self.owner.as_deref())
    }
}

/// One field of a format.
#[derive(Debug, Clone, Deserialize)]
pub struct Field {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, Value>,
}

/// A structured data format specification: one function's display.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Format {
    pub intent: Value,
    #[serde(default)]
    pub interpolated_intent: Option<String>,
    #[serde(default)]
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DisplaySection {
    #[serde(default)]
    pub formats: BTreeMap<String, Format>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContractContext {
    pub deployments: Vec<Deployment>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Erc7730Context {
    #[serde(rename = "$id", default)]
    pub id: Option<String>,
    pub contract: ContractContext,
}

/// An ERC-7730 file bound to a contract.
#[derive(Debug, Clone, Deserialize)]
pub struct Erc7730 {
    pub context: Erc7730Context,
    #[serde(default)]
    pub metadata: Metadata,
    #[serde(default)]
    pub display: DisplaySection,
}

impl Erc7730 {
    #[must_use]
    pub fn binds(&self, chain_id: u64, address: Address) -> bool {
        self.context
            .contract
            .deployments
            .iter()
            .any(|d| d.chain_id == chain_id && d.address == address)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        self.context
            .id
            .as_deref()
            .or(self.metadata.name())
            .unwrap_or("ERC-7730")
    }

    /// The format whose selector matches `data`, with its decoded parameters. `Ok(None)` when no
    /// key has the selector; an error when one has it and the data does not decode.
    pub fn select(&self, data: &[u8]) -> Result<Option<(&Format, Values)>, LayoutError> {
        let Some(selector) = crate::value::selector_of(data) else {
            return Ok(None);
        };
        for (key, format) in &self.display.formats {
            let layout = AbiLayout::parse(key)?;
            if layout.selector() == selector {
                return Ok(Some((format, layout.decode(data)?)));
            }
        }
        Ok(None)
    }
}

/// Which signature entry's signer a `verify` rule is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SignerRule {
    /// The `owner` argument of the account's code.
    Owner,
    /// Any signer that is not the owner.
    Other,
}

/// What the entry's `msg` is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum MsgRule {
    /// Empty: the entry signs the canonical signature hash.
    #[serde(rename = "sigHash")]
    SigHash,
    /// The execution digest E of `exp-frames` experiment 27's draft ERC.
    FrameExecution,
}

/// The scopes a rule can approve: what the frame's flags allow, or a fixed list.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Approves {
    Allowed(String),
    Only(Vec<u8>),
}

/// One way the account's `VERIFY` frame approves.
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyRule {
    /// The signature entry the frame reads.
    pub entry: usize,
    pub signer: SignerRule,
    pub msg: MsgRule,
    pub approves: Approves,
    pub intent: String,
    /// What else the frame checks in the transaction.
    #[serde(default)]
    pub requires: Option<String>,
    /// What it reads from storage, which a device does not have.
    #[serde(default)]
    pub state: Option<String>,
}

impl VerifyRule {
    /// Whether the rule can approve `scope`.
    #[must_use]
    pub fn can_approve(&self, scope: u8) -> bool {
        match &self.approves {
            Approves::Allowed(_) => true,
            Approves::Only(scopes) => scopes.contains(&scope),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountBinding {
    /// Creation code, before the arguments: what a deploy frame's initcode starts with.
    #[serde(default)]
    pub creation_code: Option<Bytes>,
    /// Runtime code, before the arguments: what the account's code starts with.
    #[serde(default)]
    pub runtime_code: Option<Bytes>,
    /// The arguments that follow the code, ABI-encoded, as a parameter list: `(address owner)`.
    pub args: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountContext {
    #[serde(rename = "$id")]
    pub id: String,
    pub account: AccountBinding,
}

/// One account implementation.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountDescriptor {
    pub context: AccountContext,
    #[serde(default)]
    pub metadata: Metadata,
    pub verify: Vec<VerifyRule>,
    #[serde(default)]
    pub display: DisplaySection,
}

impl AccountDescriptor {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.context.id
    }

    /// The arguments, if `code` is the binding's `template` followed by them.
    pub fn args_after(&self, template: &[u8], code: &[u8]) -> Option<Values> {
        let encoded = code.strip_prefix(template)?;
        let layout = AbiLayout::parse(&format!("args{}", self.context.account.args)).ok()?;
        let mut data = layout.selector().to_vec();
        data.extend_from_slice(encoded);
        layout.decode(&data).ok()
    }

    /// The arguments, if `initcode` is this implementation's creation code and its arguments.
    #[must_use]
    pub fn match_initcode(&self, initcode: &[u8]) -> Option<Values> {
        self.args_after(self.context.account.creation_code.as_ref()?, initcode)
    }

    /// A self-call's format and values: an ABI key by selector, or a packed key by tag.
    pub fn select(&self, data: &[u8]) -> Result<Option<(&Format, Values)>, LayoutError> {
        for (key, format) in &self.display.formats {
            if key.starts_with("0x") {
                let layout = PackedLayout::parse(key)?;
                if data.starts_with(layout.tag()) {
                    return Ok(Some((format, layout.decode(data)?)));
                }
            } else {
                let layout = AbiLayout::parse(key)?;
                if crate::value::selector_of(data) == Some(layout.selector()) {
                    return Ok(Some((format, layout.decode(data)?)));
                }
            }
        }
        Ok(None)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeployerBinding {
    pub deployments: Vec<Deployment>,
    /// The calldata layout. Only `salt (bytes32) || initcode` is defined.
    pub calldata: String,
    /// How the new address follows. Only `create2` is defined.
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeployerContext {
    #[serde(rename = "$id")]
    pub id: String,
    pub deployer: DeployerBinding,
}

/// A deployer whose calldata is not ABI.
#[derive(Debug, Clone, Deserialize)]
pub struct DeployerDescriptor {
    pub context: DeployerContext,
    #[serde(default)]
    pub metadata: Metadata,
}

impl DeployerDescriptor {
    #[must_use]
    pub fn binds(&self, chain_id: u64, address: Address) -> bool {
        self.context
            .deployer
            .deployments
            .iter()
            .any(|d| d.chain_id == chain_id && d.address == address)
    }

    /// The salt and the initcode, if `data` has this deployer's layout.
    #[must_use]
    pub fn split<'a>(&self, data: &'a [u8]) -> Option<([u8; 32], &'a [u8])> {
        if self.context.deployer.calldata != "salt (bytes32) || initcode"
            || self.context.deployer.address != "create2"
        {
            return None;
        }
        let (salt, initcode) = data.split_at_checked(32)?;
        Some((salt.try_into().ok()?, initcode))
    }
}

/// A token in the wallet's list.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    pub chain_id: u64,
    pub address: Address,
    pub name: String,
    pub ticker: String,
    pub decimals: u8,
}

/// A name in the wallet's address book.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Name {
    pub chain_id: u64,
    pub address: Address,
    pub name: String,
}

/// An account the wallet set up, and the implementation it runs.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletAccount {
    pub chain_id: u64,
    pub address: Address,
    pub implementation: String,
    #[serde(default)]
    pub args: BTreeMap<String, Value>,
}

/// What the wallet knows beside the descriptors.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct WalletData {
    #[serde(default)]
    pub tokens: Vec<Token>,
    #[serde(default)]
    pub names: Vec<Name>,
    #[serde(default)]
    pub accounts: Vec<WalletAccount>,
}

/// Read a JSON value as a `U256`: a number, or a decimal or `0x` string.
#[must_use]
pub fn json_u256(v: &Value) -> Option<U256> {
    match v {
        Value::Number(n) => n.as_u64().map(U256::from),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Read a JSON value as a decoded value: an address, or an integer.
#[must_use]
pub fn json_val(v: &Value) -> Option<Val> {
    if let Value::String(s) = v
        && let Ok(a) = s.parse::<Address>()
    {
        return Some(Val::Address(a));
    }
    json_u256(v).map(Val::Uint)
}
