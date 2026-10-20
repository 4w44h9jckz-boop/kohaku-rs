//! ERC-7715's execution permissions, bound to `SessionAccount`'s session keys.
//!
//! ERC-7715 (Draft, read at `ethereum/ERCs` `48dc87a2897c`) requires ERC-4337 and ERC-7710: a
//! granted permission is redeemed by the `to` account calling a delegation manager's
//! `redeemDelegations`. Over frames the account's own `VERIFY` is the delegation manager. The
//! session key that `to` names signs a frame transaction whose sender is the user's account, in
//! the four-frame shape `SessionAccount` checks, and anyone may send it.
//!
//! | ERC-7715 | Frames binding |
//! |---|---|
//! | `from` | the user's `SessionAccount` |
//! | `to` | the session key: the address whose secp256k1 signature the account accepts for the session |
//! | `permission` `native-token-allowance`, `data.allowance` | the session's budget in wei, which counts value sent and each transaction's maximum fee |
//! | rule `expiry`, `data.timestamp` | the session's `validUntil`; required, since every session transaction carries an expiry frame |
//! | rule `call-target`, `data.target`, `data.selector` | not in ERC-7715: the one contract and the one function the session may call; required |
//! | `isAdjustmentAllowed` | never used: the wallet grants what was asked or refuses |
//! | `context` | `account (20 bytes) || session key (20 bytes)` |
//! | `delegationManager` | the account itself, whose `VERIFY` checks the session |
//! | `dependencies` | always empty: the account must already be deployed |
//! | redemption, `redeemDelegations` | a frame transaction `[expiry] [VERIFY account] [SENDER spend record] [SENDER calls]`, signed by the session key |
//! | `wallet_revokeExecutionPermission` | the owner's transaction removing the session; a pending session transaction is overtaken by replacement |

use alloy::primitives::{Address, Bytes, U64, U256};
use kohaku_frame_accounts::session::SessionPolicy;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::ProviderError;

/// The one permission type this binding grants.
pub const NATIVE_TOKEN_ALLOWANCE: &str = "native-token-allowance";
/// ERC-7715's own rule: a deadline.
pub const EXPIRY: &str = "expiry";
/// This binding's rule: the one target and selector a `SessionAccount` session is scoped to.
pub const CALL_TARGET: &str = "call-target";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Permission {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub is_adjustment_allowed: bool,
    #[serde(default)]
    pub data: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub data: Value,
}

/// One entry of `wallet_requestExecutionPermissions`'s parameter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRequest {
    pub chain_id: U64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    pub to: Address,
    pub permission: Permission,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}

/// A granted permission: the request, and what the session became.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Granted {
    pub request: PermissionRequest,
    pub account: Address,
    pub key: Address,
    pub policy: SessionPolicy,
}

impl Granted {
    /// `account || key`, what revocation names.
    #[must_use]
    pub fn context(&self) -> Bytes {
        context_of(self.account, self.key)
    }

    /// ERC-7715's `PermissionResponse`: the request as granted, plus the binding's fields.
    #[must_use]
    pub fn response(&self) -> Value {
        let mut out = serde_json::to_value(&self.request).unwrap_or_default();
        out["from"] = json!(self.account);
        out["context"] = json!(self.context());
        out["dependencies"] = json!([]);
        out["delegationManager"] = json!(self.account);
        out
    }
}

#[must_use]
pub fn context_of(account: Address, key: Address) -> Bytes {
    let mut out = Vec::with_capacity(40);
    out.extend_from_slice(account.as_slice());
    out.extend_from_slice(key.as_slice());
    out.into()
}

/// `wallet_getSupportedExecutionPermissions`'s answer.
#[must_use]
pub fn supported(chain_id: u64) -> Value {
    json!({
        NATIVE_TOKEN_ALLOWANCE: {
            "chainIds": [U64::from(chain_id)],
            "ruleTypes": [EXPIRY, CALL_TARGET],
        }
    })
}

fn field<'a>(data: &'a Value, name: &str, what: &str) -> Result<&'a Value, ProviderError> {
    data.get(name)
        .ok_or_else(|| ProviderError::invalid_params(format!("{what} has no `{name}`")))
}

fn parse<T: serde::de::DeserializeOwned>(v: &Value, what: &str) -> Result<T, ProviderError> {
    serde_json::from_value(v.clone())
        .map_err(|e| ProviderError::invalid_params(format!("{what}: {e}")))
}

impl PermissionRequest {
    /// The session this request asks for, or why the account cannot hold it.
    ///
    /// A rule the account cannot enforce is refused rather than ignored: ERC-7715 says the `to`
    /// account "MUST abide by" every rule, and only the account's code makes it.
    pub fn policy(&self, chain_id: u64, account: Address) -> Result<SessionPolicy, ProviderError> {
        if self.chain_id.to::<u64>() != chain_id {
            return Err(ProviderError::new(
                5710,
                format!("unsupported chain id {}", self.chain_id),
            ));
        }
        if self.from.is_some_and(|f| f != account) {
            return Err(ProviderError::new(
                4100,
                format!(
                    "{} is not this wallet's account",
                    self.from.unwrap_or_default()
                ),
            ));
        }
        if self.permission.kind != NATIVE_TOKEN_ALLOWANCE {
            return Err(ProviderError::invalid_params(format!(
                "permission type {} is not supported; {NATIVE_TOKEN_ALLOWANCE} is",
                self.permission.kind
            )));
        }
        let allowance: U256 = parse(
            field(&self.permission.data, "allowance", NATIVE_TOKEN_ALLOWANCE)?,
            "allowance",
        )?;
        let budget = u128::try_from(allowance)
            .map_err(|_| ProviderError::invalid_params("allowance does not fit 128 bits"))?;
        let (mut valid_until, mut scope) = (None, None);
        for rule in &self.rules {
            match rule.kind.as_str() {
                EXPIRY => {
                    valid_until = Some(parse::<u64>(
                        field(&rule.data, "timestamp", EXPIRY)?,
                        "timestamp",
                    )?);
                }
                CALL_TARGET => {
                    let target: Address =
                        parse(field(&rule.data, "target", CALL_TARGET)?, "target")?;
                    let selector: Bytes = rule
                        .data
                        .get("selector")
                        .map(|s| parse(s, "selector"))
                        .transpose()?
                        .unwrap_or_default();
                    let selector: [u8; 4] = match selector.len() {
                        0 => [0; 4],
                        4 => selector[..].try_into().unwrap_or_default(),
                        n => {
                            return Err(ProviderError::invalid_params(format!(
                                "selector must be 4 bytes or empty, got {n}"
                            )));
                        }
                    };
                    scope = Some((target, selector));
                }
                other => {
                    return Err(ProviderError::invalid_params(format!(
                        "rule {other} is not supported, and this account cannot enforce it"
                    )));
                }
            }
        }
        let valid_until = valid_until.ok_or_else(|| {
            ProviderError::invalid_params(
                "a session needs an `expiry` rule: every session transaction carries a deadline",
            )
        })?;
        let (target, selector) = scope.ok_or_else(|| {
            ProviderError::invalid_params(format!(
                "a session needs a `{CALL_TARGET}` rule: the account scopes it to one target and one selector"
            ))
        })?;
        if target == account {
            return Err(ProviderError::invalid_params(
                "a session may not call the account itself",
            ));
        }
        Ok(SessionPolicy {
            target,
            selector,
            valid_until,
            budget,
        })
    }
}
