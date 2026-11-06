//! Intents picked from templates. The user picks a template and fills in its parameters; no model
//! is involved. A template expands, through the registry's layouts, into the writes it allows.

use std::collections::HashMap;

use alloy::primitives::{Address, Bytes, I256, U256};
use serde::Serialize;

use crate::layout::{Contract, Registry, address_slot, nested_slot};
use crate::writes::Field;

/// What an allowed write must do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "expect", content = "value", rename_all = "camelCase")]
pub enum Expect {
    /// `after == before + delta`.
    Delta(I256),
    /// `after == value`.
    Exact(U256),
    /// `after == value` if the field changed at all; the write may also be absent.
    ExactIfChanged(U256),
    /// A swap's output, moving by one amount `>= min` that every `SwapOut` of the intent shares:
    /// `sign` is +1 where it arrives and -1 where it leaves.
    SwapOut { sign: i8, min: U256 },
}

/// One allowed write, with the getter that reads it back, if it has one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Allowed {
    pub what: String,
    pub address: Address,
    pub field: Field,
    pub expect: Expect,
    /// `(target, calldata)` of a view call whose first word is the field's value.
    pub getter: Option<(Address, Bytes)>,
}

/// An expanded intent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Intent {
    pub template: String,
    pub allowed: Vec<Allowed>,
    /// Ether the intent sends from the sender, beside the fee.
    pub value_out: U256,
}

#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    #[error("unknown template {0:?}; known: {KNOWN}")]
    Unknown(String),
    #[error("template {0}: missing parameter {1:?}")]
    Missing(&'static str, &'static str),
    #[error("template {0}: parameter {1:?}: {2}")]
    Bad(&'static str, &'static str, String),
    #[error("template {0}: {1} is not a known {2} in the registry")]
    NotRegistered(&'static str, Address, &'static str),
}

pub const KNOWN: &str = "erc20-transfer, eth-transfer, approve-and-swap, pool-withdrawal, calls-only";

const BALANCE_OF: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
const ALLOWANCE: [u8; 4] = [0xdd, 0x62, 0xed, 0x3e];

fn call(sel: [u8; 4], args: &[Address]) -> Bytes {
    let mut v = sel.to_vec();
    for a in args {
        v.extend_from_slice(a.into_word().as_slice());
    }
    v.into()
}

struct Params<'a, S> {
    name: &'static str,
    map: &'a HashMap<String, String, S>,
}

impl<S: std::hash::BuildHasher> Params<'_, S> {
    fn raw(&self, k: &'static str) -> Result<&str, TemplateError> {
        self.map.get(k).map(String::as_str).ok_or(TemplateError::Missing(self.name, k))
    }
    fn address(&self, k: &'static str) -> Result<Address, TemplateError> {
        self.raw(k)?.parse().map_err(|e| TemplateError::Bad(self.name, k, format!("{e}")))
    }
    fn amount(&self, k: &'static str) -> Result<U256, TemplateError> {
        let s = self.raw(k)?;
        let r = if let Some(h) = s.strip_prefix("0x") { U256::from_str_radix(h, 16) } else { U256::from_str_radix(s, 10) };
        r.map_err(|e| TemplateError::Bad(self.name, k, format!("{e}")))
    }
    fn opt_amount(&self, k: &'static str) -> Result<Option<U256>, TemplateError> {
        if self.map.contains_key(k) { self.amount(k).map(Some) } else { Ok(None) }
    }
}

fn erc20(name: &'static str, reg: &Registry, t: Address) -> Result<(u64, u64), TemplateError> {
    match reg.get(t) {
        Some(Contract::Erc20 { balance_slot, allowance_slot }) => Ok((*balance_slot, *allowance_slot)),
        _ => Err(TemplateError::NotRegistered(name, t, "ERC-20")),
    }
}

fn neg(v: U256) -> I256 {
    -I256::from_raw(v)
}

/// Token balance of `who` in `token`, moving by `expect`.
fn token_balance(token: Address, bal: u64, who: Address, expect: Expect, what: String) -> Allowed {
    Allowed {
        what,
        address: token,
        field: Field::Storage(address_slot(who, bal)),
        expect,
        getter: Some((token, call(BALANCE_OF, &[who]))),
    }
}

/// Expand `template` with `params` for a transaction from `sender`.
pub fn expand<S: std::hash::BuildHasher>(template: &str, params: &HashMap<String, String, S>, sender: Address, reg: &Registry) -> Result<Intent, TemplateError> {
    let mut intent = Intent { template: template.to_owned(), ..Intent::default() };
    match template {
        "erc20-transfer" => {
            let p = Params { name: "erc20-transfer", map: params };
            let (token, to, amount) = (p.address("token")?, p.address("to")?, p.amount("amount")?);
            let (bal, _) = erc20(p.name, reg, token)?;
            if to != sender && !amount.is_zero() {
                intent.allowed.push(token_balance(token, bal, sender, Expect::Delta(neg(amount)), format!("{token}: the sender's balance falls by {amount}")));
                intent.allowed.push(token_balance(token, bal, to, Expect::Delta(I256::from_raw(amount)), format!("{token}: {to}'s balance rises by {amount}")));
            }
        }
        "eth-transfer" => {
            let p = Params { name: "eth-transfer", map: params };
            let (to, value) = (p.address("to")?, p.amount("value")?);
            if to != sender && !value.is_zero() {
                intent.allowed.push(Allowed {
                    what: format!("{to}'s ether balance rises by {value}"),
                    address: to,
                    field: Field::Balance,
                    expect: Expect::Delta(I256::from_raw(value)),
                    getter: None,
                });
                intent.value_out = value;
            }
        }
        "approve-and-swap" => {
            let p = Params { name: "approve-and-swap", map: params };
            let (tin, amount_in, dex, tout, min_out) = (p.address("token-in")?, p.amount("amount-in")?, p.address("dex")?, p.address("token-out")?, p.amount("min-out")?);
            let approve = p.opt_amount("approve")?.unwrap_or(amount_in);
            let (bin, ain) = erc20(p.name, reg, tin)?;
            let (bout, _) = erc20(p.name, reg, tout)?;
            intent.allowed.push(token_balance(tin, bin, sender, Expect::Delta(neg(amount_in)), format!("{tin}: the sender pays {amount_in}")));
            intent.allowed.push(token_balance(tin, bin, dex, Expect::Delta(I256::from_raw(amount_in)), format!("{tin}: the DEX receives {amount_in}")));
            intent.allowed.push(token_balance(tout, bout, dex, Expect::SwapOut { sign: -1, min: min_out }, format!("{tout}: the DEX pays the output")));
            intent.allowed.push(token_balance(tout, bout, sender, Expect::SwapOut { sign: 1, min: min_out }, format!("{tout}: the sender receives at least {min_out}")));
            intent.allowed.push(Allowed {
                what: format!("{tin}: the DEX's allowance ends at {}", approve.saturating_sub(amount_in)),
                address: tin,
                field: Field::Storage(nested_slot(sender, dex, ain)),
                expect: Expect::ExactIfChanged(approve.saturating_sub(amount_in)),
                getter: Some((tin, call(ALLOWANCE, &[sender, dex]))),
            });
        }
        "pool-withdrawal" => {
            let p = Params { name: "pool-withdrawal", map: params };
            let (pool, to, amount, nullifier) = (p.address("pool")?, p.address("to")?, p.amount("amount")?, p.amount("nullifier")?);
            let Some(Contract::Pool { nullifier_slot }) = reg.get(pool) else {
                return Err(TemplateError::NotRegistered(p.name, pool, "pool"));
            };
            intent.allowed.push(Allowed {
                what: format!("{pool}: nullifier {nullifier:#x} spent"),
                address: pool,
                field: Field::Storage(crate::layout::mapping_slot(nullifier.into(), U256::from(*nullifier_slot))),
                expect: Expect::Exact(U256::from(1)),
                getter: None,
            });
            intent.allowed.push(Allowed { what: format!("{pool}: pays out {amount}"), address: pool, field: Field::Balance, expect: Expect::Delta(neg(amount)), getter: None });
            intent.allowed.push(Allowed { what: format!("{to}: receives {amount}"), address: to, field: Field::Balance, expect: Expect::Delta(I256::from_raw(amount)), getter: None });
        }
        "calls-only" => {}
        other => return Err(TemplateError::Unknown(other.to_owned())),
    }
    Ok(intent)
}
