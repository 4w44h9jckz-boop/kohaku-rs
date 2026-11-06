//! Storage layouts: what a slot of a known contract means. A template speaks of resources ("the
//! recipient's balance of T"); the simulation lists slots. A contract the registry does not know
//! cannot have a write matched to a resource.

use std::collections::HashMap;

use alloy::primitives::{Address, B256, U256, keccak256};
use serde::{Deserialize, Serialize};

/// A contract's kind and the declaration slots of its mappings, as solc lays them out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Contract {
    /// `balanceOf` and `allowance` mappings at these declaration slots.
    #[serde(rename_all = "camelCase")]
    Erc20 { balance_slot: u64, allowance_slot: u64 },
    /// `isApprovedForAll` at this declaration slot.
    #[serde(rename_all = "camelCase")]
    Collection { operator_slot: u64 },
    /// An account keeping its owner and its implementation in storage.
    #[serde(rename_all = "camelCase")]
    Account { owner_slot: U256, implementation_slot: U256 },
    /// A pool marking spent nullifiers in a mapping at this declaration slot.
    #[serde(rename_all = "camelCase")]
    Pool { nullifier_slot: u64 },
    /// A contract that holds tokens and keeps no storage of its own the templates expect to change.
    Dex,
}

/// Contracts by address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Registry(pub HashMap<Address, Contract>);

impl Registry {
    #[must_use]
    pub fn get(&self, a: Address) -> Option<&Contract> {
        self.0.get(&a)
    }
}

/// `keccak256(pad32(key) || uint256(slot))`: a mapping entry.
#[must_use]
pub fn mapping_slot(key: B256, slot: U256) -> B256 {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(key.as_slice());
    buf[32..].copy_from_slice(&slot.to_be_bytes::<32>());
    keccak256(buf)
}

/// An address as a mapping key.
#[must_use]
pub fn key(a: Address) -> B256 {
    a.into_word()
}

/// `m[a]` for a mapping declared at `slot`.
#[must_use]
pub fn address_slot(a: Address, slot: u64) -> B256 {
    mapping_slot(key(a), U256::from(slot))
}

/// `m[a][b]` for a nested mapping declared at `slot`.
#[must_use]
pub fn nested_slot(a: Address, b: Address, slot: u64) -> B256 {
    mapping_slot(key(b), address_slot(a, slot).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn registry_reads_its_json() {
        let r: Registry = serde_json::from_str(
            r#"{"0x2700000000000000000000000000000000000010":{"kind":"erc20","balanceSlot":3,"allowanceSlot":4}}"#,
        )
        .unwrap();
        assert_eq!(
            r.get(address!("0x2700000000000000000000000000000000000010")),
            Some(&Contract::Erc20 { balance_slot: 3, allowance_slot: 4 })
        );
    }

    #[test]
    fn nested_is_keccak_of_keccak() {
        let (a, b) = (Address::repeat_byte(1), Address::repeat_byte(2));
        assert_eq!(nested_slot(a, b, 4), mapping_slot(key(b), address_slot(a, 4).into()));
    }
}
