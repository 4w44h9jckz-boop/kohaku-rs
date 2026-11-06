//! The `writes` field of a patched `ethrex_simulateFrameTransaction`, as exp-e2e-frames'
//! `docs/simulated-writes.md` documents it: one entry per changed account, sorted by address, each
//! field present only when it changed, every value 0x-hex. `writes` is `null` when the full
//! execution did not run.

use alloy::primitives::{Address, B256, U256};
use serde::{Deserialize, Serialize};

/// One storage slot whose value changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotWrite {
    /// Read as a number so that a short hex form is accepted too.
    pub slot: U256,
    pub before: U256,
    pub after: U256,
}

/// One changed account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountWrites {
    pub address: Address,
    #[serde(default)]
    pub removed: bool,
    #[serde(default)]
    pub balance: Option<[U256; 2]>,
    #[serde(default)]
    pub nonce: Option<[U256; 2]>,
    #[serde(default)]
    pub code_hash: Option<[B256; 2]>,
    #[serde(default)]
    pub storage: Vec<SlotWrite>,
}

/// The parts of a simulation result the checker reads. Other fields are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Simulation {
    pub valid: bool,
    #[serde(default)]
    pub violation: Option<String>,
    #[serde(default)]
    pub execution_status: Option<String>,
    #[serde(default)]
    pub max_cost: Option<U256>,
    #[serde(default)]
    pub payer: Option<Address>,
    #[serde(default)]
    pub writes: Option<Vec<AccountWrites>>,
}

/// What changed in an account.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(tag = "field", content = "slot", rename_all = "camelCase")]
pub enum Field {
    Balance,
    Nonce,
    CodeHash,
    Storage(B256),
    Removed,
}

/// One change, flattened: an account, a field, and its value before and after.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Change {
    pub address: Address,
    #[serde(flatten)]
    pub field: Field,
    pub before: U256,
    pub after: U256,
}

/// Every change the simulation lists, in its order.
#[must_use]
pub fn changes(writes: &[AccountWrites]) -> Vec<Change> {
    let mut out = Vec::new();
    for a in writes {
        let mut push = |field, before, after| {
            out.push(Change {
                address: a.address,
                field,
                before,
                after,
            });
        };
        if a.removed {
            push(Field::Removed, U256::ZERO, U256::ZERO);
        }
        if let Some([b, c]) = a.balance {
            push(Field::Balance, b, c);
        }
        if let Some([b, c]) = a.nonce {
            push(Field::Nonce, b, c);
        }
        if let Some([b, c]) = a.code_hash {
            push(Field::CodeHash, b.into(), c.into());
        }
        for s in &a.storage {
            push(Field::Storage(B256::from(s.slot)), s.before, s.after);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_documented_shape() {
        // A fixture in docs/simulated-writes.md's format, not a chain's output.
        let json = r#"{"valid":true,"executionStatus":"success","maxCost":"0x2710","payer":"0x00000000000000000000000000000000000057a1",
          "writes":[
            {"address":"0x0000000000000000000000000000000000000000","balance":["0x0","0x5"]},
            {"address":"0x00000000000000000000000000000000000057a1","balance":["0xde0b6b3a7640000","0xde0b6b3a763fff6"]},
            {"address":"0x00000000000000000000000000000000000057a2","storage":[{"slot":"0x1","before":"0x0","after":"0x5"}]}
          ]}"#;
        let sim: Simulation = serde_json::from_str(json).unwrap();
        let c = changes(sim.writes.as_deref().unwrap());
        assert_eq!(c.len(), 3);
        assert_eq!(c[2].field, Field::Storage(B256::from(U256::from(1))));
        assert_eq!(c[2].after, U256::from(5));
    }
}
