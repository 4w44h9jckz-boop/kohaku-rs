//! Transactions mined on the ethrex Hegota testnet by the `exp-frames` experiments.

use std::{fs, path::Path};

use alloy::primitives::U256;
use kohaku_frame_kit::{
    FrameTx,
    constants::scheme,
    gas::{FrameGasUsed, settled_gas_used},
    json::{FrameTxJson, FrameTxReceiptJson},
    signer_of,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    /// The RPC does not expose the EIP-3529 refund counter. Fixtures whose execution clears
    /// storage record it here, derived from ethrex's SSTORE rules, with a note saying how.
    #[serde(default)]
    meta: Meta,
    tx: FrameTxJson,
    receipt: FrameTxReceiptJson,
}

#[derive(Deserialize, Default)]
struct Meta {
    refund: Option<String>,
}

fn fixtures() -> Vec<(String, Fixture)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chain");
    let mut out: Vec<_> = fs::read_dir(dir)
        .expect("fixture directory")
        .map(|e| e.expect("entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy().into_owned();
            let fixture = serde_json::from_slice(&fs::read(&p).unwrap())
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            (name, fixture)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[test]
fn there_are_fixtures() {
    assert_eq!(fixtures().len(), 55);
}

#[test]
fn re_encodes_to_the_on_chain_hash() {
    for (name, f) in fixtures() {
        let tx = FrameTx::try_from(&f.tx).unwrap();
        assert_eq!(tx.hash(), f.tx.hash, "{name}");
        assert_eq!(FrameTx::decode(&tx.encode()).unwrap(), tx, "{name}");
    }
}

#[test]
fn every_signature_proves_its_signer_over_our_sig_hash() {
    let mut checked = [0usize; 3];
    for (name, f) in fixtures() {
        let tx = FrameTx::try_from(&f.tx).unwrap();
        let sig_hash = tx.sig_hash();
        for s in &tx.signatures {
            let who = signer_of(s, sig_hash).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(who, s.signer.unwrap_or(tx.sender), "{name}");
            checked[usize::from(s.scheme)] += 1;
        }
    }
    // Both schemes are represented, so neither path is vacuous.
    assert!(checked[usize::from(scheme::SECP256K1)] > 0);
    assert!(checked[usize::from(scheme::P256)] > 0);
}

#[test]
fn settles_to_the_receipt_gas_used() {
    for (name, f) in fixtures() {
        let tx = FrameTx::try_from(&f.tx).unwrap();
        let frames: Vec<_> = f
            .receipt
            .frame_receipts
            .iter()
            .map(|r| FrameGasUsed {
                execution: r.gas_used.to(),
                state: r.state_gas_used.to(),
            })
            .collect();
        let refund = f.meta.refund.map_or(0, |r| r.parse().unwrap());
        let settled = settled_gas_used(&tx, &frames, refund).unwrap();
        assert_eq!(U256::from(settled), f.receipt.gas_used, "{name}");
    }
}
