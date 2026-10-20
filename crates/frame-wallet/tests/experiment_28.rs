//! The frame transactions `exp-frames` experiment 28 sent, rebuilt by this crate: eight from
//! its TypeScript wallet, and four from this crate's `frame-wallet`, driven by the same
//! `dapp.ts` (cases B to E, its second run on 2026-10-20). Each is rebuilt from what a wallet
//! decides: the calls, whether they are atomic, the payer's quote, the
//! envelope, and each call frame's execution budget tightened from its use.
//!
//! The users' keys are not here, so a rebuild must reach the mined signature hash; with the
//! mined signature put back it must then be the mined transaction, byte for byte.
//!
//! `exp-frames` experiment 38's descriptors, from `kohaku-frame-display`'s fixtures, show each
//! batch as the device would.
//!
//! `binding-0x9688c1f8.json` is experiment 28's own `frameTxToRpc` applied to case C's fixture,
//! printed by `frameTxFromJson` and `frameTxToRpc` from `exp-frames` at `1d709ad`.

use std::{fs, path::Path};

use alloy::primitives::{Address, U256};
use kohaku_frame_accounts::{
    account::{Eoa, Signer},
    builder::Envelope,
};
use kohaku_frame_display::{
    Registry, Rules,
    format::{self, Container},
    render,
};
use kohaku_frame_kit::{
    FrameTx,
    constants::{ATOMIC_BATCH_FLAG, mode},
    json::{FrameTxJson, FrameTxReceiptJson},
};
use kohaku_frame_wallet::{
    binding::{QuotedSponsor, RpcFrameTx},
    calls::{Call, batch_tx, call_frame_indexes, call_frames, status_code, tightened},
};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
    receipt: FrameTxReceiptJson,
}

fn fixtures() -> Vec<(String, FrameTx, FrameTxReceiptJson)> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chain");
    let mut out: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            let f: Fixture = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            let name = path.file_stem().unwrap().to_string_lossy()[..10].to_owned();
            (name, FrameTx::try_from(&f.tx).unwrap(), f.receipt)
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// The batch as the dapp asked for it, read back from the mined transaction.
fn calls_of(tx: &FrameTx) -> (Vec<Call>, bool) {
    let frames: Vec<_> = tx
        .frames
        .iter()
        .filter(|f| f.mode == mode::SENDER)
        .collect();
    let calls = frames
        .iter()
        .map(|f| Call {
            to: f.target,
            data: Some(f.data.clone()),
            value: Some(f.value),
            capabilities: std::collections::BTreeMap::default(),
        })
        .collect();
    (calls, frames[0].flags & ATOMIC_BATCH_FLAG != 0)
}

#[test]
fn rebuilds_every_batch_experiment_28_sent() {
    let fixtures = fixtures();
    assert_eq!(fixtures.len(), 12);
    let mut sponsored = 0;
    for (name, mined, receipt) in fixtures {
        let (calls, atomic) = calls_of(&mined);
        let mut sponsor = QuotedSponsor::from_mined(&mined);
        sponsored += usize::from(sponsor.is_some());
        let envelope = Envelope {
            chain_id: mined.chain_id,
            nonce_keys: mined.nonce_keys.clone(),
            nonce_seq: mined.nonce_seq,
            fees: mined.fees,
        };
        let execution: Vec<u64> = call_frame_indexes(&mined)
            .iter()
            .map(|&i| tightened(receipt.frame_receipts[i].gas_used.to()))
            .collect();
        let account = Eoa::new(Signer::secp256k1(mined.sender));
        let mut built = batch_tx(
            &account,
            sponsor
                .as_mut()
                .map(|s| s as &mut dyn kohaku_frame_accounts::sponsor::Sponsor),
            call_frames(&calls, atomic, &execution),
            &envelope,
        )
        .unwrap();
        assert_eq!(built.sig_hash(), mined.sig_hash(), "{name}");
        built.signatures[0].signature = mined.signatures[0].signature.clone();
        assert_eq!(built, mined, "{name}");
        assert_eq!(built.hash(), mined.hash(), "{name}");
    }
    // Case C from each wallet, and the two sponsored rails rows.
    assert_eq!(sponsored, 4);
}

#[test]
fn derives_the_status_experiment_28_reported() {
    // B, C and the rails rows 200; D 600, two of three calls persisted; E 500, rolled back.
    assert_eq!(fixtures().len(), 12);
    let expected = [
        ("0x0cd8150d", 200),
        ("0x28885722", 200),
        ("0x32eb0bc5", 200),
        ("0x3fc65c1d", 500),
        ("0x57135ff7", 200),
        ("0x644424fe", 200),
        ("0x6c5d0038", 600),
        ("0x78564f0a", 600),
        ("0x9489899e", 200),
        ("0x9688c1f8", 200),
        ("0xd3c04b29", 200),
        ("0xf00c9f2c", 500),
    ];
    for ((name, mined, receipt), (want_name, want)) in fixtures().into_iter().zip(expected) {
        assert_eq!(name, want_name);
        let (_, atomic) = calls_of(&mined);
        let statuses: Vec<u64> = call_frame_indexes(&mined)
            .iter()
            .map(|&i| receipt.frame_receipts[i].status.to())
            .collect();
        assert_eq!(status_code(atomic, &statuses), want, "{name}");
        // ethrex's own transaction status says failure whenever any frame failed.
        let any_failed = receipt
            .frame_receipts
            .iter()
            .any(|f| f.status != U256::from(1));
        assert_eq!(receipt.status == U256::ZERO, any_failed, "{name}");
    }
}

/// What ERC-7730 shows for one EIP-5792 call, in its EVM transaction container.
fn call_intent(registry: &Registry, chain_id: u64, from: Address, call: &Call) -> String {
    let to = call.to.unwrap();
    let d = registry.contract(chain_id, to).unwrap();
    let data = call.data.clone().unwrap_or_default();
    let (fmt, values) = d.select(&data).unwrap().unwrap();
    let container = Container {
        chain_id,
        from,
        to,
        value: call.value.unwrap_or_default(),
    };
    format::apply(fmt, &values, container, &d.metadata, registry)
        .unwrap()
        .intent
}

#[test]
fn shows_each_batch_as_erc_7730_shows_its_calls() {
    let registry = Registry::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../frame-display/tests/fixtures/descriptors"),
    )
    .unwrap();
    for (name, mined, _) in fixtures() {
        let (calls, _) = calls_of(&mined);
        let review = render(&mined, 0, &registry, Rules::HEGOTA_TESTNET).unwrap();
        // ERC-7730 joins a batch's intents with " and "; each SENDER frame is its call, in an EVM
        // transaction container from the sender.
        let joined: Vec<String> = calls
            .iter()
            .map(|c| call_intent(&registry, mined.chain_id, mined.sender, c))
            .collect();
        assert_eq!(review.intent, joined.join(" and "), "{name}");
        assert!(review.gaps.is_empty(), "{name}: {:?}", review.gaps);
    }
}

fn lowercase(v: Value) -> Value {
    match v {
        Value::String(s) => Value::String(s.to_lowercase()),
        Value::Array(a) => Value::Array(a.into_iter().map(lowercase).collect()),
        Value::Object(o) => Value::Object(o.into_iter().map(|(k, v)| (k, lowercase(v))).collect()),
        other => other,
    }
}

#[test]
fn speaks_experiment_28s_binding() {
    let (_, mined, _) = fixtures()
        .into_iter()
        .find(|(n, ..)| n == "0x9688c1f8")
        .unwrap();
    let golden: Value = serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/binding-0x9688c1f8.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let ours = serde_json::to_value(RpcFrameTx::from(&mined)).unwrap();
    // Addresses are checksummed on one side and not the other; nothing else differs.
    assert_eq!(lowercase(ours), lowercase(golden.clone()));
    let back = FrameTx::try_from(&serde_json::from_value::<RpcFrameTx>(golden).unwrap()).unwrap();
    assert_eq!(back, mined);
}
