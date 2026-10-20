//! `exp-frames` experiment 38's shapes, reviewed: what each shows, and the gaps left.
//!
//! The fixtures are copies: `chain/` of `exp-frames` `test/fixtures/chain`, `exp27/` of
//! experiment 27's `erc-assets` cases files, and `descriptors/` of experiment 38's descriptors.

use std::{fs, path::Path};

use alloy::primitives::{Address, address, hex};
use kohaku_frame_display::{
    GapKind, Registry, Review, Rules, Section, Signs, render, render_typed,
    typed::{execution_typed_data, parse_execution},
};
use kohaku_frame_kit::{FrameTx, digest::execution_digest, json::FrameTxJson};
use serde::Deserialize;

fn fixtures() -> &'static Path {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures"))
}

fn registry() -> Registry {
    Registry::load(&fixtures().join("descriptors")).unwrap()
}

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
}

fn chain(prefix: &str) -> FrameTx {
    let dir = fixtures().join("chain");
    let path = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with(prefix))
        .unwrap();
    let f: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    FrameTx::try_from(&f.tx).unwrap()
}

fn cases(file: &str, rules: Rules) -> Vec<(String, String, FrameTx)> {
    fs::read_to_string(fixtures().join("exp27").join(file))
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("case "))
        .map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            (
                w[1].to_owned(),
                w[2].to_owned(),
                FrameTx::decode_with(&hex::decode(w[3]).unwrap(), rules.eip8250).unwrap(),
            )
        })
        .collect()
}

fn kinds(r: &Review) -> Vec<(Option<usize>, GapKind, bool)> {
    r.gaps.iter().map(|g| (g.frame, g.kind, g.blind)).collect()
}

fn line<'a>(r: &'a Review, label: &str) -> Option<&'a str> {
    r.lines
        .iter()
        .find(|l| l.label == label)
        .map(|l| l.value.as_str())
}

/// Experiment 27's vectors call targets that are no contract: a pool and a factory with made-up
/// selectors, and the many-frames targets. Those calls are the only frames without a descriptor.
const SYNTHETIC: [Address; 2] = [
    address!("0x2700000000000000000000000000000000000011"),
    address!("0x2700000000000000000000000000000000000012"),
];

fn synthetic(tx: &FrameTx, frame: usize) -> bool {
    let t = tx.frames[frame].target.unwrap_or(tx.sender);
    SYNTHETIC.contains(&t) || (t.0[0] == 0x27 && t.0[19] >= 0x20)
}

#[test]
fn experiment_27_accepted_cases_show_everything_but_synthetic_calls() {
    let reg = registry();
    for (file, rules, accepted) in [
        ("cases-eip8250-f3079a0.txt", Rules::HEGOTA_TESTNET, 11),
        ("cases-eip8250-master.txt", Rules::EIP8250_MASTER, 12),
    ] {
        let valid: Vec<_> = cases(file, rules)
            .into_iter()
            .filter(|c| c.1 == "valid")
            .collect();
        assert_eq!(valid.len(), accepted, "{file}");
        for (name, _, tx) in valid {
            let r = render(&tx, 0, &reg, rules).unwrap();
            assert_eq!(
                r.signs,
                Signs::ExecutionDigest {
                    digest: execution_digest(&tx)
                },
                "{name}"
            );
            for g in r.blind() {
                assert_eq!(g.kind, GapKind::NoDescriptor, "{name}: {g:?}");
                assert!(synthetic(&tx, g.frame.unwrap()), "{name}: {g:?}");
            }
            assert!(
                r.gaps
                    .iter()
                    .all(|g| g.blind || g.kind == GapKind::NotInTransaction),
                "{name}: {:?}",
                kinds(&r)
            );
            assert!(
                line(&r, "Payer").unwrap().starts_with("not signed"),
                "{name}"
            );

            // From the typed data alone: the same, but the nonce keys are a hash unless they are
            // the legacy selection.
            let message = parse_execution(&execution_typed_data(&tx)).unwrap();
            assert_eq!(message.digest, execution_digest(&tx), "{name}");
            let t = render_typed(&message, &reg, rules);
            assert_eq!(t.intent, r.intent, "{name}");
            let hash_only = t.gaps.iter().any(|g| g.kind == GapKind::HashOnly);
            assert_eq!(hash_only, tx.nonce_keys != rules.legacy_keys(), "{name}");
        }
    }
}

#[test]
fn experiment_27_refused_cases_are_flagged() {
    let reg = registry();
    for (file, rules) in [
        ("cases-eip8250-f3079a0.txt", Rules::HEGOTA_TESTNET),
        ("cases-eip8250-master.txt", Rules::EIP8250_MASTER),
    ] {
        for (name, _, tx) in cases(file, rules).into_iter().filter(|c| c.1 == "refused") {
            let r = render(&tx, 0, &reg, rules).unwrap();
            let flagged: Vec<GapKind> = r
                .gaps
                .iter()
                .map(|g| g.kind)
                .filter(|k| matches!(k, GapKind::Refusal | GapKind::Opaque))
                .collect();
            let expect = match name.as_str() {
                // The account's own rule: no payment approved on E.
                "self-paying" | "payer-is-sender" => GapKind::Refusal,
                // A relay changed what E pins, so the owner's msg is no longer this E.
                _ => GapKind::Opaque,
            };
            assert_eq!(flagged, vec![expect], "{file} {name}: {:?}", kinds(&r));
        }
    }
}

#[test]
fn the_key_zero_bytes_mean_two_nonces() {
    let reg = registry();
    let (_, _, master) = cases("cases-eip8250-master.txt", Rules::EIP8250_MASTER)
        .into_iter()
        .find(|c| c.0 == "key-zero")
        .unwrap();
    let raw = master.encode();
    let read_master = render(&master, 0, &reg, Rules::EIP8250_MASTER).unwrap();
    let old = FrameTx::decode_with(&raw, Rules::HEGOTA_TESTNET.eip8250).unwrap();
    let read_old = render(&old, 0, &reg, Rules::HEGOTA_TESTNET).unwrap();
    assert_eq!(
        line(&read_master, "Nonce"),
        Some("keys [0] at sequence 0, in NONCE_MANAGER")
    );
    assert_eq!(line(&read_old, "Nonce"), Some("the account nonce, 0"));
    assert_eq!(
        read_master.signs, read_old.signs,
        "one signature, two meanings"
    );
}

const EXP_28: [&str; 12] = [
    "0x32eb0bc5",
    "0x9688c1f8",
    "0x78564f0a",
    "0x3fc65c1d",
    "0x9489899e",
    "0x57135ff7",
    "0x644424fe",
    "0xd3c04b29",
    "0x28885722",
    "0x0cd8150d",
    "0x6c5d0038",
    "0xf00c9f2c",
];

#[test]
fn experiment_28_batches_show_in_full() {
    let reg = registry();
    let alone = Registry::default();
    for prefix in EXP_28 {
        let tx = chain(prefix);
        let r = render(&tx, 0, &reg, Rules::HEGOTA_TESTNET).unwrap();
        assert!(r.gaps.is_empty(), "{prefix}: {:?}", kinds(&r));
        assert!(matches!(r.signs, Signs::SigHash { .. }));
        assert!(
            line(&r, "Account").unwrap().contains("default code"),
            "{prefix}"
        );
        let sponsored = tx.signatures.len() == 2;
        assert_eq!(
            line(&r, "Payer").unwrap().ends_with("you pay no gas"),
            sponsored,
            "{prefix}"
        );
        let independent = matches!(prefix, "0x78564f0a" | "0x6c5d0038");
        if independent {
            assert_eq!(
                r.intent,
                "Approve ToyDex to spend 1 TKA and Swap 2 TKA for at least 2 TKB and Approve ToyDex to spend 0 TKA"
            );
            assert!(line(&r, "Independent").is_some());
        } else {
            // Case E asks for one wei more than the swap pays, so that it fails; full precision
            // shows it.
            let min_out = if matches!(prefix, "0x3fc65c1d" | "0xf00c9f2c") {
                "1.000000000000000001"
            } else {
                "1"
            };
            assert_eq!(
                r.intent,
                format!("Approve ToyDex to spend 1 TKA and Swap 1 TKA for at least {min_out} TKB"),
                "{prefix}"
            );
            assert!(line(&r, "Atomic").is_some(), "{prefix}");
        }

        // The transaction alone shows every protocol line and none of the calls.
        let t = render(&tx, 0, &alone, Rules::HEGOTA_TESTNET).unwrap();
        let calls = tx.frames.iter().filter(|f| f.mode == 2).count();
        assert_eq!(t.blind().count(), calls, "{prefix}");
        assert!(t.blind().all(|g| g.kind == GapKind::NoDescriptor));
        for label in [
            "Signs",
            "Account",
            "Nonce",
            "Approves",
            "Max fee",
            "Atomic",
            "Independent",
        ] {
            assert_eq!(line(&t, label), line(&r, label), "{prefix} {label}");
        }
        // Without the address book the sponsor is an address, still the payer.
        assert_eq!(
            line(&t, "Payer").unwrap().ends_with("you pay no gas"),
            sponsored,
            "{prefix}"
        );
    }
}

#[test]
fn session_grant_redemptions_and_revocation() {
    let reg = registry();
    let grant = render(&chain("0x3650463d"), 0, &reg, Rules::HEGOTA_TESTNET).unwrap();
    assert!(grant.gaps.is_empty(), "{:?}", kinds(&grant));
    assert_eq!(
        grant.intent,
        "Let the session key spend up to 0.002 ETH on the merchant until 2026-10-07T11:01:55Z"
    );
    assert!(line(&grant, "Signer").unwrap().starts_with("the owner key"));

    for prefix in ["0x1d381c94", "0x84d4a91f"] {
        let r = render(&chain(prefix), 0, &reg, Rules::HEGOTA_TESTNET).unwrap();
        assert_eq!(
            kinds(&r),
            vec![(Some(1), GapKind::State, false)],
            "{prefix}"
        );
        assert_eq!(
            line(&r, "Signer"),
            Some("the session key, entry 0, secp256k1")
        );
        assert_eq!(
            line(&r, "Valid until").map(|d| &d[..10]),
            Some("2026-10-07")
        );
        assert!(r.intent.starts_with("Count "), "{prefix}");
    }

    let revoke = render(&chain("0x822694c8"), 0, &reg, Rules::HEGOTA_TESTNET).unwrap();
    assert!(revoke.gaps.is_empty());
    assert_eq!(revoke.intent, "Revoke the session of the session key");

    // Without the account's descriptor, its calls to itself are raw: the grant is blind.
    let mut no_accounts = reg.clone();
    no_accounts.accounts.clear();
    let g = render(&chain("0x3650463d"), 0, &no_accounts, Rules::HEGOTA_TESTNET).unwrap();
    assert_eq!(kinds(&g), vec![(Some(1), GapKind::NoDescriptor, true)]);
}

#[test]
fn a_deploy_frame_binds_the_account_it_deploys() {
    let reg = registry();
    let mut no_wallet = reg.clone();
    no_wallet.wallet.accounts.clear();
    let r = render(&chain("0x9882637a"), 0, &no_wallet, Rules::HEGOTA_TESTNET).unwrap();
    assert!(r.gaps.is_empty(), "{:?}", kinds(&r));
    assert_eq!(
        r.intent,
        "Deploy your account as SimpleAccount and Send 0.001 ETH to 0xb470FfA0F6706c720D824Fb0fCde3BbB8CeeAD35"
    );
    assert!(
        line(&r, "Account")
            .unwrap()
            .ends_with("deployed by frame 0")
    );
    assert!(line(&r, "Before payment").is_some());
    assert!(
        r.lines
            .iter()
            .any(|l| l.section == Section::Execution && l.source == "deployer: CREATE2 deployer")
    );

    // After deployment, nothing in the transaction names the implementation.
    let after = render(&chain("0x68fc041a"), 0, &no_wallet, Rules::HEGOTA_TESTNET).unwrap();
    assert!(
        line(&after, "Account")
            .unwrap()
            .ends_with("no descriptor binds it")
    );
    assert!(
        after.gaps.is_empty(),
        "the signature covers the whole transaction either way"
    );
}
