//! `exp-frames` experiment 31's transactions on the testnet (2026-10-20), rebuilt with
//! [`DeviceRecoveryAccount`] from what each one was: who signed, and which operation it carried.
//! Two accounts, one per [`TimeRule`]; the devices are a laptop and a hardware key, both needed.

use std::{fs, path::Path};

use alloy::primitives::{Address, B256, address, keccak256};
use kohaku_frame_accounts::{
    DeviceRecoveryAccount, Devices, Envelope, TimeRule, TxPlan, recovery::op,
};
use kohaku_frame_kit::{Frame, FrameTx, constants::mode, json::FrameTxJson};
use serde::Deserialize;

const FUNDER: Address = address!("0xEB8e3354c1E33A8e671ABB927DcF6A523ad45FF3");
const PHONE: Address = address!("0x2b8328a7D59C8f36e98E3cD6Ef62c181C3AB3eA9");
const EIP_ACCOUNT: Address = address!("0x57257496FEDA550aC7DBfe2618a2FbCA68B3b05B");
const ETHREX_ACCOUNT: Address = address!("0xDBc37572df127a8AD4ADE0c72B93a046a9a53451");
const DELAY: u64 = 60;

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
}

fn mined() -> Vec<FrameTx> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/device-recovery");
    let mut out: Vec<FrameTx> = fs::read_dir(dir)
        .unwrap()
        .map(|e| {
            let f: Fixture = serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap();
            FrameTx::try_from(&f.tx).unwrap()
        })
        .collect();
    out.sort_by_key(|t| (t.sender, t.nonce_seq));
    out
}

/// The devices, read back from the first transaction they signed.
fn devices(txs: &[FrameTx]) -> Devices {
    let d = &txs
        .iter()
        .find(|t| !t.frames[0].data.is_empty())
        .unwrap()
        .frames[0]
        .data;
    Devices {
        salt: B256::from_slice(&d[..32]),
        m: d[32],
        devices: d[33..].chunks(20).map(Address::from_slice).collect(),
    }
}

fn account(devices: &Devices, rule: TimeRule) -> DeviceRecoveryAccount {
    let label = match rule {
        TimeRule::Eip => "exp-frames/31/device-recovery-account/eip",
        TimeRule::Ethrex => "exp-frames/31/device-recovery-account/ethrex",
    };
    DeviceRecoveryAccount {
        owner: PHONE,
        commitment: devices.commitment(),
        delay: DELAY,
        rule,
        salt: keccak256(label),
    }
}

/// What the transaction was: its signers and operation, rebuilt with the crate.
fn rebuild(account: &DeviceRecoveryAccount, devices: &Devices, mined: &FrameTx) -> FrameTx {
    let call = &mined.frames[1];
    let (signer, frame) = if mined.frames[0].data.is_empty() {
        let key = mined.signatures[0].signer.unwrap();
        let frame = if call.target == Some(account.address()) {
            match call.data[0] {
                op::FINISH => account.finish(),
                op::CANCEL => account.cancel(),
                other => panic!("unexpected operation {other}"),
            }
        } else {
            // The owner pays the funder.
            Frame::sender(call.target)
                .with_value(call.value)
                .with_execution(30_000)
        };
        (account.signed_by(key), frame)
    } else {
        assert_eq!(call.data[0], op::START);
        let next = Address::from_slice(&call.data[1..21]);
        (account.signed_by_devices(devices), account.start(next))
    };
    let envelope = Envelope {
        chain_id: mined.chain_id,
        nonce_keys: mined.nonce_keys.clone(),
        nonce_seq: mined.nonce_seq,
        fees: mined.fees,
    };
    let mut built = TxPlan::new(&signer).call(frame).build(&envelope).unwrap();
    assert_eq!(built.sig_hash(), mined.sig_hash());
    for (b, m) in built.signatures.iter_mut().zip(&mined.signatures) {
        b.signature = m.signature.clone();
    }
    built
}

#[test]
fn lands_at_the_testnet_addresses() {
    let txs = mined();
    let devices = devices(&txs);
    assert_eq!((devices.m, devices.devices.len()), (2, 2));
    assert_eq!(account(&devices, TimeRule::Eip).address(), EIP_ACCOUNT);
    assert_eq!(
        account(&devices, TimeRule::Ethrex).address(),
        ETHREX_ACCOUNT
    );
    // The funder's setup deployed each one with exactly this frame.
    let setups: Vec<_> = txs.iter().filter(|t| t.sender == FUNDER).collect();
    assert_eq!(setups.len(), 2);
    for (setup, rule) in setups.iter().zip([TimeRule::Eip, TimeRule::Ethrex]) {
        assert!(
            setup
                .frames
                .contains(&account(&devices, rule).deploy_frame())
        );
    }
}

#[test]
fn rebuilds_every_transaction_from_both_accounts() {
    let txs = mined();
    let devices = devices(&txs);
    let mut seen = 0;
    for rule in [TimeRule::Eip, TimeRule::Ethrex] {
        let account = account(&devices, rule);
        let own: Vec<_> = txs
            .iter()
            .filter(|t| t.sender == account.address())
            .collect();
        for mined in &own {
            assert_eq!(&rebuild(&account, &devices, mined), *mined);
            seen += 1;
        }
        // Under the EIP's rule the early finish was mined; under ethrex's it was refused.
        let finishes = own
            .iter()
            .filter(|t| t.frames[1].mode == mode::SENDER && t.frames[1].data[..] == [op::FINISH])
            .count();
        assert_eq!(finishes, if rule == TimeRule::Eip { 2 } else { 1 });
    }
    assert_eq!(seen, 13);
}
