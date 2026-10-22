//! ERC-7715 over frames on the testnet, from `exp-frames` experiment 28's `permissions.ts`
//! (third run, 2026-10-20): the owner's grant and revocation, which this crate's wallet sent,
//! and the dapp's redemption in between, which experiment 12's TypeScript `sessionTx` built and
//! the session key signed. Each is rebuilt here from what was decided: the session's policy,
//! the dapp's call and deadline, the envelope.

use std::{fs, path::Path};

use alloy::primitives::{Address, U256, keccak256};
use kohaku_frame_accounts::{
    account::{FrameAccount, Signer},
    builder::{Envelope, TxPlan},
    session::{SessionAccount, SessionPolicy},
};
use kohaku_frame_kit::{Frame, FrameTx, json::FrameTxJson};
use kohaku_frame_wallet::wallet::WalletAccount;
use serde::Deserialize;

const GRANT: &str = "0x739dbfa01e2109f776e13e4614235c5d726f92508e7bd48a7178add8252aca2a";
const REDEMPTION: &str = "0x97a109454a5f08ae733058dbfc1ef4518fdacbe02ffab35ca52eacfdac12df02";
const REVOCATION: &str = "0x8e7dbfdf05aebe44cc7a53ae8eb5efb7d21ca7932f91c41f894f41ca8f8be85f";

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
}

fn mined(hash: &str) -> FrameTx {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/permissions")
        .join(format!("{hash}.json"));
    let f: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    FrameTx::try_from(&f.tx).unwrap()
}

fn envelope(tx: &FrameTx) -> Envelope {
    Envelope {
        chain_id: tx.chain_id,
        nonce_keys: tx.nonce_keys.clone(),
        nonce_seq: tx.nonce_seq,
        fees: tx.fees,
    }
}

/// The user's account, from the owner the grant names and experiment 28's salt.
fn account(grant: &FrameTx) -> SessionAccount {
    let owner = grant.signatures[0].signer.unwrap();
    let account = SessionAccount::new(owner, keccak256("exp-frames/28/session-account"));
    assert_eq!(account.address(), grant.sender);
    account
}

/// `0x01 || key || target || selector || validUntil (8) || budget (16)`.
fn granted(grant: &FrameTx) -> (Address, SessionPolicy) {
    let d = &grant.frames[1].data;
    assert_eq!(d[0], 0x01);
    let key = Address::from_slice(&d[1..21]);
    let policy = SessionPolicy {
        target: Address::from_slice(&d[21..41]),
        selector: d[41..45].try_into().unwrap(),
        valid_until: u64::from_be_bytes(d[45..53].try_into().unwrap()),
        budget: u128::from_be_bytes(d[53..69].try_into().unwrap()),
    };
    (key, policy)
}

fn owner_tx(account: SessionAccount, frame: Frame, envelope: &Envelope) -> FrameTx {
    TxPlan::new(&WalletAccount::Session(account))
        .call(frame)
        .build(envelope)
        .unwrap()
}

fn assert_rebuilt(mut built: FrameTx, mined: &FrameTx) {
    assert_eq!(built.sig_hash(), mined.sig_hash());
    built.signatures[0].signature = mined.signatures[0].signature.clone();
    assert_eq!(&built, mined);
}

#[test]
fn rebuilds_the_grant_and_the_revocation() {
    let grant = mined(GRANT);
    let account = account(&grant);
    let (key, policy) = granted(&grant);
    // What permissions.ts asked for: approve on Token A, 0.002 ETH.
    assert_eq!(policy.selector, [0x09, 0x5e, 0xa7, 0xb3]);
    assert_eq!(policy.budget, 2_000_000_000_000_000);
    assert_rebuilt(
        owner_tx(
            account,
            account.add_session(key, &policy),
            &envelope(&grant),
        ),
        &grant,
    );
    let revocation = mined(REVOCATION);
    assert_rebuilt(
        owner_tx(account, account.revoke_session(key), &envelope(&revocation)),
        &revocation,
    );
}

#[test]
fn rebuilds_the_redemption_experiment_12_built() {
    let grant = mined(GRANT);
    let account = account(&grant);
    let (key, policy) = granted(&grant);
    let redemption = mined(REDEMPTION);
    assert_eq!(redemption.signatures[0].signer, Some(key));
    let call = redemption.frames[3].clone();
    assert_eq!(call.target, Some(policy.target));
    assert_eq!(call.data[..4], policy.selector);
    let deadline = u64::from_be_bytes(redemption.frames[0].data[..8].try_into().unwrap());
    assert!(deadline <= policy.valid_until);
    let built = account
        .session_tx(
            Signer::secp256k1(key),
            &[call],
            deadline,
            &envelope(&redemption),
        )
        .unwrap();
    assert_rebuilt(built, &redemption);
    // Paid by the user's account, within the budget.
    let amount = U256::from_be_slice(&redemption.frames[2].data[21..53]);
    assert!(amount < U256::from(policy.budget));
    assert_eq!(redemption.sender, account.address());
}
