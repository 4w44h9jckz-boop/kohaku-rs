//! Transactions `exp-frames` experiments 01 to 05, 09, 10 and 12 mined on the ethrex Hegota testnet,
//! laid out again with this crate from what they were built from, and compared byte for byte.
//!
//! Keys are not in the repository, so each rebuilt transaction takes its signature bytes from the
//! mined one; everything else (frames, limits, flags, signature entries, sender) is this crate's.

use std::{fs, path::Path};

use alloy::primitives::{Address, U256, address};
use kohaku_frame_accounts::{
    CanonicalPaymaster, Envelope, Eoa, EoaSponsor, FrameAccount, Multisig, MultisigSponsor,
    SessionAccount, SessionPolicy, Signer, SimpleAccount, TokenSponsor, TxPlan,
    builder::BuildError,
    calls,
    contracts::{
        canonical_paymaster_code, deploy_frame, is_canonical_paymaster, multisig_code, salt_of,
    },
};
use kohaku_frame_kit::{
    Frame, FrameTx,
    constants::{NEW_ACCOUNT_STATE_GAS, STORAGE_SET_STATE_GAS, approve},
    json::FrameTxJson,
};
use serde::Deserialize;

const FUNDER: Address = address!("0xa93CEe06b1e4fFACdf920BD500cb301a39DdEB74");
const TUSD: Address = address!("0xd8d75cd4d9C19651Bc96dBdC6948d47894D354EA");
const RATE: u64 = 2000;

#[derive(Deserialize)]
struct Fixture {
    tx: FrameTxJson,
}

fn mined(prefix: &str) -> FrameTx {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chain");
    let path = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_name().unwrap().to_string_lossy().starts_with(prefix))
        .unwrap_or_else(|| panic!("no fixture {prefix}"));
    let f: Fixture = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let tx = FrameTx::try_from(&f.tx).unwrap();
    assert_eq!(tx.hash(), f.tx.hash);
    tx
}

fn envelope(tx: &FrameTx) -> Envelope {
    Envelope {
        chain_id: tx.chain_id,
        nonce_keys: tx.nonce_keys.clone(),
        nonce_seq: tx.nonce_seq,
        fees: tx.fees,
    }
}

/// The rebuilt transaction must name the same signers in the same order; then it takes the
/// mined signature bytes and must equal the mined transaction.
fn assert_rebuilds(mut built: FrameTx, mined: &FrameTx) {
    assert_eq!(built.signatures.len(), mined.signatures.len(), "entries");
    for (b, m) in built.signatures.iter_mut().zip(&mined.signatures) {
        assert_eq!((b.scheme, b.signer, &b.msg), (m.scheme, m.signer, &m.msg));
        assert!(b.signature.is_empty());
        b.signature = m.signature.clone();
    }
    assert_eq!(&built, mined);
    assert_eq!(built.hash(), mined.hash());
}

fn funder() -> Eoa {
    Eoa::new(Signer::secp256k1(FUNDER))
}

fn target(f: &Frame) -> Address {
    f.target.unwrap()
}

// ---- 01: EIP Examples 1 and 1a, from an account with no code ----

#[test]
fn ex01_transfers_to_a_new_and_an_existing_account() {
    for (hash, exists) in [("0x7fbe0199", false), ("0xb91efd4a", true)] {
        let m = mined(hash);
        let w = &m.frames[1];
        let built = TxPlan::new(&funder())
            .call(calls::eth_transfer(target(w), w.value, exists))
            .build(&envelope(&m))
            .unwrap();
        assert_rebuilds(built, &m);
    }
}

#[test]
fn ex01_calls_with_sender_and_default_frames() {
    for hash in ["0x4c68a30a", "0xaa8aa58c"] {
        let m = mined(hash);
        let built = TxPlan::new(&funder())
            .calls(m.frames[1..].iter().cloned())
            .build(&envelope(&m))
            .unwrap();
        assert_rebuilds(built, &m);
    }
}

// ---- 02: Example 1b, an account that deploys itself at tx.sender ----

#[test]
fn ex02_simple_account_deploys_itself_then_validates_alone() {
    let salt = salt_of("exp-frames/simple-account/v1");
    for (hash, deployed) in [("0x9882637a", false), ("0x68fc041a", true)] {
        let m = mined(hash);
        let account = SimpleAccount::new(FUNDER, salt).deployed(deployed);
        assert_eq!(account.address(), m.sender);
        let w = m.frames.last().unwrap();
        let built = TxPlan::new(&account)
            .call(calls::eth_transfer(target(w), w.value, false))
            .build(&envelope(&m))
            .unwrap();
        assert_rebuilds(built, &m);
    }
}

// ---- 03: Example 2, atomic approve and swap ----

#[test]
fn ex03_batches_with_and_without_the_atomic_flag() {
    for hash in ["0x952ac725", "0xf790e5ad", "0x5c08e5fe", "0xaca3e784"] {
        let m = mined(hash);
        let approve_frame = &m.frames[1];
        // approve(spender, amount) as this crate writes it: the arguments come from the call.
        let spender = Address::from_slice(&approve_frame.data[16..36]);
        let amount = U256::from_be_slice(&approve_frame.data[36..68]);
        let mut approve = calls::erc20_approve(target(approve_frame), spender, amount);
        if approve_frame.flags & 0x4 != 0 {
            approve = approve.atomic();
        }
        let account = funder();
        let mut plan = TxPlan::new(&account).call(approve);
        // The swap is the experiment's own call; a trailing token transfer is this crate's.
        if let Some(swap) = m.frames.get(2) {
            plan = plan.call(swap.clone());
        }
        if let Some(send) = m.frames.get(3) {
            let to = Address::from_slice(&send.data[16..36]);
            let value = U256::from_be_slice(&send.data[36..68]);
            plan = plan.call(calls::erc20_transfer(target(send), to, value));
        }
        assert_rebuilds(plan.build(&envelope(&m)).unwrap(), &m);
    }
}

#[test]
fn ex03_setup_deploys_through_create2() {
    let m = mined("0xed789253");
    let deploy = |i: usize, extra_state: u64| {
        let data = &m.frames[i].data;
        deploy_frame(
            &data[32..],
            alloy::primitives::B256::from_slice(&data[..32]),
            extra_state,
        )
    };
    let built = TxPlan::new(&funder())
        .call(deploy(1, 2 * STORAGE_SET_STATE_GAS))
        .call(deploy(2, 2 * STORAGE_SET_STATE_GAS))
        .call(deploy(3, 0))
        .calls(m.frames[4..].iter().cloned())
        .build(&envelope(&m))
        .unwrap();
    assert_rebuilds(built, &m);
}

// ---- 04: Example 3, sponsored ----

#[test]
fn ex04_an_eoa_sponsor_pays_for_a_fresh_user() {
    let m = mined("0xc8d33262");
    let user = Eoa::new(Signer::secp256k1(m.sender)).with_verify_execution(10_000);
    // APPROVE(PAYMENT) creates the user's account, from the payment frame's state budget.
    let mut sponsor = EoaSponsor::new(Signer::secp256k1(FUNDER)).with_state(NEW_ACCOUNT_STATE_GAS);
    let built = TxPlan::new(&user)
        .sponsored_by(&mut sponsor)
        .call(m.frames[2].clone())
        .build(&envelope(&m))
        .unwrap();
    assert_rebuilds(built, &m);
}

#[test]
fn ex04_token_sponsor_prices_the_fee_as_the_experiment_did() {
    // The fixed sponsor, and the first one whose post-op had a bug: same layout, same quote.
    for hash in ["0xb1342980", "0xcc96591e"] {
        let m = mined(hash);
        let user = Eoa::new(Signer::secp256k1(m.sender)).with_verify_execution(10_000);
        let mut sponsor = TokenSponsor::new(target(&m.frames[1]), TUSD, U256::from(RATE));
        let send = &m.frames[3];
        let to = Address::from_slice(&send.data[16..36]);
        let amount = U256::from_be_slice(&send.data[36..68]);
        let built = TxPlan::new(&user)
            .sponsored_by(&mut sponsor)
            .call(calls::erc20_transfer(TUSD, to, amount))
            .build(&envelope(&m))
            .unwrap();
        let mined_fee = U256::from_be_slice(&m.frames[2].data[36..68]);
        assert_eq!(sponsor.fee, mined_fee, "{hash}");
        assert_rebuilds(built, &m);
    }
}

#[test]
fn ex04_token_sponsor_address_and_setup() {
    let salt = salt_of("exp-frames/04/token-sponsor/v1");
    let sponsor = TokenSponsor::address_of(TUSD, U256::from(RATE), FUNDER, salt);
    assert_eq!(
        sponsor,
        address!("0xc57cB255D6113ae92D8229dB939F40C785D868E4")
    );

    let m = mined("0x80f2c88b");
    let initcode = TokenSponsor::initcode(TUSD, U256::from(RATE), FUNDER);
    let built = TxPlan::new(&funder())
        .call(deploy_frame(&initcode, salt, 0))
        .call(calls::eth_transfer(sponsor, m.frames[2].value, true))
        .build(&envelope(&m))
        .unwrap();
    assert_rebuilds(built, &m);
}

#[test]
fn ex04_first_setup_deploys_the_token_and_the_first_sponsor() {
    let m = mined("0x0d6ba2eb");
    let data = &m.frames[1].data;
    let tusd = deploy_frame(
        &data[32..],
        alloy::primitives::B256::from_slice(&data[..32]),
        2 * STORAGE_SET_STATE_GAS,
    );
    // The first sponsor's code predates the fixed post-op, so its deploy frame is copied.
    let first_sponsor = target(&m.frames[3]);
    let built = TxPlan::new(&funder())
        .call(tusd)
        .call(m.frames[2].clone())
        .call(calls::eth_transfer(first_sponsor, m.frames[3].value, true))
        .build(&envelope(&m))
        .unwrap();
    assert_rebuilds(built, &m);
}

// ---- 05: k-of-n multisig ----

/// The owners and threshold the experiment deployed with, read from its deploy frame.
fn deployed_multisig(deploy: &Frame, label: &str) -> Multisig {
    let args = &deploy.data[32 + multisig_code().len()..];
    let words: Vec<U256> = args.chunks(32).map(U256::from_be_slice).collect();
    let (owners, nk) = words.split_at(words.len() - 2);
    let owners = owners
        .iter()
        .map(|w| Address::from_word(w.to_be_bytes::<32>().into()))
        .collect::<Vec<_>>();
    assert_eq!(nk[0], U256::from(owners.len()));
    Multisig::new(owners, nk[1].to(), salt_of(label)).unwrap()
}

#[test]
fn ex05_multisig_setup_and_two_of_three_transfers() {
    let setup = mined("0xebbf8e6f");
    let secp = deployed_multisig(&setup.frames[1], "exp-frames/05/multisig-2of3-secp/v1");
    let mixed = deployed_multisig(&setup.frames[3], "exp-frames/05/multisig-2of3-mixed/v1");
    let built = TxPlan::new(&funder())
        .call(secp.deploy_frame())
        .call(calls::eth_transfer(
            secp.address(),
            setup.frames[2].value,
            true,
        ))
        .call(mixed.deploy_frame())
        .call(calls::eth_transfer(
            mixed.address(),
            setup.frames[4].value,
            true,
        ))
        .build(&envelope(&setup))
        .unwrap();
    assert_rebuilds(built, &setup);

    for (hash, account) in [("0x8d3b555a", secp), ("0xa317ca5b", mixed)] {
        let m = mined(hash);
        // Who signed is in the mined entries: alice + carol, then bob + the P256 passkey.
        let signers = m
            .signatures
            .iter()
            .map(|s| Signer {
                address: s.signer.unwrap(),
                scheme: s.scheme,
            })
            .collect();
        let account = account.deployed(true).signed_by(signers).unwrap();
        assert_eq!(account.address(), m.sender);
        let w = &m.frames[1];
        let built = TxPlan::new(&account)
            .call(calls::eth_transfer(target(w), w.value, true))
            .build(&envelope(&m))
            .unwrap();
        assert_rebuilds(built, &m);
    }
}

#[test]
fn a_sponsor_takes_the_payment_scope_from_the_account() {
    let m = mined("0xc8d33262");
    let user = Eoa::new(Signer::secp256k1(m.sender));
    let alone = TxPlan::new(&user).build(&envelope(&m)).unwrap();
    assert_eq!(alone.frames[0].flags, approve::EXECUTION_AND_PAYMENT);
    let mut sponsor = EoaSponsor::new(Signer::secp256k1(FUNDER));
    let sponsored = TxPlan::new(&user)
        .sponsored_by(&mut sponsor)
        .build(&envelope(&m))
        .unwrap();
    assert_eq!(sponsored.frames[0].flags, approve::EXECUTION);
    assert_eq!(sponsored.frames[1].flags, approve::PAYMENT);
}

#[test]
fn the_examples_contracts_are_the_ones_the_experiments_call() {
    #[derive(Deserialize)]
    struct Contracts {
        contracts: Vec<Contract>,
    }
    #[derive(Deserialize)]
    struct Contract {
        name: String,
        deploy: alloy::primitives::Bytes,
    }
    let json: Contracts = serde_json::from_str(include_str!("../examples/contracts.json")).unwrap();
    let address = |name: &str| {
        let c = json.contracts.iter().find(|c| c.name == name).unwrap();
        kohaku_frame_accounts::contracts::create2_address(
            &c.deploy[32..],
            alloy::primitives::B256::from_slice(&c.deploy[..32]),
        )
    };
    let swap_c = mined("0x5c08e5fe");
    assert_eq!(address("Token A"), target(&swap_c.frames[1]));
    assert_eq!(address("ToyDex"), target(&swap_c.frames[2]));
    assert_eq!(address("Token B"), target(&swap_c.frames[3]));
    assert_eq!(address("tUSD"), TUSD);
}

// ---- 10: the expiry verifier frame ----

#[test]
fn ex10_a_deadline_is_the_first_frame() {
    const USER: Address = address!("0xa6b01af7512a08b1f0a7603765b21a53a7d1d7db");
    // A deadline in the future, the far deadline 2^64 - 1, and the funder sending to itself.
    for (hash, sender) in [
        ("0x96cdac11", USER),
        ("0x045fb58b", USER),
        ("0xefb6d408", FUNDER),
    ] {
        let m = mined(hash);
        let deadline = u64::from_be_bytes(m.frames[0].data[..].try_into().unwrap());
        let w = &m.frames[2];
        let built = TxPlan::new(&Eoa::new(Signer::secp256k1(sender)))
            .expires_at(deadline)
            .call(calls::eth_transfer(target(w), w.value, true))
            .build(&envelope(&m))
            .unwrap();
        assert_rebuilds(built, &m);
    }
}

#[test]
fn a_deadline_goes_before_the_deploy_frame() {
    let account = SimpleAccount::new(FUNDER, salt_of("exp-frames/simple-account/v1"));
    let env = Envelope {
        chain_id: 8141,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: 0,
        fees: kohaku_frame_kit::Fees::default(),
    };
    let tx = TxPlan::new(&account).expires_at(1).build(&env).unwrap();
    assert_eq!(tx.frames[0], Frame::expiry(1));
    assert_eq!(tx.frames[1], account.deploy_frames()[0]);
    assert_eq!(tx.frames[2].flags, approve::EXECUTION_AND_PAYMENT);
}

// ---- EIP-8250 nonce keys used for the first time ----

/// Experiment 01 named the signer in these entries, and in `0x6f07b8e7` the `VERIFY` target as
/// well, where `Eoa` leaves both implicit; so the frames' limits are compared, not the envelope.
#[test]
fn ex01_a_fresh_nonce_key_charges_its_slot_to_the_verify_that_pays() {
    for (hash, verify_execution, fresh) in [
        ("0x80ca7402", 5_000, 1),
        ("0x26ed3e31", 5_000, 2),
        ("0x6f07b8e7", 80_000, 1),
    ] {
        let m = mined(hash);
        let env = envelope(&m);
        assert_eq!(env.fresh_nonce_keys(), fresh, "{hash}");
        let account = Eoa::new(Signer::secp256k1(m.sender)).with_verify_execution(verify_execution);
        let built = TxPlan::new(&account)
            .calls(m.frames[1..].iter().cloned())
            .build(&env)
            .unwrap();
        assert_eq!(built.frames[0].limits, m.frames[0].limits, "{hash}");
        assert_eq!(built.frames[1..], m.frames[1..], "{hash}");
        assert_eq!(
            built.frames[0].limits.state,
            fresh as u64 * STORAGE_SET_STATE_GAS
        );
    }
}

#[test]
fn a_fresh_nonce_key_is_charged_to_the_sponsor_when_one_pays() {
    // Experiment 16: the first pull on a merchant's lane put 97,920 on the merchant's pay frame.
    let user = Eoa::new(Signer::secp256k1(address!(
        "0x00000000000000000000000000000000000000a1"
    )));
    let mut sponsor = EoaSponsor::new(Signer::secp256k1(FUNDER));
    let mut env = Envelope {
        chain_id: 8141,
        nonce_keys: vec![U256::from(1)],
        nonce_seq: 0,
        fees: kohaku_frame_kit::Fees::default(),
    };
    let tx = TxPlan::new(&user)
        .sponsored_by(&mut sponsor)
        .build(&env)
        .unwrap();
    assert_eq!(tx.frames[0].limits.state, 0);
    assert_eq!(tx.frames[1].limits.state, STORAGE_SET_STATE_GAS);

    // The second use of the same key creates nothing.
    env.nonce_seq = 1;
    assert_eq!(env.fresh_nonce_keys(), 0);
    let tx = TxPlan::new(&user)
        .sponsored_by(&mut sponsor)
        .build(&env)
        .unwrap();
    assert_eq!(tx.frames[1].limits.state, 0);

    // Key 0 is the account nonce, which has no slot of its own.
    env.nonce_keys = vec![U256::ZERO];
    env.nonce_seq = 0;
    assert_eq!(env.fresh_nonce_keys(), 0);
}

// ---- 09: paymasters in the public mempool ----

/// The sponsor key of experiment 09, and its instance of the canonical paymaster.
const PM_SIGNER: Address = address!("0x712faf4318973e6df080cae63db221c348c65f16");
const PM_MAIN: Address = address!("0xba19bf88b475d9d5d19bc0c26a35f4d3bf35b994");

#[test]
fn ex09_canonical_paymaster_address_and_code_hash() {
    assert_eq!(
        CanonicalPaymaster::address_of(PM_SIGNER, salt_of("exp-frames/09/main/v1")),
        PM_MAIN
    );
    // The initcode ends with the runtime it returns, and that runtime is the pinned one.
    let code = canonical_paymaster_code();
    let runtime = &code[code.len() - 355..];
    assert!(is_canonical_paymaster(runtime));
    // Experiment 09's control: the same runtime and one unreachable byte more.
    let mut copy = runtime.to_vec();
    copy.push(0);
    assert!(!is_canonical_paymaster(&copy));
}

#[test]
fn ex09_the_canonical_paymaster_pays_for_users_with_no_eth() {
    // Two users' first transactions, whose pay frame creates the sender's account; a later one
    // at a low fee; and one through a second instance.
    for (hash, state) in [
        ("0xf2c01318", NEW_ACCOUNT_STATE_GAS),
        ("0x2a0afccf", NEW_ACCOUNT_STATE_GAS),
        ("0xda25878b", 0),
        ("0xa9320bf8", 0),
    ] {
        let m = mined(hash);
        let user = Eoa::new(Signer::secp256k1(m.sender));
        let mut pm = CanonicalPaymaster::new(target(&m.frames[1]), Signer::secp256k1(PM_SIGNER))
            .with_state(state);
        let w = m.frames.last().unwrap();
        let built = TxPlan::new(&user)
            .sponsored_by(&mut pm)
            .call(calls::eth_transfer(target(w), w.value, true))
            .build(&envelope(&m))
            .unwrap();
        assert_rebuilds(built, &m);
    }
}

#[test]
fn ex09_a_multisig_treasury_pays_for_a_member() {
    let m = mined("0xf32a1681");
    let [alice, bob, carol] = [
        address!("0x2fd47e3a9509808cd7758786df7d9ab20a5d68ed"),
        address!("0xb944ed3494cfeb8aab873b1441557828c2cda86f"),
        address!("0x50fbe19c83d38f351a2e651a7537270a70579d74"),
    ];
    let treasury = Multisig::new(
        vec![alice, bob, carol],
        2,
        salt_of("exp-frames/09/treasury-2of3/v1"),
    )
    .unwrap()
    .deployed(true)
    .signed_by(vec![Signer::secp256k1(alice), Signer::secp256k1(carol)])
    .unwrap();
    assert_eq!(treasury.address(), target(&m.frames[1]));
    let mut sponsor = MultisigSponsor::new(treasury).with_state(NEW_ACCOUNT_STATE_GAS);
    let user = Eoa::new(Signer::secp256k1(m.sender));
    let w = m.frames.last().unwrap();
    let built = TxPlan::new(&user)
        .sponsored_by(&mut sponsor)
        .call(calls::eth_transfer(target(w), w.value, true))
        .build(&envelope(&m))
        .unwrap();
    assert_rebuilds(built, &m);
}

#[test]
fn the_canonical_paymaster_cannot_pay_for_a_multisig() {
    // Its runtime reads entry 1, which a 2-of-3 sender's second owner would occupy.
    let owners = vec![FUNDER, PM_SIGNER, PM_MAIN];
    let sender = Multisig::new(owners.clone(), 2, salt_of("test"))
        .unwrap()
        .deployed(true)
        .signed_by(owners[..2].iter().map(|o| Signer::secp256k1(*o)).collect())
        .unwrap();
    let mut pm = CanonicalPaymaster::new(PM_MAIN, Signer::secp256k1(PM_SIGNER));
    let env = Envelope {
        chain_id: 8141,
        nonce_keys: vec![U256::ZERO],
        nonce_seq: 1,
        fees: kohaku_frame_kit::Fees::default(),
    };
    let err = TxPlan::new(&sender)
        .sponsored_by(&mut pm)
        .build(&env)
        .unwrap_err();
    assert!(matches!(err, BuildError::EntryIndex { needs: 1, has: 2 }));
}

// ---- 12: session keys ----

const OWNER: Address = address!("0xb66e53f7394a5069933103cad898194181f8574e");
const SESSION: Address = address!("0xc549c8fdafd2ef85a758d04f7a5d77249d62cc28");
const MERCHANT: Address = address!("0x336d9de562e6f9cbbd3d49be3a4810a854173e47");

fn session_account() -> SessionAccount {
    SessionAccount::new(OWNER, salt_of("exp-frames/12/session-account/v1"))
}

#[test]
fn ex12_the_funder_deploys_and_funds_the_session_account() {
    let account = session_account();
    assert_eq!(
        account.address(),
        address!("0x49f30d74edd539cdb026bd05f05b9359c719276a")
    );
    let m = mined("0x922d2f82");
    let built = TxPlan::new(&funder())
        .call(account.deploy_frame())
        .call(calls::eth_transfer(
            account.address(),
            U256::from(10_000_000_000_000_000u64),
            true,
        ))
        .build(&envelope(&m))
        .unwrap();
    assert_rebuilds(built, &m);
}

#[test]
fn ex12_the_owner_grants_and_revokes_a_session() {
    let account = session_account();
    let m = mined("0x3650463d");
    let data = &m.frames[1].data;
    let policy = SessionPolicy {
        target: MERCHANT,
        selector: [0; 4],
        valid_until: u64::from_be_bytes(data[45..53].try_into().unwrap()),
        budget: 2_000_000_000_000_000,
    };
    let built = TxPlan::new(&account)
        .call(account.add_session(SESSION, &policy))
        .build(&envelope(&m))
        .unwrap();
    assert_rebuilds(built, &m);

    // D revokes; E revokes by replacing a pending session transaction, at fees 25% higher.
    for hash in ["0x822694c8", "0x5cd226e7"] {
        let m = mined(hash);
        let built = TxPlan::new(&account)
            .call(account.revoke_session(SESSION))
            .build(&envelope(&m))
            .unwrap();
        assert_rebuilds(built, &m);
    }
}

#[test]
fn ex12_a_session_key_pays_the_merchant() {
    // A; the first run's A, whose payment ran out of gas and whose spend was still recorded;
    // and B, two payments in one transaction.
    let account = session_account();
    for (hash, values) in [
        ("0x1d381c94", &[100_000_000_000_000u64][..]),
        ("0x7f53ae0c", &[100_000_000_000_000]),
        ("0x84d4a91f", &[100_000_000_000_000, 200_000_000_000_000]),
    ] {
        let m = mined(hash);
        let deadline = u64::from_be_bytes(m.frames[0].data[..].try_into().unwrap());
        let calls: Vec<Frame> = values
            .iter()
            .map(|v| {
                Frame::sender(Some(MERCHANT))
                    .with_value(U256::from(*v))
                    .with_execution(50_000)
            })
            .collect();
        let built = account
            .session_tx(Signer::secp256k1(SESSION), &calls, deadline, &envelope(&m))
            .unwrap();
        assert_rebuilds(built, &m);
    }
}
