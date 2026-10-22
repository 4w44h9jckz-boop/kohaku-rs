//! Experiment 05: two 2-of-3 multisigs, one with three secp256k1 owners and one with two
//! secp256k1 owners and a P256 passkey. Each sends 0.001 ETH back to the funder with two of its
//! owners' signatures. No signature is checked in the EVM: the protocol checks them, and the
//! account counts its owners among the signers with `SIGPARAM`.
//!
//! The owner keys are derived from `PRIVATE_KEY` as experiment 05 derives them, so these are the
//! accounts it deployed.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-accounts --example ex05_multisig
//! ```

mod common;

use alloy::{
    primitives::{U256, uint, utils::parse_ether},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use kohaku_frame_accounts::{
    Eoa, FrameAccount, Multisig, Signer, TxPlan, calls, contracts::salt_of,
};
use kohaku_frame_kit::FrameSigner;

/// The order of secp256r1's group.
const P256_N: U256 = uint!(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551_U256);

fn secp(label: &str) -> anyhow::Result<FrameSigner> {
    let key = common::derive(&format!("exp-frames/05/{label}"))?;
    Ok(FrameSigner::Secp256k1(PrivateKeySigner::from_bytes(&key)?))
}

/// `keccak256(PRIVATE_KEY || label) mod (n - 1) + 1`: a valid P256 scalar.
fn passkey(label: &str) -> anyhow::Result<FrameSigner> {
    let h = common::derive(&format!("exp-frames/05/p256/{label}"))?;
    let d = U256::from_be_bytes(h.0) % (P256_N - U256::from(1)) + U256::from(1);
    Ok(FrameSigner::P256(p256::ecdsa::SigningKey::from_slice(
        &d.to_be_bytes::<32>(),
    )?))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = common::provider()?;
    let funder = common::funder()?;
    let (alice, bob, carol, pk) = (
        secp("alice")?,
        secp("bob")?,
        secp("carol")?,
        passkey("passkey")?,
    );
    let owners = |keys: [&FrameSigner; 3]| keys.iter().map(|k| k.address()).collect::<Vec<_>>();
    let secp_ms = Multisig::new(
        owners([&alice, &bob, &carol]),
        2,
        salt_of("exp-frames/05/multisig-2of3-secp/v1"),
    )?;
    let mixed_ms = Multisig::new(
        owners([&alice, &bob, &pk]),
        2,
        salt_of("exp-frames/05/multisig-2of3-mixed/v1"),
    )?;
    println!(
        "2-of-3 secp256k1 {}\n2-of-3 mixed     {}",
        secp_ms.address(),
        mixed_ms.address()
    );

    // Deploy and fund whichever account needs it, from the funder.
    let mut setup = Vec::new();
    for ms in [&secp_ms, &mixed_ms] {
        if !common::has_code(&provider, ms.address()).await? {
            setup.push(ms.deploy_frame());
        }
        let balance = provider.get_balance(ms.address()).await?;
        let funding = parse_ether("0.01")?;
        if balance < funding / U256::from(2) {
            setup.push(calls::eth_transfer(ms.address(), funding - balance, true));
        }
    }
    if !setup.is_empty() {
        let account = Eoa::new((&funder).into());
        let envelope = common::envelope(&provider, account.address()).await?;
        let tx = TxPlan::new(&account).calls(setup).build(&envelope)?;
        common::run(
            &provider,
            tx,
            std::slice::from_ref(&funder),
            "setup: deploy and fund",
            true,
        )
        .await?;
    }

    for (ms, signers, label) in [
        (
            secp_ms,
            [alice.clone(), carol],
            "2-of-3 secp256k1: alice + carol sign",
        ),
        (
            mixed_ms,
            [bob, pk],
            "2-of-3 mixed: bob (secp256k1) + passkey (P256) sign",
        ),
    ] {
        let account = ms
            .deployed(true)
            .signed_by(signers.iter().map(Signer::from).collect())?;
        let envelope = common::envelope(&provider, account.address()).await?;
        let tx = TxPlan::new(&account)
            .call(calls::eth_transfer(
                funder.address(),
                parse_ether("0.001")?,
                true,
            ))
            .build(&envelope)?;
        common::run(&provider, tx, &signers, label, true).await?;
    }
    Ok(())
}
