//! A wallet's note openings recovered from two of the owner's devices, on the ethrex Hegota
//! testnet. `exp-frames` experiment 31 recovers the account with the same two devices; this
//! recovers what the account cannot hold, the openings of the notes it deposited.
//!
//! ```text
//! PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-wallet --example device_recovery
//! ```
//!
//! 1. Before the loss: a keychain key, split between the laptop and the hardware key, and a note
//!    the keychain derives, deposited into `exp-frames` experiment 06's keyed pool.
//! 2. The phone, and the key on it, are lost.
//! 3. The two shares give the key back. The keychain derives its notes again, and the pool's
//!    public events say which were deposited and which spent.
//! 4. The recovered note is withdrawn, with the pool as sender: the opening works.
//!
//! `PRIVATE_KEY` pays the deposit; `RPC_URL` defaults to the testnet. No share or key is printed.

use std::env;

use alloy::{
    primitives::{Address, B256, U256, address, keccak256},
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use anyhow::{Context, ensure};
use kohaku_frame_kit::{FrameSigner, rpc};
use kohaku_frame_pool::{
    chain, prove,
    withdrawal::{DENOMINATION, FramePool, PoolMode, WithdrawalOpts, withdrawal_tx},
};
use kohaku_frame_wallet::recovery::{join, keychain_pool, pool_events, root_slot, split};
use kohaku_tornadocash::{Payer, merkle_tree::MerkleTree};
use kohaku_tornadocash_keychain::{
    Keychain,
    recovery::{next_nonce, recover},
    signature::SignatureKeychain,
};

/// The keyed pool `exp-frames` experiment 06 deployed on the testnet.
const KEYED_POOL: Address = address!("0x73e47a8DA2C83Beb802708Fc473B5B7D094f3eE6");
/// What the withdrawal pays the pool for its gas, as `keyed_withdrawal` pays.
const FEE: u64 = 10_000_000_000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = env::var("RPC_URL").unwrap_or_else(|_| rpc::HEGOTA_RPC_URL.to_owned());
    let funder: PrivateKeySigner = env::var("PRIVATE_KEY")
        .context("PRIVATE_KEY pays the deposit")?
        .parse()?;
    let provider = ProviderBuilder::new().connect_http(url.parse()?);
    let chain_id = provider.get_chain_id().await?;
    let pool = FramePool {
        address: KEYED_POOL,
        mode: PoolMode::Keyed,
        salt: keccak256("exp-frames/06/pool-keyed"),
    };
    let kpool = keychain_pool(&pool, chain_id, 0);

    // 1. Before the loss. The key and the note exist only inside this block.
    let (shares, nonce, commitment) = {
        let key = PrivateKeySigner::random();
        let shares = split(key.to_bytes(), &mut rand::rng());
        let keychain = SignatureKeychain::new(key);
        let events = pool_events(&provider, pool.address, 0).await?;
        let nonce = next_nonce(&keychain, &kpool, &events, None).await?;
        let note = keychain.note(&kpool, nonce).await?.note;
        let deposited =
            chain::deposit(&provider, &pool, &FrameSigner::Secp256k1(funder), &note).await?;
        let commitment = B256::from(note.commitment());
        println!(
            "before the loss: keychain note {nonce} deposited in {} (block {}), leaf {}, commitment {commitment}",
            deposited.receipt.transaction_hash,
            deposited.receipt.block_number,
            deposited.leaf_index
        );
        (shares, nonce, commitment)
    };

    // 2. The phone is lost: nothing of the keychain is left but the two devices' shares.

    // 3. Recovery from the two devices.
    let recovered_key = PrivateKeySigner::from_bytes(&join(shares))?;
    let keychain = SignatureKeychain::new(recovered_key);
    let events = pool_events(&provider, pool.address, 0).await?;
    let recovered = recover(&keychain, &kpool, &events, None).await?;
    let unspent: Vec<_> = recovered
        .iter()
        .filter(|r| r.withdrawal.is_none())
        .collect();
    println!(
        "recovered from the shares: {} note(s) of this keychain in {} pool events, {} unspent",
        recovered.len(),
        events.len(),
        unspent.len()
    );
    let mine = unspent
        .iter()
        .find(|r| B256::from(r.deposit.commitment) == commitment)
        .context("the deposited note was not recovered")?;
    ensure!(mine.nonce == nonce);

    // 4. Spend it: the recovered opening proves membership and pays out.
    let note = keychain.note(&kpool, mine.nonce).await?.note;
    let leaves = chain::leaves(&provider, pool.address, mine.deposit.leaf_index as usize).await?;
    let root = B256::from(MerkleTree::from_leaves(&leaves)?.root()?);
    let slot = root_slot(&provider, pool.address, mine.deposit.block_number, root)
        .await?
        .context("the pool did not publish this root to EIP-8272 in the deposit's block")?;
    let recipient = PrivateKeySigner::random().address();
    let payer = Payer {
        address: pool.address,
        fee: U256::from(FEE),
        refund: U256::ZERO,
    };
    let proof = prove(note, &leaves, recipient, payer, &mut rand::rng())?;
    let opts = WithdrawalOpts {
        root_slot: Some(slot),
        ..WithdrawalOpts::new(chain_id)
    };
    let tx = withdrawal_tx(&pool, &proof.inputs, &proof.proof, &opts)?;
    let executed = rpc::execute(&provider, &tx, true).await?;
    ensure!(
        executed.receipt.payer == pool.address,
        "the pool did not pay"
    );
    let received = provider.get_balance(recipient).await?;
    ensure!(received == U256::from(DENOMINATION - u128::from(FEE)));
    println!(
        "withdrawn with the recovered opening: {} in block {}, gasUsed {}, no signature; recipient {recipient} received {received} wei",
        executed.hash, executed.receipt.block_number, executed.receipt.gas_used
    );
    Ok(())
}
