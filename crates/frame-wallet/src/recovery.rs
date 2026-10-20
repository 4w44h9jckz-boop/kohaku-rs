//! Recovering a wallet's note openings from the owner's own devices.
//!
//! `kohaku-tornadocash-keychain` derives every note from one keychain key, so the note openings
//! are recoverable exactly when that key is. Here the key is split between two of the owner's
//! devices, the same two that can recover the account (`kohaku_frame_accounts::recovery`). Each
//! holds a uniformly random 32-byte share, and the key is their XOR. Neither share alone says
//! anything about the key, and no one but the owner holds one.
//!
//! After the loss, the two shares give the key back. The keychain then derives its notes nonce by
//! nonce, and [`kohaku_tornadocash_keychain::recovery::recover`] matches them against the pool's
//! `Deposit` and `Withdrawal` events, which [`pool_events`] reads from the node.

use alloy::{
    primitives::{Address, B256, U256},
    providers::Provider,
    rpc::types::Filter,
    sol_types::SolEvent,
};
use kohaku_frame_pool::withdrawal::{
    DENOMINATION, FramePool,
    abi::{Deposit, RecentRoot, Withdrawal},
};
use kohaku_tornadocash::{
    Asset, Field, Pool,
    syncer::{self, SyncEvent},
};
use rand::CryptoRng;

/// Two shares of a 32-byte secret: the first uniformly random, the second the secret XOR it.
#[must_use]
pub fn split(secret: B256, rng: &mut impl CryptoRng) -> [B256; 2] {
    let mut first = [0u8; 32];
    rng.fill_bytes(&mut first);
    let first = B256::from(first);
    [first, first ^ secret]
}

/// The secret two shares were split from.
#[must_use]
pub fn join(shares: [B256; 2]) -> B256 {
    shares[0] ^ shares[1]
}

/// A frame-native pool as the keychain names it: the chain, the address and the denomination
/// sign every note's derivation, so a note derived for one pool is not another's.
#[must_use]
pub fn keychain_pool(pool: &FramePool, chain_id: u64, deployed_block: u64) -> Pool {
    Pool {
        chain_id,
        address: pool.address,
        asset: Asset::ETH,
        amount_wei: DENOMINATION,
        deployed_block,
        paymaster: None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    #[error(transparent)]
    Transport(#[from] alloy::transports::TransportError),
    #[error("a log of {0} is malformed")]
    Malformed(&'static str),
}

fn block_of(log: &alloy::rpc::types::Log) -> Result<u64, RecoveryError> {
    log.block_number
        .ok_or(RecoveryError::Malformed("a mined event"))
}

/// The pool's `Deposit` and `Withdrawal` events since `from_block`, as the keychain's recovery
/// reads them.
pub async fn pool_events<P: Provider>(
    provider: &P,
    pool: Address,
    from_block: u64,
) -> Result<Vec<SyncEvent>, RecoveryError> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(pool)
                .event_signature(vec![Deposit::SIGNATURE_HASH, Withdrawal::SIGNATURE_HASH])
                .from_block(from_block),
        )
        .await?;
    let mut out = Vec::with_capacity(logs.len());
    for log in &logs {
        let topic = log.topics().first().copied();
        if topic == Some(Deposit::SIGNATURE_HASH) {
            let commitment = log
                .topics()
                .get(1)
                .and_then(|t| Field::try_from(*t).ok())
                .ok_or(RecoveryError::Malformed("Deposit"))?;
            let data = &log.data().data;
            let leaf_index = u32::try_from(U256::from_be_slice(
                data.get(..32).ok_or(RecoveryError::Malformed("Deposit"))?,
            ))
            .map_err(|_| RecoveryError::Malformed("Deposit"))?;
            out.push(SyncEvent::Deposit(syncer::Deposit {
                commitment,
                leaf_index,
                block_number: block_of(log)?,
            }));
        } else if topic == Some(Withdrawal::SIGNATURE_HASH) {
            let w = Withdrawal::decode_log_data(log.data())
                .map_err(|_| RecoveryError::Malformed("Withdrawal"))?;
            out.push(SyncEvent::Withdrawal(syncer::Withdrawal {
                to: w.to,
                nullifier_hash: Field::try_from(w.nullifierHash)
                    .map_err(|_| RecoveryError::Malformed("Withdrawal"))?,
                relayer: w.relayer,
                fee: w.fee,
                block_number: block_of(log)?,
            }));
        }
    }
    Ok(out)
}

/// The EIP-8272 slot in which a keyed pool published `root`, from its `RecentRoot` events in
/// `block`: what a withdrawal proving against that root names.
pub async fn root_slot<P: Provider>(
    provider: &P,
    pool: Address,
    block: u64,
    root: B256,
) -> Result<Option<u64>, RecoveryError> {
    let logs = provider
        .get_logs(
            &Filter::new()
                .address(pool)
                .event_signature(RecentRoot::SIGNATURE_HASH)
                .from_block(block)
                .to_block(block),
        )
        .await?;
    Ok(logs.iter().find_map(|l| {
        let d = &l.data().data;
        (d.len() >= 64 && B256::from_slice(&d[..32]) == root)
            .then(|| U256::from_be_slice(&d[32..64]).to::<u64>())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_shares_join_to_the_secret_and_one_is_noise() {
        let secret = B256::repeat_byte(0x5a);
        let shares = split(secret, &mut rand::rng());
        assert_eq!(join(shares), secret);
        assert_ne!(shares[0], secret);
        assert_ne!(shares[1], secret);
        // Another split of the same secret shares nothing with the first.
        let again = split(secret, &mut rand::rng());
        assert_ne!(again[0], shares[0]);
        assert_eq!(join(again), secret);
    }
}
