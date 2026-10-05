use std::time::Duration;

use alloy::{
    providers::Provider,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use tokio::time::sleep;
use tracing::{info, warn};

use crate::{
    abis::tornado::Tornado,
    pool::Pool,
    syncer::{
        Snapshot, SyncEvent, Syncer, SyncerError,
        event::{Deposit, Withdrawal},
    },
};

/// A syncer that reads from an Ethereum JSON-RPC provider
#[derive(Clone)]
pub struct RpcSyncer<P: Provider> {
    provider: P,
    batch_size: u64,
    batch_delay: Duration,
}

#[derive(Debug, thiserror::Error)]
enum RpcSyncerError {
    #[error("Error decoding log: {0}")]
    LogDecodeError(#[from] alloy::sol_types::Error),
    #[error("RPC error: {0}")]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    #[error("Unknown event with topics {topics:?}")]
    UnknownEvent {
        topics: Vec<alloy::primitives::B256>,
    },
    #[error("Missing block number in log")]
    MissingBlockNumber,
    #[error("Field conversion error: {0}")]
    Field(#[from] crate::field::NotInRangeError),
}

impl<P: Provider> RpcSyncer<P> {
    pub fn new(provider: P) -> Self {
        Self {
            provider,
            batch_size: 10,
            batch_delay: Duration::from_millis(1000),
        }
    }

    #[must_use]
    /// Sets the batch size for `eth_getLogs` calls.
    pub fn with_batch_size(mut self, batch_size: u64) -> Self {
        self.batch_size = batch_size;
        self
    }

    #[must_use]
    /// Sets the delay between `eth_getLogs` calls.
    pub fn with_batch_delay(mut self, batch_delay: Duration) -> Self {
        self.batch_delay = batch_delay;
        self
    }
}

#[cfg_attr(native, async_trait::async_trait)]
#[cfg_attr(wasm, async_trait::async_trait(?Send))]
impl<P: Provider> Syncer for RpcSyncer<P> {
    async fn sync_range(
        &self,
        pool: &Pool,
        from_block: u64,
        to_block: u64,
    ) -> Result<Snapshot, SyncerError> {
        Ok(self
            .sync(pool, from_block, to_block)
            .await
            .map_err(SyncerError::other)?)
    }
}

impl<P: Provider> RpcSyncer<P> {
    async fn sync(
        &self,
        pool: &Pool,
        from_block: u64,
        to_block: u64,
    ) -> Result<Snapshot, RpcSyncerError> {
        let range = self.block_range(pool, from_block, to_block).await?;
        info!("Syncing from {} to {}", range.start, range.end);

        let batch_size = self.batch_size.max(1);
        let mut events = Vec::new();
        let mut current = range.start;

        while current < range.end {
            //? `eth_getLogs` treats both block bounds as inclusive
            let batch_end = current.saturating_add(batch_size).min(range.end) - 1;

            let filter = Filter::new()
                .address(pool.address)
                .from_block(current)
                .to_block(batch_end);

            let logs = self.provider.get_logs(&filter).await?;
            sleep(self.batch_delay).await;

            for log in logs {
                match decode_log(&log) {
                    Ok(decoded) => events.push(decoded),
                    Err(RpcSyncerError::UnknownEvent { topics }) => {
                        warn!("Unknown event with topics {topics:?}");
                    }
                    Err(e) => return Err(e),
                }
            }

            current = batch_end + 1;
            info!("{}/{} ({} events)", current, range.end, events.len());
        }

        Ok(Snapshot { range, events })
    }

    /// Clamps the requested range to the blocks this syncer can serve: the pool's deployment
    /// block through the chain's latest block.
    async fn block_range(
        &self,
        pool: &Pool,
        from_block: u64,
        to_block: u64,
    ) -> Result<std::ops::Range<u64>, RpcSyncerError> {
        let from = from_block.max(pool.deployed_block);
        //? `latest_block` is an inclusive block number, `to_block` an exclusive bound.
        let latest = self.provider.get_block_number().await?.saturating_add(1);
        let to = to_block.min(latest).max(from);

        Ok(from..to)
    }
}

fn decode_log(log: &Log) -> Result<SyncEvent, RpcSyncerError> {
    match log.topics().first() {
        Some(&Tornado::Deposit::SIGNATURE_HASH) => {
            let decoded = Tornado::Deposit::decode_log(&log.inner)?.data;
            Ok(SyncEvent::Deposit(Deposit {
                commitment: decoded.commitment.try_into()?,
                leaf_index: decoded.leafIndex,
                block_number: log.block_number.ok_or(RpcSyncerError::MissingBlockNumber)?,
            }))
        }
        Some(&Tornado::Withdrawal::SIGNATURE_HASH) => {
            let decoded = Tornado::Withdrawal::decode_log(&log.inner)?.data;
            Ok(SyncEvent::Withdrawal(Withdrawal {
                to: decoded.to,
                nullifier_hash: decoded.nullifierHash.try_into()?,
                relayer: decoded.relayer,
                fee: decoded.fee,
                block_number: log.block_number.ok_or(RpcSyncerError::MissingBlockNumber)?,
            }))
        }
        _ => Err(RpcSyncerError::UnknownEvent {
            topics: log.topics().to_vec(),
        }),
    }
}
