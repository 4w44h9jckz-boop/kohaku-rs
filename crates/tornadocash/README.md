# kohaku-tornadocash

Rust [Tornadocash](https://tornadocash.eth.limo/) client library, designed to interface with Tornado Cash's smart contracts. It provides support for:
- Deposit and withdrawal transaction generation
- Pluggable event syncing ([JSON-RPC](./src/syncer/rpc.rs), [cached remote](./src/syncer/remote.rs), [saga-sync](./src/syncer/saga_sync/mod.rs))
- Merkle tree construction and proof generation
- [Relayed](./src/relayer/) withdrawal transactions
- [Paymaster-sponsored](./src/userop_provider/) withdrawal transactions

## Example

### Depositing into a Tornado Cash pool

```rust,no_run
use rand::RngExt;
use alloy::providers::{DynProvider, Provider};
use kohaku_tornadocash::{Deposit, Pool};

async fn example(
    provider: DynProvider, 
    rng: &mut impl rand::CryptoRng,
) -> Result<(), Box<dyn std::error::Error>> {
    let deposit = Deposit::new(&Pool::SEPOLIA_ETHER_01, rng.random());
    
    // ERC20 pools are pulled with `transferFrom` and require an approval before the deposit.
    if let Some(approval) = deposit.approval() {
        provider.send_transaction(approval).await?.watch().await?;
    }
    provider.send_transaction(deposit.into()).await?.watch().await?;

    Ok(())
}
```

### Withdrawing directly from a Tornado Cash pool

```rust,no_run
use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider},
};
use kohaku_tornadocash::{
    merkle_tree::{MerkleTree, MerkleTreeExt},
    Note,
    Pool,
    syncer::{DynSyncer, Syncer},
    Withdrawal,
};

async fn example(
    provider: DynProvider,
    syncer: &DynSyncer,
    pool: Pool,
    note: Note,
    recipient: Address,
    rng: &mut impl rand::CryptoRng,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut tree = MerkleTree::new();
    let snapshot = syncer.sync(&pool, ..).await?;
    tree.splice_events(&snapshot.events)?;

    let merkle_proof = tree.leaf_proof(note.commitment())?;
    let withdrawal = Withdrawal::new(&pool, note, recipient)
        .prove(&merkle_proof, rng)?;

    provider.send_transaction(withdrawal.into()).await?.watch().await?;

    Ok(())
}
```

### Withdrawing via a Tornado Cash relayer

```rust,no_run
use alloy::{
    primitives::{Address, U256},
    providers::{DynProvider, Provider},
};
use kohaku_tornadocash::{merkle_tree::MerkleTree, Note, Pool, Relayer, Withdrawal};

async fn example(
    provider: DynProvider,
    tree: &MerkleTree,
    pool: Pool,
    note: Note,
    recipient: Address,
    rng: &mut impl rand::CryptoRng,
) -> Result<(), Box<dyn std::error::Error>> {
    let relayer = Relayer::new("https://mainnet.relayer.com");

    let status = relayer.status().await?;
    let gas_price = provider.get_gas_price().await?;
    let merkle_proof = tree.leaf_proof(note.commitment())?;

    let withdrawal = Withdrawal::new(&pool, note, recipient)
        .with_payer(status.quote(&pool, gas_price, U256::ZERO)?)
        .prove(&merkle_proof, rng)?;

    // Confirmation is judged by the nullifier being spent on-chain, not by the relayer's report.
    let receipt = relayer.withdraw(withdrawal).await?;
    let tx_hash = relayer.await_confirmation(&provider, &receipt).await?;
    println!("{tx_hash:?}");

    Ok(())
}
```

### Withdrawing via a `UserOperation`

```rust,no_run
use alloy::{providers::DynProvider, signers::local::PrivateKeySigner};
use kohaku_tornadocash::{
    merkle_tree::MerkleTree,
    Note,
    Pool,
    userop_provider::UserOperationPaymasterExt,
    Withdrawal,
};
use kohaku_userop_kit::{
    builder::UserOperationBuilder,
    bundler::{Bundler, pimlico::PimlicoBundler},
    smart_account::simple_7702_smart_account::{Call, Simple7702SmartAccount},
};

async fn example(
    provider: DynProvider,
    tree: &MerkleTree,
    pool: Pool,
    note: Note,
    rng: &mut impl rand::CryptoRng,
) -> Result<(), Box<dyn std::error::Error>> {
    let owner = PrivateKeySigner::random();
    let bundler = PimlicoBundler::new("https://bundler.pimlico.com".parse()?);

    let smart_account = Simple7702SmartAccount::new(provider.clone(), owner.address(), pool.chain_id);
    let builder = UserOperationBuilder::new_with_smart_account(&smart_account)
        .await?
        .with_call(&vec![Call::default()]);

    // The note pays for gas, and its remainder is withdrawn to `owner` during validation, so the
    // operation's own calls can spend it.
    let withdrawal_merkle_proof = tree.leaf_proof(note.commitment())?;
    let withdrawal = Withdrawal::new(&pool, note, owner.address());
    let builder = builder
        .with_tornado_paymaster(withdrawal, &withdrawal_merkle_proof, &provider, &bundler, rng)
        .await?;

    let userop = builder.build().sign(&owner).await?;
    let hash = bundler.send_user_operation(&userop).await?;
    println!("{hash:?}");

    Ok(())
}
```
