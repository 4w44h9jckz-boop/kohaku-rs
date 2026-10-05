# kohaku-tornadocash-keychain

Deterministic note derivation for [`kohaku-tornadocash`](../tornadocash/).

[`Keychain`]s are used to derive tornadocash note secrets from a single source of entropy. This makes it easier for users to manage their notes, because they only need to backup a single secret (e.g. a mnemonic) instead of each individual note secret. New notes can be derived from the keychain by incrementing a nonce, and notes can be recovered by scanning a pool's synced events against the keychain's derivation scheme.

## Nonce Hygiene

Nonces are used to derive tornadocash note secrets from a keychain. Nonces should:
- Be monotonically increasing, generally starting from 0. Increasing the nonce by too much can result in unrecoverable notes if the gap limit is exceeded.
- Be unique per pool. Because the (pool, nonce) pair uniquely identifies a note, reusing a nonce for the same pool results in an invalid note that cannot be deposited. This may result in compromised privacy, linking multiple addresses to the same note.

## Examples

### Deposit

```rust,no_run
use kohaku_tornadocash::Pool;
use kohaku_tornadocash_keychain::{DynKeychain, Keychain};

async fn example(
    keychain: &DynKeychain,
    pool: &Pool,
    nonce: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deposit = keychain.deposit(pool, nonce).await?;

    Ok(())
}
```

### Withdraw

```rust,no_run
use kohaku_tornadocash::{Pool, Withdrawal};
use kohaku_tornadocash_keychain::{DynKeychain, Keychain};

async fn example(
    keychain: &DynKeychain,
    pool: &Pool,
    nonce: u64,
    recipient: alloy::primitives::Address,
) -> Result<(), Box<dyn std::error::Error>> {
    let note = keychain.note(pool, nonce).await?;
    let withdrawal = Withdrawal::new(pool, note.note, recipient);

    Ok(())
}
```

### Note Recovery

```rust,no_run
use kohaku_tornadocash::{Pool, syncer::{DynSyncer, Syncer}};
use kohaku_tornadocash_keychain::{DynKeychain, recovery::{recover, next_nonce}};

async fn example(
    keychain: &DynKeychain,
    syncer: &DynSyncer,
    pool: &Pool,
) -> Result<(), Box<dyn std::error::Error>> {
    let snapshot = syncer.sync(pool, ..).await?;
    let notes = recover(keychain, pool, &snapshot.events, None).await?;

    for note in &notes {
        println!("{}: leaf {}", note.nonce, note.deposit.leaf_index);
    }

    let next_nonce = next_nonce(keychain, pool, &snapshot.events, None).await?;
    // Or calculate manually:
    // let next_nonce = notes.last().map(|note| note.nonce + 1).unwrap_or(0);
    Ok(())
}
```
