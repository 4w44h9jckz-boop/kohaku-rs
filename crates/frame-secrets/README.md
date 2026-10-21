# kohaku-frame-secrets

Experimental. The wallet's secrets: one seed that every other secret derives from. The testnet
runs and their write-ups are `exp-frames` experiments 45 to 47.

## `derive`: one seed (experiment 45)

```text
mnemonic   BIP-39, 24 English words
seed       BIP-39's 64-byte seed, empty passphrase
owner i    BIP-32 at BIP-44's m/44'/60'/0'/0/i                              secp256k1
K(label)   HKDF-SHA256(IKM = seed, salt = "kohaku-seed-v1", info = label)   32 bytes
```

[`PATHS`] lists every label, what it gives and what brings back what it opened after a loss:
the account's CREATE2 salt, the privacy-pool keychain, withdrawal recipients, each vault's
note secrets (custody per application), the viewing key, each ticket's fresh sender, salt and
blinding factor, and the backup's key and locator. A ticket's blinding factor is RFC 9380's
`hash_to_field` of `K` into BLS12-381's scalar field; `kohaku-frame-ticket`'s `blind_with` takes
it in place of a random one.

`tests/vector.rs` pins every path from BIP-39's public all-zero 24-word mnemonic
(`tests/fixtures/vector.json`), which `exp-frames` experiment 45 computes again in TypeScript.

`examples/seed_wallet.rs` is experiment 45's run, as two processes:

```text
SEED_FILE=... PRIVATE_KEY=0x... PUBLIC=public.json MODE=build \
  cargo run --release -p kohaku-frame-secrets --example seed_wallet
SEED_FILE=... PUBLIC=public.json MODE=restore \
  cargo run --release -p kohaku-frame-secrets --example seed_wallet
```

The first builds a wallet from a new mnemonic, kept in `SEED_FILE`: an account at an address the
seed fixes, a privacy-pool note, a vault note, a vault note the funder makes for it and seals to
its viewing key, and two blind tickets whose blinded answers it posts beside their requests. The
second is given the mnemonic and the contracts' public addresses only. It rebuilds all of it from
the chain, withdraws the pool note to a derived recipient, spends a ticket from a fresh sender,
and sends from the account. A run on 2026-10-21 did so in blocks 490,517 to 490,538.
`tests/record45.rs` reads that run's public record back.
