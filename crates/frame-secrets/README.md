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

## `guardians`: a recovery key in guardians' hands, not the seed (experiment 46)

```text
R           a fresh secp256k1 key per guardian set, not derived from the seed
shares      Shamir t-of-n of R over secp256k1's scalar field: index (1) || y (32)
commitment  keccak256(salt || 1 || address(R)), salt = K("account/<i>/recovery-salt/<r>")
envelope    0x20 || locator || nonce || AES-256-GCM(the words, padded to 216 bytes) || tag
            key = HKDF-SHA256(R || Argon2id(phrase), salt = "kohaku-seed-envelope-v1", info = address(R))
locator     keccak256("kohaku-seed-envelope-v1" || address(R))
```

`R` is the one device of `kohaku-frame-accounts`' `DeviceRecoveryAccount`, unchanged: it can
start a recovery, behind the account's delay, which the owner can cancel. The envelope needs `R`
and a phrase the user keeps, because the account's delay does not bind the seed: whoever opens
the envelope has every note at once. `seal(.., None, ..)` builds the envelope `R` alone opens,
which the experiment shows a quorum of guardians reading at once.

`examples/guardians.rs` is experiment 46's run on experiment 45's account. `MODE=setup`: a set of
three guardians, a hostile pair the owner cancels, a rotation, the old set refused.
`MODE=recover`, with no seed and no funder key: two guardians post their shares sealed to a new
device, which joins `R`, opens the envelope with the phrase, starts a recovery to owner 1 that
finishes after the delay, and rotates again. A run on 2026-10-21 did so in blocks 490,681 to
490,743. `seed_wallet`'s restore accepts any of the seed's first owners, as a recovery leaves it.

## `backup`: an encrypted backup anyone can store (experiment 47)

```text
key v      K("backup/<v>/key")          locator v   K("backup/<v>/locator")
posted     locator (32) || nonce (12) || AES-256-GCM(padded, aad = locator) || tag (16)
padded     uint32be(length) || plaintext || zeros, to a multiple of 2,048 bytes
```

One key and one locator per version, no tag byte. `examples/backup.rs` is experiment 47's run:
`MODE=write` posts two versions of the wallet's state (contracts, committees, cursors, unspent
tickets, received openings, guardians, history) from fresh senders paid with tickets;
`MODE=reopen`, given only the phrase and two guardians' shares, opens experiment 46's envelope,
finds and opens every version, checks it against the chain, and measures what each leaked key
opens. A run on 2026-10-21 posted in blocks 490,832 and 490,834.
