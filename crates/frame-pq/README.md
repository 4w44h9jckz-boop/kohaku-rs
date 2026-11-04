# kohaku-frame-pq

Experimental. The wallet's keys in a post-quantum form: leanSPHINCS signatures from the wallet's
seed, accepted on chain through EIP-8288 dependencies, and ML-KEM-768 where the wallet seals a
message to a key. The testnet runs and their write-up are `exp-frames` experiment 49.

leanSPHINCS is leanVM's at
[`3cbac04`](https://github.com/leanEthereum/leanVM/tree/3cbac047160f4d1465bfe985521603b0a3418556):
a 32-byte seed, a 32-byte public key (`root || public parameter`), a 7,740-byte signature,
stateless, at most $2^{30}$ signatures per key. leanVM says these parameters are not final. Build
with `RUSTFLAGS="-C target-cpu=native"`, as leanVM's own workspace does, or its times are not
comparable.

## Keys

```text
sphincs/account/<i>/owner/<j>   account i's owner, the j-th since it was made
sphincs/ticket/<k>/sender       ticket k's fresh sender
sphincs/ticket/<k>/binder       ticket k's one-time key
sphincs/recipient/<n>           the pool's n-th recipient
sphincs/view/d, sphincs/view/z  the ML-KEM-768 viewing key's seed
```

each `K(label)` of `kohaku-frame-secrets`, so the seed's recovery brings them all back.

## How a key authorises a transaction

The transaction declares the triple `0x10 || 32 zero bytes || key`, and EIP-8288 reads the zero
data hash as the transaction's signature hash: the block's proof checks the key's signature over
it. Where the triple travels is fixed when an account is deployed (`Carrier`):
- `Dependency`: in a dependency frame (mode 4). An account deployed so never accepts a triple
  anywhere else, which nothing would prove.
- `Modelled`: in the account's own `VERIFY` data, for a chain without EIP-8288. Nothing on chain
  checks the signature; `account::witnesses` signs and checks it off chain.

## Contracts

`contracts/`, compiled by solc 0.8.37 (EVM version osaka, optimizer on, 200 runs):
- `SphincsAccount.yul`: the device-recovery account of `kohaku-frame-accounts` with every key a
  leanSPHINCS key: an owner that $m$ committed recovery keys can replace after a delay the owner
  can use to cancel. 1,168 bytes of runtime.
- `SphincsSender.yul`: one key, kept in the code, small enough (190 bytes with its key) to deploy
  itself ahead of its own `VERIFY`, within the validation prefix's 500,000 state gas.
- `PqBoundTicketPaymaster.yul`: experiment 48's bound paymaster with the one-time key a leanSPHINCS
  key: a 164-byte message, 200-byte pay data, and the binder's triple required.

## Modules

- `account`: the two accounts, `Acting` and `Fresh` for `TxPlan`, `declare` (the dependency frame)
  and `witnesses` (each key's signature over the signature hash).
- `ticket`: the bound claim, ticket and paymaster.
- `envelope`: experiment 46's seed envelope under a leanSPHINCS recovery key.
- `seal`: ML-KEM-768 and AES-256-GCM, for shares handed to a new device and notes sealed to the
  viewing key.

`examples/pq_wallet.rs` is experiment 49's testnet run, `MODE=signer`, `account`, `tickets`,
`recover` and `seal`.

## What is still classical

The issuers' BLS signatures on tickets, the pool's Groth16 withdrawal proof, and the funder,
which only funds.
