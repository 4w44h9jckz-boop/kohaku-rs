# kohaku-frame-pool

Experimental. A Tornado Cash pool whose withdrawals are EIP-8141 frame transactions with the pool
itself as `tx.sender`: the proof is checked in the pool's `VERIFY` frame, so a withdrawal needs no
relayer, no EOA and no signature.

This crate holds the client side. It reuses the Tornado Cash circuit, notes and Merkle tree from
`kohaku-tornadocash` unchanged; what changes is the contract that checks the proof and the
transaction that carries it. The contracts and the testnet measurements live in the
`exp-frames` repository (experiment 06).

- `prove`: a proof and its six public inputs for a note among the pool's leaves.
- `withdrawal`: the withdrawal transaction in its four layouts (storage or keyed pool, pool or
  sponsor pays), built with `kohaku-frame-kit`. It refuses what the pool's `VERIFY` would
  refuse. The test rebuilds every withdrawal mined on the testnet byte for byte.

`examples/keyed_withdrawal.rs` runs the whole flow against the testnet in Rust. An account
deposits into the keyed pool, and the pool then withdraws to a fresh address with itself as
sender. Nothing on the withdrawal side holds a key.

```text
PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-pool --example keyed_withdrawal
```

A run on 2026-10-07 put the deposit in block 304500 and the withdrawal in block 304501. The
withdrawal used 567,821 gas: 5,579 for the EIP-8272 root check, 244,808 plus 97,920 state for
the pool's `VERIFY` (the Groth16 check plus the first use of the nullifier as a nonce key), and
14,381 plus 183,600 state for the payout.

The `frame-pool` binary exposes note generation, the tree's zero hashes and proving as JSON, so
that a script in another language can drive the pool:

```text
cargo run --release -p kohaku-frame-pool --bin frame-pool -- note
cargo run --release -p kohaku-frame-pool --bin frame-pool -- zeros
cargo run --release -p kohaku-frame-pool --bin frame-pool -- prove < request.json
```
