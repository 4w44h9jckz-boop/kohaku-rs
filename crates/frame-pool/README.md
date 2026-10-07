# kohaku-frame-pool

Experimental. A Tornado Cash pool whose withdrawals are EIP-8141 frame transactions with the pool
itself as `tx.sender`: the proof is checked in the pool's `VERIFY` frame, so a withdrawal needs no
relayer, no EOA and no signature.

This crate holds the client side. It reuses the Tornado Cash circuit, notes and Merkle tree from
`kohaku-tornadocash` unchanged; what changes is the contract that checks the proof and the
transaction that carries it. The contracts and the testnet measurements live in the
`exp-frames` repository (experiment 06).

The `frame-pool` binary exposes note generation, the tree's zero hashes and proving as JSON, so
that a script in another language can drive the pool:

```text
cargo run --release -p kohaku-frame-pool --bin frame-pool -- note
cargo run --release -p kohaku-frame-pool --bin frame-pool -- zeros
cargo run --release -p kohaku-frame-pool --bin frame-pool -- prove < request.json
```
