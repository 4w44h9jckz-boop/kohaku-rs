# kohaku-frame-pool

Experimental. A Tornado Cash pool whose withdrawals are EIP-8141 frame transactions with the pool
itself as `tx.sender`: the proof is checked in the pool's `VERIFY` frame, so a withdrawal needs no
relayer, no EOA and no signature.

This crate holds the client side. It reuses the Tornado Cash circuit, notes and Merkle tree from
`kohaku-tornadocash` unchanged; what changes is the contract that checks the proof and the
transaction that carries it. The contracts and the testnet measurements live in the
`exp-frames` repository (experiment 06).

- `prove`: a proof and its six public inputs for a note among the pool's leaves.
- `withdrawal`: the withdrawal transaction in its five layouts (storage or keyed pool, pool or
  sponsor pays, and a refund pool that pays and then refunds), built with `kohaku-frame-kit`. It
  refuses what the pool's `VERIFY` would refuse, including an execution limit under the pool's
  floor. The test rebuilds every withdrawal mined on the testnet byte for byte.
- `chain`: the pool on a node. A deposit, the tree read back from `Deposit` events, and a
  pool-paid withdrawal priced the way `exp-frames` experiment 30 priced one. It simulates, sets
  each limit to a quarter over its use plus 5,000, and fixes the note's fee at the worst-case max
  cost of that shape, every data byte non-zero, before the final proof.

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

`tests/local_node.rs` runs the same flow against a local ethrex node from `kohaku-fork-kit`
(`ETHREX_BIN`; skipped when it is unset). It first deploys the hasher, the patched verifier and
the keyed pool with the CREATE2 frames `exp-frames` experiment 06 used
(`tests/fixtures/deployments.json`, printed by that experiment's `export.ts`), so the pool lands
at its testnet address. Then it deposits and withdraws, and requires every frame of the
withdrawal to use the status, execution gas and state gas of the block 304501 withdrawal. With
ethrex at `64b8fc09`, the testnet's commit, it does.

`examples/refund_withdrawal.rs` does the same against `exp-frames` experiment 30's
`RefundPool`. That pool's last frame sends the recipient the note's fee less an upper bound on
what the transaction is charged, so without a relayer the note pays about its gas, not its max
cost.

```text
PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-pool --example refund_withdrawal
```

A run on 2026-10-20 put the deposit in block 477921
([`0x70346def...`](https://dora.privacy.ethrex.xyz/tx/0x70346def0670b891c564372cd0a620b2792c0b50b144a13473d193453631a73f))
and the withdrawal in block 477924
([`0x339af560...`](https://dora.privacy.ethrex.xyz/tx/0x339af560b79b175b240b4250809cc14e84b34799023cb2a847053bd2e7119659)),
with no signature and the pool as payer. Priced at a 0.1 gwei tip and a 0.2 gwei max fee, as
experiment 30 priced its own, it chose the same limits, 11,973 / 310,930 / 100,000 / 25,000
execution, and the same fee, 150,658,200,000,000 wei. The withdrawal used 579,697 gas: 5,579 for
the root check, 244,744 plus 97,920 state for the pool's `VERIFY`, 14,255 plus 183,600 state for
the payout, and 11,531 for the refund. At 100,000,007 wei per gas the chain charged
57,969,704,057,879 wei. The refund frame sent back 91,341,595,847,838, so the note paid
59,316,604,152,162: 1.023 times its gas, the bound being the refund frame's 13,469 unused gas
above the charge. With `SEND_RPC_URL` set, the withdrawal is handed to that node alone, for example a mempool node
other than the chain's, while the deposit, the simulation and the receipt still go through
`RPC_URL`. A run that way on 2026-10-20, with both URLs at the testnet, mined
[`0x07f534f4...`](https://dora.privacy.ethrex.xyz/tx/0x07f534f4a6b8399b61458119c333465dc08a7a344ec5f3b9a846953569575fbb)
in block 478011 with the same limits, fee and bound. The test rebuilds the first withdrawal and both of experiment 30's byte for byte,
and `exp-frames`' `experiments/30-relayer-free-withdrawal/layout.test.ts` rebuilds the same
three in TypeScript.

The `frame-pool` binary exposes note generation, the tree's zero hashes and proving as JSON, so
that a script in another language can drive the pool:

```text
cargo run --release -p kohaku-frame-pool --bin frame-pool -- note
cargo run --release -p kohaku-frame-pool --bin frame-pool -- zeros
cargo run --release -p kohaku-frame-pool --bin frame-pool -- prove < request.json
```

`chain::keyed_batch` builds several pool-paid withdrawals from one wallet against one root, each
with its own nullifier hash as its nonce key, and refuses two spends of one note.
`examples/concurrent_withdrawals.rs` hands such a pair to a mempool node back to back
(`SEND_RPC_URL`). On 2026-10-20 a skandha node under the mempool specification's
`hegota-testnet` profile admitted both at head 479,760 and handed them to ethrex, and both were
mined in block 479,761
(`0xe2e65ff9`, `0x5ce6a700`). A second spend of the first note, sent while it was pending, was
refused as `ErrReplaceUnderpriced` (`exp-frames` experiment 34).
