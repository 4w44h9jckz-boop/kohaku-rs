# kohaku-frame-registry

Experimental. A registry for the private owned state of many applications: one tree for every
application's notes, and a contract that is its own EIP-8141 sender. A note's owner updates it
with a kernel proof checked in the registry's `VERIFY`, with the note's nullifier as the
transaction's EIP-8250 nonce key. No relayer, no EOA, no signature. The contracts and the testnet
run are `exp-frames` experiment 32; this crate is the client side, beside `kohaku-frame-pool`.

```text
inner     = H(nullifierSecret, secret)
leaf      = H(tag, inner, state)          tag = the application's address, state < 2^64 wei
nullifier = H(tag, nullifierSecret)
```

`H` is circomlib's `MiMCSponge(n, 220, 1)`, which `kohaku-tornadocash` now exports as
`mimc_sponge`. The tag is in all three, so the same secrets are two unrelated notes, with two
unrelated nullifiers, in two applications.

- `note`: secrets, leaves, and each application's nullifier.
- `update`: a deposit frame; a spend's kernel input (`Spend::kernel_input`), the signals a circom
  prover takes for `kernel.circom`; and the update transaction (`update_tx`), which refuses what
  the registry's `VERIFY` refuses for its shape: more than two updates, nullifiers out of order,
  a pair that does not link, or a fee above what an update withdraws.
- `contracts`: the registry, its Groth16 verifier with the kernel's key appended, and the three
  applications of the experiment (`FixedPool`, `Balance`, and `StoredRule`, the control whose
  rule reads its own storage), with their addresses.
- `groth16`: the verifier's pairing check, in Rust, against the same key.

The crate has no prover. The proofs are made with snarkjs in `exp-frames`, from the proving key
committed there (`experiments/32-owned-state/build/kernel.zkey`).

`tests/registry.rs` checks the experiment's mined transactions with this crate alone. The five
contracts land at their testnet addresses. Each deposit's logged leaf is `H(tag, inner, value)`
of its call. The Rust tree, built from the logged leaves, gives
the roots the updates proved against. Each of the three updates is rebuilt byte for byte, its
proof verifies in Rust, and it stops verifying with the other application's tag or another
recipient. The two applications' updates of the same secrets used two different nonce keys.
And a spend's kernel input matches, signal by signal, the one `exp-frames`' `registry.ts` computes
(`tests/fixtures/kernel-input.json`).
