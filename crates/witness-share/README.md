# kohaku-witness-share

Experimental. A withdrawal's witness, secret-shared for a proving committee instead of proved by
the wallet: the wallet half of a withdrawal proved by TACEO's co-snarks. The record is
`exp-frames` experiment 43.

The format is the one the committee fixed: `exp-e2e-frames` commit `c8eb5cc`,
`committee/co-withdraw/README.md`, "The witness's share format (fixed)". In short:

- the withdrawal circuit's whole witness as websnark extends it: 28,300 values, the constant 1,
  the six public inputs, then 28,293 private signals;
- REP3 over BN254's scalar field, of the private signals only, in co-snarks'
  `CompressedRep3SharedWitness<ark_bn254::Fr>` serialized with bincode 1, as
  `co-circom split-witness` writes it;
- `share-0.bin` to `share-2.bin` (1,811,012 bytes each, replicated) and `public.json`.

The sharing is co-snarks' own `share_rep3`, from `co-circom-types` and `mpc-core` at the
format's commit, `436f63fa17f2f10ece38c6650df68da99fbc0307`, unmodified (MIT OR Apache-2.0).
`taceo-circom-types` 0.3.1 is from crates.io (MIT OR Apache-2.0).

- `extend_witness`: the witness from `kohaku-tornadocash-circuit`'s inputs, as the wallet extends
  it before it proves alone.
- `share`, `write`: the members' shares and `public.json`.
- `reconstruct`: all three shares back into the witness, checking that each is replicated as the
  format says. It is for tests and audits; no member can run it, since each holds one share.

`kohaku-frame-pool` gains `circuit_inputs`, the inputs `prove` proves, without proving.
`chain::worst_case_fee` gives the fee for the default limits without a draft proof.
`kohaku-tornadocash` gains `Withdrawal::circuit_inputs`.

## Examples

```text
PRIVATE_KEY=0x... OUT_DIR=shares cargo run --release -p kohaku-witness-share --example share_withdrawal
cargo run --release -p kohaku-witness-share --example assemble_withdrawal -- shares/withdrawal.json members.json
```

- `share_withdrawal` deposits a fresh note into `exp-frames` experiment 30's `RefundPool`. It
  builds the withdrawal's inputs at the worst-case fee for the default limits, since the wallet
  has no draft proof to tighten them with, and writes the shares and `withdrawal.json`.
- `assemble_withdrawal` takes the proof the committee's members wrote (`co-withdraw local`'s
  `members.json`). It builds the transaction the wallet would have built around its own proof,
  simulates it, and sends it with `SEND` set.

The crate is left out of CI's `wasm32-unknown-unknown` check: co-snarks' crates do not target it.
