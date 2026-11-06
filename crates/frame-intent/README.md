# kohaku-frame-intent

Experimental. The exact list of writes a frame transaction makes, compared with an intent the user
picks from a template, without a language model. This is `exp-frames` experiment 58, whose README
holds the pre-registration, the templates, the exemptions and the cases.

- `writes`: the `writes` field of a patched `ethrex_simulateFrameTransaction`, as exp-e2e-frames'
  `docs/simulated-writes.md` documents it (`f8c7361`).
- `template`, `layout`: the templates (`erc20-transfer`, `eth-transfer`, `approve-and-swap`,
  `pool-withdrawal`, `calls-only`) and the registry that maps a contract's resources to its slots.
- `check`: the exact comparison and the verdict, `pass`, `fail` or `not-simulated`. The fee and
  the nonce are exempt by kind and bounded; nothing else is exempt.
- `encode`: on a pass, Q in experiment 54's two forms:
  - `assertWrites`, for a mode-3 frame where EIP-7906 runs;
  - `assert(Q)`, for the final frame of an atomic batch where it does not.

  `sign_batch` puts the second form into the transaction and signs it again.

## `write-check`

```text
cargo run -p kohaku-frame-intent --bin write-check -- \
  --raw <0x06...> --layouts <registry.json> --template erc20-transfer \
  --param token=0x... --param to=0x... --param amount=10000000000000000000 \
  (--rpc http://127.0.0.1:8545 | --sim simulation.json [--fee-recipient 0x...]) [--sign]
```

- `--rpc` needs a node that returns `writes`. The tool takes the fee recipient from the latest
  block, and checks every layout it uses against that node before comparing.
- `--sign` reads the owner's key from `SIGNER_KEY`.

The tests in `tests/fixtures.rs` run on hand-written fixtures in the documented format, not on a
chain's output.

**Post-quantum status.** The checker reads writes, not signatures, and works for any scheme.
`--sign` signs with secp256k1.
