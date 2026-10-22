# kohaku-noir-transfer

Experimental. A private transfer on Aztec's note and nullifier model, proved from Rust: the
wallet side of `exp-frames` experiment 42. The circuit is that experiment's `transfer.nr`: it
spends two notes from a depth-32 Poseidon2 tree and creates two, with seven public inputs. The
compiled circuit is `fixtures/transfer.json`, as Noir 1.0.0-rc.6's compiler wrote it.

Everything third-party is used unmodified, at the releases experiment 42 pins:

| crate | version | from | licence |
|---|---|---|---|
| `acvm`, `acir`, `bn254_blackbox_solver` | 1.0.0-rc.6 | Noir, commit `2c22344a0d76f2456d017859a8f59d4dcd7b1208` | MIT OR Apache-2.0 |
| `barretenberg-rs` | 5.2.1 | aztec-packages, commit `20a398740d3716f09d36154f20e5968a37c05214` | Apache-2.0 |

`barretenberg-rs` is built with only its `native` feature. That feature drives Barretenberg's `bb`
binary over its msgpack interface; the binary is the one `@aztec/bb.js` 5.2.1 ships. The `ffi`
feature would download a static library from GitHub's release pages at build time.

- `hash`, `Tree`: the sponge the circuit hashes with, over Noir's own Poseidon2 permutation, and
  the note tree.
- `transfer`: from a request (the same JSON `exp-frames`' `build/prove.mjs` takes), the root,
  the two nullifiers and the circuit's whole input. The spent notes are ordered so that their
  nullifiers ascend, because the pool takes them as the transaction's EIP-8250 nonce keys in that
  order.
- `Circuit::execute`: the witness, by Noir's executor.
- `prove`: the proof, by Barretenberg, for either of its EVM targets, and Barretenberg's own check
  of it.

The tests compare against the JavaScript packages' outputs: Poseidon2 against `bb.js`, and the
transfer's root, nullifiers and output notes against `build/drive.mjs`'s. When `BB` names the
binary, they also prove for both targets.

## Run

```text
BB=.../@aztec/bb.js/build/amd64-linux/bb cargo test --release -p kohaku-noir-transfer
BB=... cargo run --release -p kohaku-noir-transfer --example prove -- response.json < request.json
```

The crate is left out of CI's `wasm32-unknown-unknown` check: it starts a process.
