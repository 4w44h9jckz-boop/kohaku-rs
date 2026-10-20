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

## Version 2 and the swap (`exp-frames` experiment 33)

Version 2 of the registry (`Version::V2`) adds two things. Every proof binds the deadline of an
expiry frame at the front of the transaction, so a proof handed to someone else stops being
usable at a time its maker chose. And each update of a pair names the other's nullifier and
change note (`update::pair_link`), so a pair is a fair swap: neither proof is valid beside any
other update. Version 1's pair named only the other's nullifier. That made it atomic, but the
other side could spend its note in the same transaction and keep the value.

- `announce`: messages sealed to a secp256k1 key (ECDH, HKDF-SHA256, AES-256-GCM, with a
  one-byte view tag), the board's `post` frame, a scan of its `Posted` events, and a swap's
  offer and answer.
- `update::update_tx` builds both versions; for version 2 it takes the deadline and refuses a
  pair whose links do not name each other.

`tests/swap.rs` checks the experiment's mined transactions: registry version 2, the second asset
and the board land at their testnet addresses. The swap and the two owners' own updates are
rebuilt byte for byte, and each proof verifies with its deadline and fails with any other.
The swap's two updates name each other. Each of the six posted messages is a sealed offer or
answer. And `tests/fixtures/announcement.json`, written by the TypeScript, seals to the same
bytes here and opens.

`examples/scan_board.rs` scans the testnet board with the experiment's keys:

```text
PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-registry --example scan_board
```

On 2026-10-20 it found the board's 6 messages. Bob's key opened 3 offers and Alice's 3 answers.
For the first pair, the two notes the swap had to create, computed from the decrypted terms
alone, were both in the registry, and both nullifiers were used. For the other two, only the
offerer's nullifier was used, by Alice's cancel, and the acceptor's note was still his.

## Custody per application (`exp-frames` experiment 40)

`custody` is the vaulted registry: experiment 32's tree, verifier and nonce space, with each
application's value in a vault of its own (`Vault.yul`) that pays only that application's
withdrawals, on the registry's call. The registry computes a vault's scope,
`SHA-256(0x91 || params || uint64be(chain id) || vault) mod p`, from the vault's address, and
every note under it, so a note opens against one vault only. Each proof is bound to a context,
`SHA-256(0x61 || recipient || fee || max_priority_fee_per_gas || max_fee_per_gas) >> 8`, which the
registry's `VERIFY` computes from the transaction's own fees. An update carries no signature, so
without the fees in the context anyone holding a pending one could send it again with a higher
priority fee and pay the difference to the block's producer, which experiment 40's control did
against experiment 32's registry. The kernel and its key are unchanged: the scope is its `tag` and
the context its `binding`. `VERIFY` reads no storage.

`tests/custody.rs` checks experiment 40's mined transactions with this crate alone:
- the registry and the three vaults are at the testnet's addresses;
- each scope is the one the TypeScript computed, and A and its twin C, with the same parameters,
  have different scopes;
- each deposit's leaf is its call's under its vault's scope;
- each update is rebuilt byte for byte, and its proof verifies under its own vault's scope and its
  own fees, and under no other vault's and with no other fees;
- both payments in each update frame, the recipient's and the fee, were made by the note's vault.
