# kohaku-frame-device-key

Notes of private owned state whose owner is a P-256 key, as `exp-frames` experiment 50 deployed
them on the ethrex Hegota testnet: the note commits to the key's address, the kernel proof makes
it public, and the registry's `VERIFY` checks the key's signature over the transaction, either
with EIP-7951's `P256VERIFY` (an `ARBITRARY` entry) or through the protocol's P256 scheme.

**Simulated.** The owner key is a software P-256 key, in the experiment and in this crate. It
stands in for a key held by a device's secure element. Nothing here tests an enclave.

| Item | What |
|---|---|
| `RegistryV3` | the registry version 3, or its control (`keyed: false`), and where it deploys |
| `kernel_key` | experiment 50's kernel key: seven public inputs |
| `inner`, `owner_of` | `H(nullifierSecret, secret, owner)` and the key's address as a number |
| `update_tx` | the update, with an empty entry for the owner's signature |
| `sign_update` | the one request an enclave would serve: a P-256 signature over the signature hash, low `s` |
| `check_owner` | what the registry checks of that entry, offline |

`tests/chain.rs` checks experiment 50's mined transactions with this crate alone: the verifier
and both registries land at the testnet's addresses; A, B, C and E rebuild byte for byte; each
proof verifies; each owner signature passes the registry's checks; and a stranger's key, a high
`s` and a signature moved to another update are refused (4 tests).

The update reuses `kohaku-frame-registry`'s `Update`: word 6, its `link`, holds the owner.
