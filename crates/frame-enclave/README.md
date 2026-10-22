# kohaku-frame-enclave

The chain's end of `exp-frames` experiment 51: an output of a remote enclave accepted in a
`VERIFY` frame either on its attestation, a P-256 signature checked with `P256VERIFY`, or on a
Groth16 proof of the computation.

**Simulated.** The enclave in experiment 51 is a process with a sealed key; this crate only
rebuilds and checks what the chain checked.

| Item | What |
|---|---|
| `Outcome` | the outcome contract: its verifier and the attestation key it trusts, and where it deploys |
| `outcome_tx` | one output, by route, as the contract's `VERIFY` requires |
| `attestation_digest`, `attestation_holds` | what the attestation key signs, and route 1's check |
| `proof_holds`, `enclave_key` | route 2's check, and the comparison circuit's key |

`tests/chain.rs` (3 tests) finds the attestation key in the deployed initcode, lands the verifier
and the contract at the testnet's addresses, rebuilds both outputs byte for byte, verifies the
attestation for the enclave's measurement and the proof for the same statement, and shows what
each binds: the proof refuses the other output and another ciphertext; the mined attestation
does not carry over, but a fresh signature by the same key would, and nothing checkable tells it
apart.
