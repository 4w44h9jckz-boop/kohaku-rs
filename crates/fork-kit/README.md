# kohaku-fork-kit

Fixtures for testing Kohaku crates against local network instances.

Kohaku's integration tests are designed to run entirely locally. Certain tests thus require local infrastructure, such as a local Ethereum node, 4337 bundler, or certain deployed contracts. This crate provides APIs for spinning up and interacting with these local instances, as well as fixtures for common test scenarios.

## A local ethrex node for frame transactions

The anvil fixtures cannot carry EIP-8141 frame transactions (type `0x06`). `ethrex::EthrexBuilder`
starts an `ethrex` binary instead, on ethrex's single-node Hegota genesis
(`fixtures/ethrex-l1-hegota.json`, copied from ethrex `fixtures/genesis/l1-hegota.json` at
`379bff04`), with the ethrex Hegota testnet's block gas limit, base fee and
`--mempool.max-verify-gas`. It produces the blocks itself, as a consensus client would, through
`engine_forkchoiceUpdatedV5`, `engine_getPayloadV6` and `engine_newPayloadV6`. ethrex's own
`--dev` mode stops at Hegota: its block producer sends `engine_forkchoiceUpdatedV4`, which
refuses Hegota payload attributes. The node installs the expiry verifier, nonce manager and
recent-root predeploys itself in the first block, byte for byte the code the testnet holds.

Build the binary from the commit the testnet runs and name it in `ETHREX_BIN`:

```text
git clone https://github.com/lambdaclass/ethrex && cd ethrex
git checkout 64b8fc09d47d7787eb1a4e3f082aa9e831dc5f8c   # hegota-testnet-hotfix
cargo build --release --bin ethrex
export ETHREX_BIN=$PWD/target/release/ethrex
```

Tests that need it skip themselves when `ETHREX_BIN` is unset, so `cargo test` stays offline and
needs no binary. `kohaku-frame-pool`'s `tests/local_node.rs` is the first. The chain id is the
genesis's, 9, not the testnet's 8141, so nothing signed against the local node is valid on the
testnet.

