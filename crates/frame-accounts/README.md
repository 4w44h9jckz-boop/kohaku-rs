# kohaku-frame-accounts

Experimental. Accounts and sponsors for EIP-8141 frame transactions, on top of
`kohaku-frame-kit`. It covers what `kohaku-userop-kit`'s smart account and paymaster cover for
ERC-4337, with no `EntryPoint`, bundler or deposit: an account is a `VERIFY` frame, a sponsor is
another `VERIFY` frame, and a call is a `SENDER` frame.

- `account`: who `tx.sender` is and how it approves.
  - `Eoa`: no code; the protocol's default code checks a secp256k1 or P256 signature by the
    sender.
  - `SimpleAccount`: one secp256k1 owner, counterfactual, able to deploy itself in its first
    transaction (the EIP's Example 1b).
  - `Multisig`: k of n secp256k1 or P256 owners.
- `sponsor`: who pays when the sender does not.
  - `EoaSponsor`: another account signs and pays.
  - `TokenSponsor`: paid in an ERC-20, priced on the transaction's `max_cost`, with a refund
    post-op (the EIP's Example 3).
- `builder`: `TxPlan` lays out account, sponsor and calls, and lets the sponsor price the
  result. Signing is separate (`kohaku_frame_kit::sign_all`), so keys never have to be where the
  transaction is built.
- `calls` and `contracts`: common calls with the state gas they need, and the account and
  sponsor contracts with CREATE2 deployment. The Yul sources are in `contracts/`.

These are the contracts and layouts of the `exp-frames` experiments 01 to 05. The tests rebuild
19 transactions those experiments mined on the ethrex Hegota testnet byte for byte, and check
that the embedded contract code lands at the addresses the testnet has it at. The examples run
each experiment again from Rust:

```text
PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-accounts --example <name>
```
