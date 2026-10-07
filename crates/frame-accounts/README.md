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

| Example | Experiment | What it does |
|---|---|---|
| `ex01_transfer` | 01, Example 1a | sends ETH from an account with no code, to a new account and then again |
| `ex02_account_deployment` | 02, Example 1b | a `SimpleAccount` deploys itself at `tx.sender` and sends in the same transaction, then sends on its own |
| `ex03_atomic_batch` | 03, Example 2 | approve and swap as a batch; a batch whose swap reverts (rolled back, next frame skipped); the same without the flag (a dangling allowance) |
| `ex04_sponsored` | 04, Example 3 | a user with no ETH: first the funder pays as an `EoaSponsor`, then `TokenSponsor` is paid in tUSD and refunds in its post-op |
| `ex05_multisig` | 05 | 2-of-3 multisigs, one secp256k1-only and one with a P256 passkey owner, send with two signatures |

The examples reuse the contracts and accounts the experiments deployed: the same code, salts
and derived keys give the same addresses. A run on 2026-10-07 (blocks 304730 to 304746) sent 13
transactions, now fixtures in `kohaku-frame-kit`. Every frame used the gas the TypeScript runs
recorded for the same step. The multisig transfers match exactly (35,622 and 43,554 gas). The
other totals differ only where the calldata or the existing state differs: other recipients, or
a slot the earlier run had already created.
