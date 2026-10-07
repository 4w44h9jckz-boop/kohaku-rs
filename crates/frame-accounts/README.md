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
  - `SessionAccount`: one owner, plus session keys the owner grants. A session may call one
    target with one selector until a deadline, within a budget in wei that counts value and
    maximum fees; `session_tx` lays out the four-frame shape the account's `VERIFY` checks.
- `sponsor`: who pays when the sender does not.
  - `EoaSponsor`: another account signs and pays.
  - `TokenSponsor`: paid in an ERC-20, priced on the transaction's `max_cost`, with a refund
    post-op (the EIP's Example 3).
  - `CanonicalPaymaster`: an instance of the EIP's canonical paymaster, whose signer approves
    payments without holding ETH. It is the only payer the mempool lets carry many pending
    transactions at once; it reads signature entry 1, so the sender must have exactly one entry.
  - `MultisigSponsor`: a `Multisig` treasury paying for one member at a time.
- `builder`: `TxPlan` lays out account, sponsor and calls, and lets the sponsor price the
  result. `expires_at` adds a deadline in the expiry verifier frame, which goes first. A nonce
  key used for the first time gets its 97,920 state gas on whichever frame approves payment.
  Signing is separate (`kohaku_frame_kit::sign_all`), so keys never have to be where the
  transaction is built.
- `calls` and `contracts`: common calls with the state gas they need, and the account and
  sponsor contracts with CREATE2 deployment. The Yul sources are in `contracts/`.

These are the contracts and layouts of the `exp-frames` experiments 01 to 05, 09, 10 and 12.
The tests rebuild 34 transactions those experiments mined on the ethrex Hegota testnet byte for
byte, and 3 more frame for frame, where the experiment named a signer this crate leaves
implicit. They also check that the embedded contract code lands at the addresses the testnet
has it at, and that the canonical paymaster's runtime hashes to the pinned value. The examples
run experiments 01 to 05 again from Rust:

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

## What later experiments changed here

| Rule | Where | From |
|---|---|---|
| A deadline is a `VERIFY` frame on `0x8141` with 8 bytes of data, first in the transaction. It costs 3,051 gas, and 3,050 runs out | `TxPlan::expires_at` | experiment 10 |
| A nonce key's first use creates a 64-byte slot, charged to the frame that approves payment | `Envelope::fresh_nonce_keys`, the builder | experiments 01, 08 and 16 |
| The canonical paymaster is recognised by its code hash alone. Every other payer, a code-less sponsor included, is held to one pending transaction | `CanonicalPaymaster`, `contracts::is_canonical_paymaster` | experiment 09 |
| A replacement must raise both fees by 10% | `kohaku_frame_kit::Fees::bumped` | experiment 19 |
| A receipt can name a block that is then replaced; send what depends on it only once a block is built on it | `kohaku_frame_kit::rpc::execute` | experiment 19 |
| `TIMESTAMP` is banned in `VERIFY`, so a session's deadline comes from the expiry frame; `VERIFY` is static, so a spend is recorded by a frame outside any batch that the account makes sure cannot fail | `SessionAccount` | experiment 12 |
| A pending session transaction is revoked by replacing it at the same nonce, since the pool holds one pending transaction per such sender | `SessionAccount::revoke_session`, `Fees::bumped` | experiment 12 |

Experiment 21 ran `kohaku-userop-kit`'s path on the same chain: `EntryPoint` v0.8, a
`Simple7702Account` EOA and a bundler, against frames. The same ERC-20 transfer cost 122,868
gas through the `EntryPoint`, 116,735 from a `SimpleAccount`, and 47,927 from a frame EOA. The
first operation from a fresh 7702 EOA cost another 195,840, for the `EntryPoint`'s nonce and
deposit slots. The `EntryPoint` writes the deposit slot after it has measured the operation's gas,
so the bundler paid that slot's 97,920 itself. A frame sender has neither slot and no bundler.
