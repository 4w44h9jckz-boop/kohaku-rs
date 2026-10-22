# kohaku-frame-wallet

Experimental. A wallet that serves dapps through EIP-5792 and sends EIP-8141 frame transactions,
on top of `kohaku-frame-accounts`. It is an EIP-1193 provider: the binary `frame-wallet` serves
one account over HTTP JSON-RPC, so a dapp in any language can use it, and a dapp written against
viem's stock wallet actions needs no change.

```text
WALLET_KEY=0x... cargo run --release -p kohaku-frame-wallet --bin frame-wallet
```

`WALLET_KEY` is read from the environment and never printed. `RPC_URL` defaults to the ethrex
Hegota testnet, `LISTEN` to any free port on `127.0.0.1`, and with `SESSION_ACCOUNT_SALT` the
account is the `SessionAccount` the key owns at that salt rather than the key's own address. The
first line on standard output is `listening on http://<address>`.

| Method | What it does |
|---|---|
| `wallet_getCapabilities` | `atomic: supported` and `paymasterService: supported` on the node's chain |
| `wallet_sendCalls` | one batch as one frame transaction, estimated, signed and sent |
| `wallet_getCallsStatus` | EIP-5792's status, derived from the frame receipts |
| `wallet_showCallsStatus` | nothing to show; refuses an unknown id |
| `wallet_getSupportedExecutionPermissions`, `wallet_requestExecutionPermissions`, `wallet_getGrantedExecutionPermissions`, `wallet_revokeExecutionPermission` | ERC-7715, for a `SessionAccount` |
| `kohaku_getBatch`, `kohaku_getOwnerTransactions` | not standard: what the wallet recorded, for experiments that report it |
| any other `wallet_*` | refused with 4200 |
| anything else | forwarded to the node |

## EIP-5792 over frames

A batch is one transaction. The layout is `exp-frames` experiment 28's:

```text
self-paid   [VERIFY sender, scope 3] [SENDER call 0] ... [SENDER call n-1]
sponsored   [VERIFY sender, scope 2] [VERIFY payer, scope 1] [SENDER call 0] ... [post-op]
```

With `atomicRequired`, every call frame but the last carries the atomic-batch flag, so the calls
commit or roll back together. Without it the calls are independent frames, some of which may
persist while others fail: EIP-5792's status 600, which a 7702 delegate's or an ERC-4337
account's `executeBatch` cannot produce in one transaction.

Estimation is experiment 28's. ethrex simulates only a transaction whose validation prefix
approves, so the user signs a draft with 400,000 execution gas per call, the node simulates it,
and each call frame is tightened to a quarter over its use plus 5,000. The user signs again. The
simulation reports no state gas per frame, so every call keeps 379,440 of state budget: two fresh
slots and one new account.

The status is derived from the call frames' statuses, not from the receipt's `status`. ethrex
reports `0x0` whenever any frame failed, even when two of three independent calls persisted, and
a frame rolled back with its atomic batch keeps `SUCCESS`. Only the wallet, which built the batch,
knows which frames formed one. Logs come from the call frames only.

## ERC-7677 bound to frames

Sponsorship goes through a paymaster web service in ERC-7677's shape, with the same binding as
experiment 28's `binding.ts` and `paymaster.ts`, field for field (`src/binding.rs`):

| ERC-7677 | Frames binding |
|---|---|
| `entryPoint` parameter | `0x00...aa`, the frames entry point |
| user-operation parameter | the unsigned frame transaction, in `RpcFrameTx`'s JSON |
| `paymaster`, `paymasterData`, `paymasterVerificationGasLimit` | the pay frame's target, data and execution budget |
| `paymasterPostOpGasLimit` | a `DEFAULT` frame after the calls, aimed at the paymaster; 0 means none |
| *(none)* | `paymasterStateGasLimit`: the pay frame's EIP-8037 state budget |
| *(none)* | `paymasterSignatures`: the payer's entries, after the sender's |

**What it leaves out.**
- The stub is useless for estimation: the node cannot simulate a stub signature, so a sponsored
  batch costs `pm_getPaymasterStubData` and two `pm_getPaymasterData`, not ERC-7677's two calls.
- A policy refusal has no error code in ERC-7677, so the dapp sees `-32603`.
- There is no agreed JSON for a frame transaction, so `RpcFrameTx` is this binding's own.

## ERC-7715 bound to `SessionAccount`

ERC-7715 (Draft, read at `ethereum/ERCs` `48dc87a2897c`) requires ERC-4337 and ERC-7710. A
granted permission is redeemed through a delegation manager's `redeemDelegations`. Over frames
the account's own `VERIFY` is the delegation manager. The session key that `to` names signs a
frame transaction from the user's account, in the four-frame shape `SessionAccount` checks,
and anyone may send it (`src/permissions.rs`):

| ERC-7715 | Frames binding |
|---|---|
| `from` | the user's `SessionAccount` |
| `to` | the session key |
| `native-token-allowance`, `data.allowance` | the session's budget in wei, which counts value sent and each transaction's maximum fee |
| rule `expiry`, `data.timestamp` | the session's `validUntil`; required |
| rule `call-target`, `data.target`, `data.selector` | not in ERC-7715: the one contract and function the session may call; required |
| `context` | `account (20 bytes) \|\| session key (20 bytes)` |
| `delegationManager` | the account itself |
| `dependencies` | always empty: the account must already be deployed |
| redemption | `[expiry] [VERIFY account] [SENDER spend record] [SENDER calls]`, signed by the session key |
| `wallet_revokeExecutionPermission` | the owner's transaction removing the session |

The grant and the revocation are transactions the owner signs and the account pays for, sent
before the method answers.

**What it leaves out.**
- **One permission type.** Only `native-token-allowance`. The budget also pays the session's
  fees, which ERC-7715's allowance does not mention. ERC-20 and other allowances are refused.
- **A rule ERC-7715 does not define.** `SessionAccount` scopes every session to one target and
  one selector, so `call-target` is required, and any rule the account cannot enforce is refused.
  ERC-7715 says the `to` account "MUST abide by" every rule, and here only the account's code
  makes it. Adjustment is never used: the request is granted as asked or refused.
- **No ERC-7710 delegation manager, no execution modes, one call shape.** Redemption is not a call
  to a contract but a frame transaction from the account.
- **An account with no code cannot grant.** The default code checks the sender's own key only,
  so an EOA wallet answers the permission methods with 4200. A `SessionAccount` cannot deploy
  itself in a validation prefix (674 bytes), so `dependencies` has nothing to offer either.
- **A pending session transaction outlives revocation** until the owner replaces it at the same
  nonce, as `exp-frames` experiment 12 found.
- **Nobody prices a redemption's state.** The dapp sets each call frame's state budget, and the
  account charges it to the session's budget as part of the maximum cost. A redemption whose
  `approve` created an allowance slot with no state budget was still mined. The spend was
  recorded and the call failed, having burned its execution budget (`exp-frames` experiment 28,
  part 2).
- **viem 2.57.3's experimental `grantPermissions` sends `wallet_grantPermissions`**, the name in
  an earlier draft. The ERC as read names `wallet_requestExecutionPermissions`. It also writes
  `ruleTypes` in its schema and `rulesTypes` in its example. This crate answers `ruleTypes`.

## Recovering note openings from the owner's devices

`src/recovery.rs`: the keychain key that `kohaku-tornadocash-keychain` derives every note from is
split between two of the owner's devices. Each holds a uniformly random 32-byte share, and the
key is their XOR. These are the same two devices that can recover a `DeviceRecoveryAccount`.
After the loss the shares give the key back, and the keychain's own `recover` finds its notes
among a frame pool's public `Deposit` and `Withdrawal` events, which `pool_events` reads.
`root_slot` finds the EIP-8272 slot a recovered note's root was published in, so the note can be
spent.

```text
PRIVATE_KEY=0x... cargo run --release -p kohaku-frame-wallet --example device_recovery
```

A run on 2026-10-20 deposited a keychain note into `exp-frames` experiment 06's keyed pool, in
block 479022, and then dropped the key. The two shares gave it back, and the keychain found its
note among the pool's 24 events. The recovered note was withdrawn in block 479025, with no
signature and the pool as payer.

**What it leaves out.** Two shares of two: losing both devices loses the notes, as it loses the
account. Shamir's scheme, two of three, is the step up, and is not here.

## The crowd behind a statement

A proof reveals nothing beyond its statement, but a statement that fits few people names its
prover. The `disclosure` module counts, from public chain data, how many notes could make the
same statement, and words the count before the wallet proves it: under 10 "would all but name
you", under 100 "narrows you down". It covers three kinds:

- a deposit into a pool before a date (`deposits_before`, a Tornado Cash pool's `nextIndex()`
  at the last block before it);
- an unspent note worth at least T (`unspent_at_least`, balance / denomination over the ETH
  pools of at least T);
- a deposit in an association set (`AssociationSet::verify` recomputes the provider's published
  tree with circomlib's Poseidon, ported here, and checks its top against the root on chain).

It cannot count a balance over all accounts: that needs the state's account range, which an
ordinary RPC does not serve. `examples/disclosure.rs` runs all three on mainnet. At block
26,231,840 its counts equal `exp-frames` experiment 35's `results.md`, from 2,266 unspent notes
of at least 100 ETH down to 3 approved Privacy Pools deposits of at least 100 ETH.

## Tests and runs

`tests/experiment_28.rs` rebuilds the twelve batches `exp-frames` experiment 28 has as fixtures:
eight sent by its TypeScript wallet and four by this one. Each is rebuilt from what a wallet
decides, first to its signature hash and then byte for byte. The test also derives each batch's
EIP-5792 status and matches the binding JSON experiment 28 writes. `tests/permissions.rs`
rebuilds the ERC-7715 grant, revocation and redemption mined on 2026-10-20. Experiment 12's
TypeScript built the redemption.

The runs are `exp-frames`' experiment 28 (`dapp.ts` and `permissions.ts`, with `RUST_WALLET`
naming this binary). In the steady state, this wallet's four batches spent the frame gas and
limits of the TypeScript wallet's exactly. They differed in `gasUsed` only by calldata: the
users' addresses and signatures have other zero bytes.
