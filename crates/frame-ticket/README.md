# kohaku-frame-ticket

Experimental. Blind tickets: prepaid, unlinkable payment for a frame transaction's gas, so that a
fresh sender with no ether can send without anyone who sold it the ticket knowing which
transaction is its. The testnet run is `exp-frames` experiment 36; this crate is the issuers'
side, the buyer's side and the paymaster's pay frame.

```text
buy        buyer -> paymaster        value = k * denomination           logs Bought(buyer, k)
issue      buyer -> q of n issuers   B = r * H(m), signed by the buyer  each answers x_i * B
unblind    buyer                     sigma = (1/r) * recover(answers)   = x * H(m)
spend      fresh sender -> chain     pay frame: VERIFY(PAYMENT) to the paymaster, data = ticket
```

`m` is the ticket's message, which binds one slot: the chain, the fresh sender, its nonce keys
and nonce sequence, an epoch and a salt (`ticket`). The paymaster rebuilds `m` from the
transaction it is asked to pay for, so a ticket pays for exactly one slot, and the protocol's
nonce is the ticket's spent mark: no storage is read or written.

- `blind`: the threshold blind signature, on Commonware's `commonware-cryptography` 2026.9.0
  with no change to it. Commonware's threshold signing hashes the message itself, so no issuer
  can be asked to sign a point the buyer chose. But its public API has every piece:
  `ops::hash_with_namespace` for `H(m)`, `Private::expose` for an issuer's `x_i * B`,
  `PartialSignature`'s public fields, `Variant::verify` to check an answer against an issuer's
  public share, and `threshold::recover` to interpolate. Unblinding multiplies by `1 / r`, and
  the result is the committee's ordinary `MinSig` signature, which `ops::verify_message`
  accepts.
- `issuers`: the committee. Its key comes from one round of Commonware's DKG
  (`dkg::feldman_desmedt`) among the issuers, so no one holds it whole; the round's messages pass
  in memory here. The `Ledger` is what each buyer bought and the requests answered under it.
- `ticket`: the message, the pay frame's data, and EIP-2537's encodings of G1 and G2 points.
- `paymaster`: `TicketPaymaster.yul`'s creation code (copied from the experiment, compiled by
  solc 0.8.37), a purchase frame, and `TicketSponsor`, the pay frame for
  `kohaku-frame-accounts`' builder.

## What the paymaster checks

In a `VERIFY(PAYMENT)` frame, with `epoch || salt || signature` as its data, the paymaster
rebuilds `m` from `TXPARAM`s, hashes it to G1 with RFC 9380's `BLS12381G1_XMD:SHA-256_SSWU_RO_`
suite (`expand_message_xmd` on the SHA-256 precompile, a reduction modulo `p` on `MODEXP`, and
EIP-2537's `MAP_FP_TO_G1` and `G1ADD`), and checks `e(signature, -g2) * e(H(m), key) = 1` on
EIP-2537's pairing precompile. It also requires the transaction's maximum cost to be at most the
denomination. The issuers' key is appended to its code; it reads no storage and no balance, so it
can run in a public-mempool `VERIFY` frame. `tests/ticket.rs` checks that these steps, done
outside Commonware, give Commonware's `H(m)`.

The experiment measured the check at 122,006 gas of execution, the same for every ticket. That
fits the testnet's validation budget (500,000, an ethrex node flag) and not EIP-8141's
`MAX_VERIFY_GAS` of 100,000.

## Two things a deployment has to provide

**One count of what each buyer was issued, shared by the issuers.** A blinded request carries
nothing an issuer can match to another, so an issuer that counts only its own answers cannot
tell a quorum it joined from one it did not. With `n` issuers, a quorum of `q` and `k` tickets
bought, a buyer who sends each request to a different quorum gets `n * k / q` tickets, rounded
down: with 4 issuers, a quorum of 3 and 3 bought, 4 (`Count::PerIssuer`, and the test
`issuers_who_count_alone_issue_more_tickets_than_were_bought`). The issuers have to agree on one
list of each buyer's requests and answer only the first `k` (`Count::Shared`). Here that list is
one structure in memory; between real issuers it is a log they agree on.

**A paymaster the mempool lets sponsor more than one pending transaction.** EIP-8141's public
mempool lets a non-canonical paymaster sponsor one pending transaction at a time. The experiment
sent two ticket-paid spends at once and the node refused the second ("Non-canonical paymaster
already sponsors the maximum number of pending frame transactions") until the first was mined.
A ticket paymaster serving many senders needs the standing the canonical paymaster has.

## Run

```text
cargo test -p kohaku-frame-ticket
PRIVATE_KEY=0x... RECORD=record.json \
  cargo run --release -p kohaku-frame-ticket --example blind_tickets
```

The example runs the DKG, deploys a paymaster for the committee's key, has two buyers buy three
tickets each, issues them, and spends them from six fresh senders: four one after another, in an
order shuffled away from the order of issuance, and two at once. It then sends three
transactions the paymaster must refuse. The record holds every transaction, the issuers'
transcripts and the committee's public keys; no private key and no blinding factor.

`tests/record.rs` reads the run's record back (`tests/fixtures/record.json`, copied from the
experiment): the deployed initcode is this crate's code with the committee's key, every mined
spend is rebuilt byte for byte by the builder and its ticket verifies, and every issuer's answer
checks against its share's key.

The crate is left out of CI's `wasm32-unknown-unknown` check: `blst` compiles C, and for that
target it needs clang, which CI's nix shell does not provide.

## Bound tickets (`bound`)

`exp-frames` experiment 48, and the mempool's claim-gated admission's CG-12. The ticket's message
gains the 20-byte address of a one-time key the buyer chose (152 bytes), the pay frame carries it
(188 bytes), and the transaction carries that key's secp256k1 signature over its signature hash.
`contracts/BoundTicketPaymaster.yul` (its creation code in `BoundTicketPaymaster.hex`, solc 0.8.37,
EVM version osaka, optimizer on, 200 runs) checks the pairing over the 152-byte message and
requires that entry. Its template, the code before the key and the denomination, is 1,185 bytes
with keccak256 `0x52c656815e560bb189c3fb362c9628432ca1ed6b720e239857775236c18bc1d3`.
