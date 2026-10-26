# kohaku-frame-exit

Experimental. The owner's side of an exit that nobody's permission opens: `exp-e2e-frames` X9,
after TACEO's "Escape hatches in MPC, and who may open them" (core.taceo.io, 2026-08-03).

A committee holds the owners' notes in a vault. With every update it publishes each new note's
opening, sealed to the note's owner. If the vault's queue stalls for T blocks, the vault enters
escape mode by itself, and each owner redeems its own note with a proof made on its device, the
vault being the transaction's sender and payer.

This crate holds the owner's part, and the note's holder's.

**Nobody but the owner can redeem a note,** all members together included. That is the claim's
eighth condition. The note is the privacy pool's, `C = pedersen(n || s)`, under the experiment 01
circuit, unchanged:
- **The owner's secret.** The owner derives the secret `s` and gives the payer only its point
  `B(s) = P(0 || s) - P(0 || 0)`.
- **The members' nullifier.** Each of the three members picks its own windows of the nullifier
  `n` (member 0 windows 0 to 20, member 1 windows 21 to 41, member 2 windows 42 to 61).
- **Why it adds up.** Pedersen is a sum of 4-bit window terms, so
  `C = x(A(n_0) + A(n_1) + A(n_2) - 2A(0) + B(s))` with `A(x) = P(x || 0)`.
- **Who knows what.** No member knows `n`, and nobody but the owner knows `s`. That holds
  because `s` never leaves the owner's device, not because the circuit binds an owner's key.

## The key, from the one seed

```text
opening key   K("exit/<vault>/opening/<o>")     secp256k1; P = k * G, 33 bytes compressed
recipient     K("exit/<vault>/recipient/<o>")   secp256k1; where the o-th redemption pays
secret        K("exit/<vault>/secret/<j>")      its first 31 bytes: the j-th note's s
```

`note::receive` gives the owner's receiving address for a note, `(P, B(s))`. The owner hands it
to the note's current holder, who sends the intent; the owner never sends one.

`K` is `kohaku-frame-secrets`' HKDF path from the BIP-39 seed. That crate is unchanged, and these
labels are listed here, not in its `PATHS`. `P` never goes on chain: the owner's intent carries
it to the committee, sealed to the committee's key.

## The sealing

`exp-frames` experiment 33's announcement, with its own version, label and associated data:

```text
shared   = x(e * P)
view tag = keccak256(shared)[0]
key, iv  = HKDF-SHA256(shared, salt = E, info = "x9/opening"), 32 + 12 bytes
aad      = vault (20) || update number (uint64be)
message  = 0x02 || view tag || E (33, compressed) || AES-256-GCM(key, iv, plaintext, aad) || tag (16)
```

- Every plaintext is `OPENING_LEN` (48) bytes, so every message is `MESSAGE_LEN` (99).
- A message holds no part of `P`, and `E` is fresh each time.
- Only `P`'s holder opens it, and only under the vault and update it was sealed for.
- Which owner a message is for is therefore not in the message. Whether it is elsewhere, in the
  order of an update's openings or of its new notes, depends on the vault and the committee. They
  shuffle each update's batch.

`scan` and `latest` find an owner's openings among an update's published list, oldest first.

## The intent (`intent`)

`enqueue(bytes sealed)`, sent by the note's current holder. `sealed` carries `P || B(s)` to the
committee's key, `committeeKey()`, under the same scheme, with info `"x9/intent"` and AAD of the
vault and the intent's index: 116 bytes.

## The opening (`note`)

An update publishes three sealed parts, one per member, in member order: 297 bytes. Each part is
`n_j (31) || member (1) || leaf (uint32be) || update (uint64be) || 4 zero bytes`.
- `assemble` opens all three, checks them, and ORs the parts into `n`. A part fails if it has a
  wrong member, bits outside its windows, a different leaf or update, or bad padding.
- `check` confirms that `pedersen(n || s)` is the commitment the vault holds at the leaf.

Any failure is a garbage opening (`Garbage`), found the day it is published.

## The vault (`vault`)

The vault's interface as the committee's builders described it, provisional until their ABI file
lands:
- `published` and `latest_note` read every update's openings, newest first, and the owner's
  latest note with any garbage found on the way.
- `redemption` is the refund pool's withdrawal (`kohaku-frame-pool`): uniform pricing, the vault
  as sender and payer, the nullifier hash as the only nonce key, at nonce sequence 0, 1 or 2.
- `redeem` hands it to one node and awaits it on the chain. It reports `Paid`, `PaidNothing` or
  `Refused` with the node's words. `PaidNothing` means mined with `withdraw` reverted, before
  escape mode; the next sequence may try again.

`kohaku-tornadocash` gains `pedersen_point`, `pack_point`, `unpack_point`, and `Point::add` and
`neg`, so that `B(s)` and the commitment's point can be computed. `pedersen_hash` is unchanged.

## Tests

- `tests/sealing.rs`:
  - a vector from BIP-39's public all-zero mnemonic: the keys, recipients and one exact sealed
    message (`tests/fixtures/vector.json`, written with `UPDATE_VECTOR=1`);
  - only the owner opens a message, and only in its context;
  - a message holds neither form of `P`, and two to one owner share nothing;
  - scanning picks the owner's openings out of batches sealed to others, and finds the latest;
  - `Debug` shows no secret.
- `tests/notes.rs`:
  - `B(s)` matches circomlibjs's bytes;
  - the whole protocol offline: an honest committee's three parts and `B(s)` make the note's
    commitment, the owner assembles and checks it, another key sees nothing, and all of the
    members' parts without `s` do not make it;
  - every kind of garbage;
  - the members' windows partition the nullifier;
  - the redemption at each sequence: vault-sent, unsigned, keyed by the nullifier hash, over the
    right root, and refused past sequence 2.
