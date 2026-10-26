# kohaku-frame-exit

Experimental. The owner's side of an exit that nobody's permission opens: `exp-e2e-frames` X9,
after TACEO's "Escape hatches in MPC, and who may open them" (core.taceo.io, 2026-08-03).

A committee holds the owners' notes in a vault. With every update it publishes each new note's
opening, sealed to the note's owner. If the vault's queue stalls for T blocks, the vault enters
escape mode by itself, and each owner redeems its own note with a proof made on its device, the
vault being the transaction's sender and payer.

This crate holds the owner's part. So far it has the key, the sealing and the scan. The rest
waits on the owner's decision about who knows which part of a note's secret:
- what an opening holds, and the check that it opens the note the vault holds;
- the redemption.

## The key, from the one seed

```text
opening key   K("exit/<vault>/opening/<o>")     secp256k1; P = k * G, 33 bytes compressed
recipient     K("exit/<vault>/recipient/<o>")   secp256k1; where the o-th redemption pays
```

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

- Every plaintext is `OPENING_LEN` bytes, so every message is `MESSAGE_LEN`. The length is
  provisional until the opening's contents are agreed.
- A message holds no part of `P`, and `E` is fresh each time.
- Only `P`'s holder opens it, and only under the vault and update it was sealed for.
- Which owner a message is for is therefore not in the message. Whether it is elsewhere, in the
  order of an update's openings or of its new notes, depends on the vault and the committee. They
  shuffle each update's batch.

`scan` and `latest` find an owner's openings among an update's published list, oldest first.

## Tests

`tests/sealing.rs`:
- a vector from BIP-39's public all-zero mnemonic: the keys, recipients and one exact sealed
  message (`tests/fixtures/vector.json`, written with `UPDATE_VECTOR=1`);
- only the owner opens a message, and only in its context;
- a message holds neither form of `P`, and two to one owner share nothing;
- scanning picks the owner's openings out of batches sealed to others, and finds the latest;
- `Debug` shows no secret.
