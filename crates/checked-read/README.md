# kohaku-checked-read

Experimental. A private read's answer, checked by the reader and signed by the server. It extends
`kohaku-ticket-read`, whose reader took the server's answers on its word. The testnet run is
`exp-frames` experiment 39.

```text
reader                                      server
------                                      ------
header of the snapshot block  <-- its own node, hashed again; never the server
GET /manifest, /hint, /top (once) ------->  snapshot, table shape, hint root, signing address;
check the hint against its root             H = D A; the trie's top
POST /read {query, ticket}        ------->  ticket checked first, as before
                                            answer = D query; signature on the statement
check the signature; decode the   <-------  {answer, signature}
bucket; find the record; walk from
the header's state root to the account
through the top and the record's branch
```

- `trie`: an account read out of the state trie, walking from a root along
  `keccak256(address)` and taking each node by its hash from whatever nodes it is given. A branch
  split between the trie's top and a record is checked as one `eth_getProof` branch is.
- `header`: a header fetched by the one who checks against it. Its RLP is rebuilt from the JSON
  fields in the Hegota testnet's order (Prague's, then EIP-7928's `blockAccessListHash` and
  EIP-7843's `slotNumber`) and must hash to the block hash the node reported.
- `table`: experiment 37's table, each record followed by the branch's lower part:
  `address (20) || delegate (20) || balance (12) || nonce (8) || n (2) || nodes (n) || zeros`.
  The nodes above `split` are the same for every reader and go into a set downloaded once.
  `split = 0` keeps the whole branch in each record.
- `statement`: what the server signs: a commitment to its snapshot block and state root, the
  table's shape, the seed of `A` and a keccak tree over the hint's rows, then the query and the
  answer. The server's identity, the one a read ticket names, is its signing address, left-padded.
- `server`: experiment 37's server, which signs every answer it gives.
- `client`: `CheckedReader`, which accepts a value only when its branch proves it, treats a key
  with no record in its bucket as unanswered rather than as an empty account, and keeps evidence
  for each answer it refuses; and `CheckedLookup`, a `LookupBackend` for `kohaku-pir-rpc`'s router.
- `evidence`: a signed wrong answer as evidence, and `judge`, the third party. To make an answer
  evidence the reader opens its query, which tells whoever holds the evidence which bucket it read.
  `judge` checks the signature, the hint rows against the hint root, and that the query is an
  encryption of one column with an error small enough that an honest server's record decodes
  exactly; then it decodes the record and compares it with the chain's account, by a branch the
  judge fetched itself. A reader cannot frame an honest server with a noisy query.

## Run

```text
cargo test -p kohaku-checked-read
PRIVATE_KEY=0x... RECORD=record.json EVIDENCE=evidence.json \
  cargo run --release -p kohaku-checked-read --example checked_read
```

`tests/checked.rs` runs it offline, on a state trie of random accounts built with `alloy-trie`
and a header committing to its root: a balance read through the router and proven, an address
the table does not hold left unanswered, two lying servers refused and judged wrong, tampered
evidence dismissed, an honest answer judged correct, and a noisy query dismissed.
`tests/vectors.rs` pins the public matrix that the TypeScript third party in `exp-frames`
computes the same way.

The example buys the tickets on the Hegota testnet, builds the table from the testnet's accounts
and their branches at a snapshot block, runs two honest servers and two lying ones, reads through
the router, has a third party judge the evidence from what it fetches itself, and measures what
the branch costs.

The node serves `eth_getProof` for about the last 128 blocks; older blocks come back with the
values and an empty branch. So a table is built at a recent block, and a third party judges
within that window or with a node that keeps older state.

The crate is left out of CI's `wasm32-unknown-unknown` check: its server needs a socket.
