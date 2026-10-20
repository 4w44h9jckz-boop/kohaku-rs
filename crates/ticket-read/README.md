# kohaku-ticket-read

Experimental. Private reads of account state, paid with blind tickets. A reader buys tickets in
public, from the same committee and in the same way as a private sender (`kohaku-frame-ticket`),
and spends one per read at a server. The server checks the ticket, then answers a PIR query
about a table of accounts. It learns neither who reads nor what. The testnet run is `exp-frames`
experiment 37.

```text
reader                                      server
------                                      ------
GET /manifest, GET /hint (once)   ------->  table shape, seed of A, committee key; H = D A
POST /read {query, ticket}        ------->  ticket: committee's signature? serial unspent?
                                            only then: answer = D query (one pass over D)
decode with the hint; find the    <-------  {answer}
record in its bucket
```

- `pir`: single-server PIR in the style of SimplePIR (Henzinger, Hong, Corrigan-Gibbs,
  Meiklejohn, Vaikuntanathan, USENIX Security 2023), with its parameters: LWE dimension 1024,
  modulus 2^32, error width 6.4, one byte per entry. It is this experiment's implementation,
  not an audited one.
- `table`: the account table, as `kohaku-pir-rpc` decodes an account (`delegate || balance (12)
  || nonce (8)`), in buckets placed by `keccak256(salt || address)`. A reader fetches its key's
  whole bucket, so the server learns neither the key nor the bucket.
- `ticket`: the read ticket. It is the committee's `MinSig` signature on `server || serial`
  under the namespace `kohaku-read-ticket-v1`. Issuance is the gas ticket's, under the same key:
  the issuers see a blinded point either way, so they cannot tell a read ticket from a gas
  ticket. The namespace keeps either from paying for the other.
- `server`: the read server (axum). It checks the ticket and its own spent set before any work,
  and logs what it saw of each request: the serial, the verdict, the time of each step, the
  sizes.
- `client`: the `Reader`, and `TicketLookup`, a `LookupBackend` for `kohaku-pir-rpc`'s router.
  `kohaku-pir-rpc` is upstream kohaku-rs's, from branch `experiments/pir-v1` at `6dc83a4`, a git
  dependency. With `TicketLookup` behind it, the router answers `eth_getBalance`,
  `eth_getTransactionCount` and `eth_getCode` by private reads, one ticket each.

On that branch, `kohaku-privacy-rpc`'s `TorPirLookup` posts the keys themselves to the PIR
server over Tor, and leaves the PIR scheme to a body codec to come. `TicketLookup` is such a
codec plus a ticket, without the Tor underlay.

## Run

```text
cargo test -p kohaku-ticket-read
PRIVATE_KEY=0x... RECORD=record.json \
  cargo run --release -p kohaku-ticket-read --example ticket_read
```

`tests/read.rs` runs it offline. A committee issues read tickets, a server on a local port
answers for a table of random accounts, and the router reads a balance through `TicketLookup`.
The read after it, with no ticket left, is not sent. A spent ticket and a ticket for another
server are refused before any work, and the server's log holds no address.

The example buys the tickets on the Hegota testnet, builds the table from the testnet's
accounts at a snapshot block, reads through the router, and measures the server's time per
answer beside the time to check a ticket.

The crate is left out of CI's `wasm32-unknown-unknown` check: its server needs a socket.
