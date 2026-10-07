# kohaku-frame-kit

Experimental. Build, sign and submit EIP-8141 frame transactions (type `0x06`), as the ethrex
Hegota testnet implements them: EIP-8141 with EIP-8250 keyed nonces and EIP-8272 recent roots.
It is to frame transactions what `kohaku-userop-kit` is to ERC-4337 user operations, and it is
much smaller, because the account, the paymaster and the bundler of 4337 are all frames of one
transaction here.

- `tx`: the envelope, its RLP in both directions, the transaction hash and the signature hash.
- `gas`: intrinsic gas, the calldata floor, `max_cost` and settlement from frame receipts.
- `sign`: secp256k1 and P256 signing, with the ordering several signers need.
- `json` and `rpc` (feature `rpc`, on by default): the node's JSON shapes, simulation through
  `ethrex_simulateFrameTransaction`, submission and receipts.

The tests are offline. They re-encode 40 transactions mined on the testnet by the
`exp-frames` experiments (`tests/fixtures/chain/`) to their on-chain hashes, recover or verify
every signature over the signature hash computed here, and settle each one to its receipt's
`gasUsed`, and they check the encoder against the golden vector in ethrex's
`scripts/hegota-testnet/frametx.py`.
