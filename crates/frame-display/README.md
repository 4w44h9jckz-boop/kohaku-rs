# kohaku-frame-display

Experimental. Clear signing for EIP-8141 frame transactions: what a hardware wallet or a
simulation service shows for a type-0x06 transaction, or for the execution digest's typed data,
from the transaction, a set of descriptors and nothing else. The format and the run are
`exp-frames` experiment 38.

```text
render(tx, entry, registry, rules)     the device holds the key of signature entry `entry`
render_typed(message, registry, rules) the device was given eth_signTypedData_v4's FrameExecution
-> Review { signs, intent, lines, gaps }
```

- `render`: the frame container, EIP-8141's rules for what a signature covers, the `VERIFY`
  frames and their allowed scopes, the payer and the maximum cost, the expiry frame, atomic
  batches and nonce keys. None of these needs a descriptor.
- `descriptor`: ERC-7730 files for the contracts a `SENDER` or `DEFAULT` frame calls, read as
  they stand, with `@.from` the sender or the entry point by mode; account descriptors, bound by
  code template, for what the sender's own `VERIFY` frame does with a signature and for the calls
  the account makes to itself, ABI or packed; deployer descriptors, for a deploy frame's
  `salt || initcode`.
- `review`: the lines a device lists, each naming its source, and the gaps: what it could not
  show, why, and whether that leaves the signer blind.
- `typed`: E as `eth_signTypedData_v4` typed data, written and read back, its digest from
  alloy's EIP-712 encoder.

A `Rules` value carries what is the fork's and not a descriptor's: the EIP-8250 revision, which
decides whether nonce keys `[0]` are the account nonce, and the expiry verifier's address.

Run the experiment's renders:

```bash
cargo run -p kohaku-frame-display --example clear_signing
```
