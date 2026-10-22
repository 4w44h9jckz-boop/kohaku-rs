# kohaku-fhe-input

Experimental. A TFHE input's proof of knowledge, made and verified on BLS12-381, and the gas a
`VERIFY` frame would have to pay to check it. The record is `exp-frames` experiment 41.

Zama's `tfhe-zk-pok` is used unmodified, pinned at tfhe-rs commit
`0a43e3cda269a1ef13690c99f2ce06b56bd9e43e` (licence BSD-3-Clause-Clear, which grants no patent
rights). tfhe-rs fixes the proof's curve to BLS12-446, which the EVM cannot pair; `tfhe-zk-pok`
itself is generic over its `Curve` and ships BLS12-381, the curve EIP-2537 prices.

- `run`: a CRS, an encryption and a proof at tfhe-rs's parameters for compact public-key
  encryption with proofs (`PARAM_PKE_..._TUNIFORM_2M128_ZKV2`: dimension 2048, noise
  `TUniform(17)`, native modulus, 2 message bits, 2 carry bits and a padding bit), verified in both
  pairing modes, and refused against a ciphertext changed after proving. The encryption is
  adapted from `tfhe-zk-pok`'s own test case, with attribution: tfhe-rs's encryption keeps its
  randomness private, so a proof on another curve cannot be made from tfhe-rs's ciphertext without
  a change to tfhe-rs.
- `floor`: what any EVM verifier of the unmodified proof must spend, in the cheaper of its two
  modes:
  - a 128-point G2 MSM whose scalars are Fiat-Shamir challenges, 1,509,120 gas by EIP-2537;
  - a pairing check of eight pairs with eight different G2 points, 298,500 gas;
  - the Fiat-Shamir transcript: at least the first hash's input (the key and the ciphertext,
    49,160 bytes for one block) and the 525,056 bytes squeezed for the matrix `R`, 4,223 Keccak-f
    permutations, each at least 504 gas, since χ needs at least seven 256-bit `AND`s or `OR`s in
    each of 24 rounds.

  For one block the floor is 3,936,012 gas: 7.9 times the testnet's 500,000 for `VERIFY`, and 39
  times EIP-8141's 100,000.

## Run

```text
cargo test --release -p kohaku-fhe-input -- --include-ignored
RECORD=measure.json cargo run --release -p kohaku-fhe-input --example measure
```

The crate is left out of CI's `wasm32-unknown-unknown` check: `tfhe-zk-pok` uses threads.
