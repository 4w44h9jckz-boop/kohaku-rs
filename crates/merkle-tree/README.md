# kohaku-merkle-tree

Generic N-arity Merkle tree implementation in rust.

## Benchmarks

Benchmarks were run on a Ryzen 5 3600, 32GB RAM.

| Method               | Target | Time (ms) |
| -------------------- | ------ | --------- |
| merkle_insert/100    | native | 0.056     |
| merkle_insert/10_000 | native | 6.531     |
