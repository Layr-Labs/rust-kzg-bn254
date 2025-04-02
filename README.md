# rust-kzg-bn254

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust implementation of KZG polynomial commitments using the BN254 elliptic curve, designed for the Ethereum ecosystem and EigenDA rollup integrations.

## Overview

The Kate-Zaverucha-Goldberg (KZG) polynomial commitment scheme allows for efficient proofs that a specific value exists in a polynomial at a given point, without revealing the entire polynomial. This implementation specifically targets the BN254 elliptic curve pairing, which is widely used in various blockchain applications.

## Crates

This repository is organized as a Rust workspace with three main crates:

### [rust-kzg-bn254-primitives](./primitives)

[![Docs](https://docs.rs/rust-kzg-bn254-primitives/badge.svg)](https://docs.rs/rust-kzg-bn254-primitives/latest/rust_kzg_bn254_primitives/)
[![Crate](https://img.shields.io/crates/v/rust-kzg-bn254-primitives.svg)](https://crates.io/crates/rust-kzg-bn254-primitives)

Provides the fundamental data structures and operations:
- `Blob`: Data representation with conversion methods
- `Polynomial`: Support for both evaluation and coefficient forms
- Various arithmetic and helper functions

### [rust-kzg-bn254-prover](./prover)

[![Docs](https://docs.rs/rust-kzg-bn254-prover/badge.svg)](https://docs.rs/rust-kzg-bn254-prover/latest/rust_kzg_bn254_prover/)
[![Crate](https://img.shields.io/crates/v/rust-kzg-bn254-prover.svg)](https://crates.io/crates/rust-kzg-bn254-prover)

Implements KZG commitment and proof generation:
- `KZG`: Main struct for creating commitments and generating proofs
- `SRS`: Structured Reference String handling
- Optimized parallel FFT implementations

### [rust-kzg-bn254-verifier](./verifier)

[![Docs](https://docs.rs/rust-kzg-bn254-verifier/badge.svg)](https://docs.rs/rust-kzg-bn254-verifier/latest/rust_kzg_bn254_verifier/)
[![Crate](https://img.shields.io/crates/v/rust-kzg-bn254-verifier.svg)](https://crates.io/crates/rust-kzg-bn254-verifier)

Provides verification functions:
- Single proof verification
- Batch verification for improved efficiency

## Getting Started

For a complete end-to-end example, see the `test_compute_kzg_proof` function in [prover/tests/kzg_test.rs](./prover/tests/kzg_test.rs).

### EigenDA Integration

To configure with the EigenDA KZG trusted setup:

1. Download the G1 and G2 points from the [Operator Setup Guide](https://github.com/Layr-Labs/eigenda-operator-setup)
2. Specify the files in `kzg.setup()` function as described in the [prover documentation](./prover/README.md)

## Development

### Requirements

- Rust 1.75 or later

### Building and Testing

```bash
# Build all crates
cargo build

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Warning & Disclaimer

This code is unaudited and under construction. This is experimental software and is provided on an "as is" and "as available" basis. It may not work as expected and should not be used in production environments.

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.