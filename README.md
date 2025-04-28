# rust-kzg-bn254

## Description

This library offers a set of functions for generating and interacting with bn254 KZG commitments and proofs in rust, with the motivation of supporting fraud and validity proof logic in EigenDA rollup integrations.

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

### Building and Benchmark

```bash
# Build all crates
cargo build

# Run benchmarks
cargo bench
```
### Compatibility
1. The project is compatible with Rust 1.75 or later

### Downstream Dependencies
1. Arbitrum Nitro uses rust 1.78
2. RiscZero ZKVM uses [1.85](https://github.com/risc0/risc0/blob/545e967bcf4fc28276e02181915febe12a1a9880/rust-toolchain.toml#L2)
3. SP1 ZKVM uses [1.79](https://github.com/succinctlabs/sp1/blob/81757da015939d8a851d909e8c3df14bdc3b030d/Cargo.toml#L5)


### Notes on testing
If you encounter issue running tests and it fails with the following error:
```
error: package `half v2.5.0` cannot be built because it requires rustc 1.81 or newer, while the currently active rustc version is 1.75.0
```
then run `cargo update half --precise 2.4.1` to downgrade this transitive dependency to a lower version that works with our MSRV.
This issue can be permanently solved when [this rust RFC](https://rust-lang.github.io/rfcs/3537-msrv-resolver.html) is implemented.

## Crates Releases

Releasing a crate is done by creating a PR (see this [example](https://github.com/Layr-Labs/rust-kzg-bn254/pull/49)) that bumps the version in `Cargo.toml` and then [manually dispatching](https://github.com/Layr-Labs/rust-kzg-bn254/actions/workflows/crates-release-prod.yml) the [crates-release-prod.yml](./.github/workflows/crates-release-prod.yml) workflow. This will publish the new version to crates.io.

```bash

## Warning & Disclaimer

This code is unaudited and under construction. This is experimental software and is provided on an "as is" and "as available" basis. It may not work as expected and should not be used in production environments.
