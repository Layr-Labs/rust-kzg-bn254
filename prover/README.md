# rust-kzg-bn254-prover

[![Docs](https://docs.rs/rust-kzg-bn254-prover/badge.svg)](https://docs.rs/rust-kzg-bn254-prover/latest/rust_kzg_bn254_prover/)
[![Crate](https://img.shields.io/crates/v/rust-kzg-bn254-prover.svg)](https://crates.io/crates/rust-kzg-bn254-prover)

This library offers a set of functions for generating and interacting with bn254 KZG commitments and proofs in rust, with the motivation of supporting fraud and validity proof logic in EigenDA rollup integrations.

## Configuring with the EigenDA KZG trusted setup

1. Follow the setup instructions to download the G1 and G2 powers of 2 points from the [Operator Setup Guide](https://github.com/Layr-Labs/eigenda-operator-setup)
2. Specify the files in `kzg.setup()` function, leave the `g2_points` empty, and specify the `srs_order` per the guide.
3. Note that this is process will take a few minutes to load since it is a bit intensive.

## Quick Start

See the `test_compute_kzg_proof` function in [./tests/kzg_test.rs](./tests/kzg_test.rs) for an end to end usage of the library.

Also make sure to check out the examples in our [docs](https://docs.rs/rust-kzg-bn254-prover/latest/rust_kzg_bn254_prover/).

## Setup for testing

1. To test, please download the provided G1 and G2 points from [DA Resources](https://github.com/Layr-Labs/eigenda/tree/master/inabox/resources/kzg),
2. Specify these files in the `kzg.setup()` function, leave the `g2_power_of2_path` empty, and specify `srs_order` to be 3000.

## Warning & Disclaimer

This code is unaudited and under construction. This is experimental software and is provided on an "as is" and "as available" basis and may not work at all. It should not be used in production.