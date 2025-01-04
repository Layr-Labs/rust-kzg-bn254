# rust-kzg-bn254

## Description

This library offers a set of functions for generating and interacting with bn254 KZG commitments and proofs in rust, with the motivation of supporting fraud and validity proof logic in EigenDA rollup integrations.

## Warning & Disclaimer

This code is unaudited and under construction. This is experimental software and is provided on an "as is" and "as available" basis and may not work at all. It should not be used in production.

## Setup for testing

1. To test, please download the provided G1 and G2 points from [DA Resources](https://github.com/Layr-Labs/eigenda/tree/master/inabox/resources/kzg),
2. Specify these files in the `kzg.setup()` function, leave the `g2_power_of2_path` empty, and specify `srs_order` to be 3000.

## Configuring with the EigenDA KZG trusted setup

1. Follow the setup instructions to download the G1 and G2 powers of 2 points from the [Operator Setup Guide](https://github.com/Layr-Labs/eigenda-operator-setup)
2. Specify the files in `kzg.setup()` function, leave the `g2_points` empty, and specify the `srs_order` per the guide.
3. Note that this is process will take a few minutes to load since it is a bit intensive.

## Clippy
Linting can be triggered via running `cargo clippy --all --manifest-path Cargo.toml -- -D warnings`.

## Quick Start

1. Check the test in `test_compute_kzg_proof` function to see the end to end usage of the library for quick start.

## Requirements

1. SRS points required are in the same format as provided by the EigenDA.
2. Commiting is performed in lagrange format. The required IFFT is done within the function and is not required to be performed separately.
3. For proof generation, the data is treated as evaluation of polynomial. The required (i)FFT is performed by the compute function and is not required to be performed separately.

## Function Reference

### `from_bytes_and_pad()`

The `Blob` is loaded with `from_bytes_and_pad` which accepts bytes and "pads" it so that the data fits within the requirements of Eigen DA functioning. It also keeps track of the blob length after padding.

### `to_polynomial()`

From the `Blob`, a polynomial can be obtained via calling the `to_polynomial()` function. This converts the Blob to Field elements, then calculates the next power of 2 from this length of field elements and appends `zero` value elements for the remaining length.

### `data_setup_custom` and `data_setup_mins` parameters

The `data_setup_custom` (for testing) or `data_setup_mins` should be used to specify the number of chunks and chunk length. These parameters are used to calculate the FFT params required for FFT operations.

### `commit()`

The `commit` function takes in a `polynomial`. It is computed over `lagrange` basis by performing the (i)FFT depending on the `polynomial` form specified.


### `compute_kzg_proof_with_roots_of_unity()`

The `compute_kzg_proof_with_roots_of_unity` takes in a `Polynomial` and an `index` at which it needs to be computed.
