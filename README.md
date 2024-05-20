# rust-kzg-bn254

## Description
This library is primarly designed to integrate with Eigen DA from the context of 4844 and Fraud Proofs.

## Warning & Disclaimer
This code is unaudited and under construction. This is experimental software and is provided on an "as is" and "as available" basis and may not work at all. It should not be used in production.

## Setup for testing
1. To test, please download the provided G1 and G2 points from [DA Resources](https://github.com/Layr-Labs/eigenda/tree/master/inabox/resources/kzg),
2. Specify these files in the `kzg.setup()` function, leave the `g2_power_of2_path` empty, and specify `srs_order` to be 3000.

## Setup to replicate Eigen DA Mainnet
1. Follow the setup instructions to download the G1 and G2 powers of 2 points from the [Operator Setup Guide](https://github.com/Layr-Labs/eigenda-operator-setup)
2. Specify the files in `kzg.setup()` function, leave the `g2_points` empty, and specify the `srs_order` per the guide.
3. Note that this is process will take a few minutes to load since it is a bit intensive.

## Quick Start
1. Check the test in `test_compute_kzg_proof` function to see the end to end usage of the library for quick start.

## Requirements
1. SRS points required are in the same format as provided by the Eigen DA.
2. Commiting is performed in lagrange format. The required IFFT is done within the function and is not required to be performed separately. 
3. For proof generation, the data is treated as evaluation of polynomial. The required (i)FFT is performed by the compute function and is not required to be performed separately.

## Details of functions
1. The `Blob` is loaded with `from_bytes_and_pad` which accepts bytes and "pads" it so that the data fits within the requirements of Eigen DA functioning. It also keeps track of the blob length after padding.
2. From the `Blob`, a polynomial can be obtained via calling the `to_polynomial()` function. This converts the Blob to Field elements, then calculates the next power of 2 from this length of field elements and appends `zero` value elements for the remaining length. 
3. The `data_setup_custom` (for testing) or `data_setup_mins` should be used to specify the number of chunks and chunk length. These parameters are used to calculate the FFT params required for FFT operations. 
4. The `commit` function takes in a `polynomial`. It is computed over `lagrange` basis by performing the (i)FFT.
5. The `compute_kzg_proof_with_roots_of_unity` takes in a `Polynomial` and an `index` at which it needs to be computed.
