#[cfg(test)]
mod tests {
    use lazy_static::lazy_static;
    use rand::Rng;
    use rust_kzg_bn254_primitives::{blob::Blob, consts::MAINNET_SRS_G1_SIZE, errors::KzgError};
    use rust_kzg_bn254_prover::{kzg::KZG, srs::SRS};

    // Define a static variable for setup
    lazy_static! {
        static ref KZG_INSTANCE: KZG = KZG::new();
        static ref SRS_INSTANCE: SRS = SRS::new(
            "tests/test-files/mainnet-data/g1.131072.point",
            268435456,
            131072
        )
        .unwrap();
    }

    #[test]
    fn test_srs_setup_errors() {
        let srs = SRS::new("tests/test-files/g1.point", 3000, 3001);
        assert_eq!(
            srs,
            Err(KzgError::GenericError(
                "Number of points to load exceeds SRS order.".to_string()
            ))
        );
    }

    // This test is kept here to prevent cyclic dependency in tests.
    #[test]
    fn test_evaluate_polynomial_in_evaluation_form_random_blob_all_indexes() {
        let mut rng = rand::thread_rng();
        let mut kzg = KZG_INSTANCE.clone();
        let blob_length: u64 = rand::thread_rng().gen_range(35..40000);
        let random_blob: Vec<u8> = (0..blob_length)
            .map(|_| rng.gen_range(32..=126) as u8)
            .collect();

        let input = Blob::from_raw_data(&random_blob);
        let input_poly = input.to_polynomial_eval_form().unwrap();

        for i in 0..input_poly.len_underlying_blob_field_elements() {
            kzg.calculate_and_store_roots_of_unity(input.len().try_into().unwrap())
                .unwrap();
            let z_fr = kzg.get_nth_root_of_unity(i).unwrap();
            let claimed_y_fr =
                rust_kzg_bn254_primitives::helpers::evaluate_polynomial_in_evaluation_form(
                    &input_poly,
                    z_fr,
                )
                .unwrap();
            assert_eq!(claimed_y_fr, input_poly.evaluations()[i]);
        }
    }

    #[test]
    fn test_commit_coeff_form_and_eval_form_equivalence() {
        // Test that committing the SAME polynomial in coefficient form and evaluation form produces equivalent commitments

        let mut rng = rand::thread_rng();
        // Create a test blob with some sample data
        // Generate random blob size between 50 and 500000 bytes
        let blob_size = rng.gen_range(50..500000);

        // Generate random test data
        let test_data: Vec<u8> = (0..blob_size).map(|_| rng.gen::<u8>()).collect();
        let blob = Blob::from_raw_data(&test_data);

        // Strategy 1: Start with coefficient form, convert to evaluation form
        // This ensures we're working with the SAME polynomial in both representations
        let poly_coeff = blob.to_polynomial_coeff_form().unwrap();
        let poly_eval_from_coeff = poly_coeff.to_eval_form().unwrap();

        // Create KZG instance and setup roots of unity
        let mut kzg = KZG_INSTANCE.clone();
        kzg.calculate_and_store_roots_of_unity(blob.len().try_into().unwrap())
            .unwrap();

        // Commit the same polynomial in both forms
        let commitment_coeff = kzg.commit_coeff_form(&poly_coeff, &SRS_INSTANCE).unwrap();
        let commitment_eval = kzg
            .commit_eval_form(&poly_eval_from_coeff, &SRS_INSTANCE)
            .unwrap();

        // These should be equivalent since they represent the same polynomial
        assert_eq!(commitment_coeff, commitment_eval, 
            "Commitment from coefficient form should equal commitment from evaluation form for the SAME polynomial");
    }

    #[test]
    fn test_calculate_and_store_roots_of_unity() {
        // Test that calculate_and_store_roots_of_unity properly initializes the expanded_roots_of_unity field

        // Create a new KZG instance (should start with empty roots)
        let mut kzg = KZG::new();

        // Check that expanded_roots_of_unity is initially empty
        let roots_before = kzg.get_roots_of_unities();
        assert!(
            roots_before.is_empty(),
            "expanded_roots_of_unity should be empty when KZG is first created"
        );
        assert_eq!(
            roots_before.len(),
            0,
            "Initial roots of unity vector should have length 0"
        );

        // Test with different blob sizes to ensure the function works correctly
        let test_cases = [32, 50000, MAINNET_SRS_G1_SIZE as u64];

        for blob_length in test_cases.iter() {
            // Call calculate_and_store_roots_of_unity with test blob length
            let result = kzg.calculate_and_store_roots_of_unity(*blob_length);
            assert!(
                result.is_ok(),
                "calculate_and_store_roots_of_unity should succeed for blob length {}",
                blob_length
            );

            // Check that expanded_roots_of_unity is now populated
            let roots_after = kzg.get_roots_of_unities();
            assert!(!roots_after.is_empty(), 
                "expanded_roots_of_unity should not be empty after calling calculate_and_store_roots_of_unity with blob length {}", blob_length);
            assert!(roots_after.len() > 0, 
                "Roots of unity vector should have non-zero length after calculation for blob length {}", blob_length);
        }
    }

    #[test]
    fn test_g1_ifft_non_power_of_two_error() {
        // Test that g1_ifft returns an error when length is not a power of 2

        let kzg = KZG_INSTANCE.clone();

        // Test with a single non-power-of-2 length
        let length = 15; // Not a power of 2

        // Call g1_ifft with non-power-of-2 length and expect an error
        let result = kzg.g1_ifft(length, &SRS_INSTANCE);

        assert!(
            result.is_err(),
            "g1_ifft should return an error for non-power-of-2 length {}",
            length
        );

        // Verify the specific error type and message
        match result.unwrap_err() {
            KzgError::FFTError(msg) => {
                assert_eq!(
                    msg, "length provided is not a power of 2",
                    "Error message should match expected text"
                );
            },
            other_error => {
                panic!("Expected FFTError but got {:?}", other_error);
            },
        }
    }

    #[test]
    fn test_compute_blob_proof_invalid_commitment() {
        // Test that compute_blob_proof returns an error when commitment is not on the curve

        use ark_bn254::Fq;
        use ark_ff::One;

        let mut kzg = KZG_INSTANCE.clone();

        // Create a test blob
        let blob = Blob::from_raw_data(b"test data for invalid commitment");
        kzg.calculate_and_store_roots_of_unity(blob.len().try_into().unwrap())
            .unwrap();

        // Create an invalid G1Affine point that is not on the curve
        // Using coordinates that don't satisfy the BN254 curve equation y² = x³ + 3
        let invalid_x = Fq::one(); // x = 1
        let invalid_y = Fq::one(); // y = 1 (but 1² ≠ 1³ + 3, so not on curve)
        let invalid_commitment = ark_bn254::G1Affine::new_unchecked(invalid_x, invalid_y);

        // Verify that our invalid point is indeed not on the curve
        assert!(
            !invalid_commitment.is_on_curve(),
            "Test point should not be on the curve"
        );

        // Call compute_blob_proof with the invalid commitment and expect an error
        let result = kzg.compute_blob_proof(&blob, &invalid_commitment, &SRS_INSTANCE);

        assert!(
            result.is_err(),
            "compute_blob_proof should return an error for invalid commitment"
        );
    }
}
