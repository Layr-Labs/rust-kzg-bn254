#[cfg(test)]
mod tests {
    use ark_bn254::{Fr, G1Affine};
    use ark_ff::UniformRand;
    use ark_serialize::CanonicalSerialize;
    use rust_kzg_bn254_primitives::{
        blob::Blob,
        consts::{
            BYTES_PER_FIELD_ELEMENT, FIAT_SHAMIR_PROTOCOL_DOMAIN, MAINNET_SRS_G1_SIZE,
            SIZE_OF_G1_AFFINE_COMPRESSED,
        },
        helpers::{compute_challenge, hash_to_field_element, usize_to_be_bytes},
    };

    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn test_compute_challenge_basic_functionality() {
        let mut rng = ark_std::test_rng();

        // Test with a simple blob
        let test_data = b"hello world test data for challenge";
        let blob = Blob::from_raw_data(test_data);
        let commitment = G1Affine::rand(&mut rng);

        let result = compute_challenge(&blob, &commitment);
        assert!(result.is_ok(), "Basic compute_challenge should succeed");

        let challenge = result.unwrap();
        // Verify the result is a valid field element (should not be zero for this input)
        assert_ne!(
            challenge,
            Fr::from(0u64),
            "Challenge should not be zero for non-trivial input"
        );
    }

    #[test]
    fn test_compute_challenge_deterministic() {
        let mut rng = ark_std::test_rng();

        // Same inputs should always produce the same challenge
        let test_data = b"deterministic test data";
        let blob = Blob::from_raw_data(test_data);
        let commitment = G1Affine::rand(&mut rng);

        let challenge1 = compute_challenge(&blob, &commitment).unwrap();
        let challenge2 = compute_challenge(&blob, &commitment).unwrap();
        let challenge3 = compute_challenge(&blob, &commitment).unwrap();

        assert_eq!(challenge1, challenge2, "Challenges should be deterministic");
        assert_eq!(challenge2, challenge3, "Challenges should be deterministic");
    }

    #[test]
    fn test_compute_challenge_different_blobs() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);

        // Different blob data should produce different challenges
        let blob1 = Blob::from_raw_data(b"first blob data");
        let blob2 = Blob::from_raw_data(b"second blob data");
        let blob3 = Blob::from_raw_data(b"first blob data with more content");

        let challenge1 = compute_challenge(&blob1, &commitment).unwrap();
        let challenge2 = compute_challenge(&blob2, &commitment).unwrap();
        let challenge3 = compute_challenge(&blob3, &commitment).unwrap();

        assert_ne!(
            challenge1, challenge2,
            "Different blob content should produce different challenges"
        );
        assert_ne!(
            challenge1, challenge3,
            "Different blob sizes should produce different challenges"
        );
        assert_ne!(
            challenge2, challenge3,
            "Different blobs should produce different challenges"
        );
    }

    #[test]
    fn test_compute_challenge_different_commitments() {
        let mut rng = ark_std::test_rng();

        // Same blob with different commitments should produce different challenges
        let blob = Blob::from_raw_data(b"same blob data for all tests");
        let commitment1 = G1Affine::rand(&mut rng);
        let commitment2 = G1Affine::rand(&mut rng);
        let commitment3 = G1Affine::rand(&mut rng);

        let challenge1 = compute_challenge(&blob, &commitment1).unwrap();
        let challenge2 = compute_challenge(&blob, &commitment2).unwrap();
        let challenge3 = compute_challenge(&blob, &commitment3).unwrap();

        assert_ne!(
            challenge1, challenge2,
            "Different commitments should produce different challenges"
        );
        assert_ne!(
            challenge1, challenge3,
            "Different commitments should produce different challenges"
        );
        assert_ne!(
            challenge2, challenge3,
            "Different commitments should produce different challenges"
        );
    }

    #[test]
    fn test_compute_challenge_empty_blob() {
        let mut rng = ark_std::test_rng();

        // Test with empty blob
        let empty_blob = Blob::from_raw_data(&[]);
        let commitment = G1Affine::rand(&mut rng);

        let result = compute_challenge(&empty_blob, &commitment);
        assert!(
            result.is_ok(),
            "Empty blob should still produce a valid challenge"
        );

        let challenge = result.unwrap();
        // Empty blob should still produce a valid, non-zero challenge due to domain separator and commitment
        assert_ne!(
            challenge,
            Fr::from(0u64),
            "Empty blob challenge should not be zero"
        );
    }

    #[test]
    fn test_compute_challenge_various_blob_sizes() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);

        // Test with various blob sizes
        let test_cases = [
            vec![42u8; 1],     // 1 byte
            vec![42u8; 31],    // 31 bytes (one field element worth after padding)
            vec![42u8; 32],    // 32 bytes
            vec![42u8; 63],    // 63 bytes
            vec![42u8; 100],   // 100 bytes
            vec![42u8; 1000],  // 1KB
            vec![42u8; 10000], // 10KB
        ];

        let mut challenges = Vec::new();

        for (i, test_data) in test_cases.iter().enumerate() {
            let blob = Blob::from_raw_data(test_data);
            let result = compute_challenge(&blob, &commitment);
            assert!(
                result.is_ok(),
                "Challenge computation should succeed for test case {}",
                i
            );

            let challenge = result.unwrap();
            challenges.push(challenge);
        }

        // All challenges should be different
        for i in 0..challenges.len() {
            for j in i + 1..challenges.len() {
                assert_ne!(
                    challenges[i],
                    challenges[j],
                    "Different blob sizes should produce different challenges (size {} vs {})",
                    test_cases[i].len(),
                    test_cases[j].len()
                );
            }
        }
    }

    #[test]
    fn test_compute_challenge_with_identity_point() {
        // Test with the identity point (point at infinity)
        // The identity point should be rejected as an invalid commitment for security reasons
        let blob = Blob::from_raw_data(b"test with identity point");
        let identity_commitment = G1Affine::identity(); // Point at infinity

        let result = compute_challenge(&blob, &identity_commitment);
        assert!(
            result.is_err(),
            "Identity point should be rejected as invalid commitment"
        );

        // Verify the specific error type
        match result.unwrap_err() {
            rust_kzg_bn254_primitives::errors::KzgError::GenericError(msg) => {
                assert_eq!(
                    msg, "Commitment is not valid",
                    "Should reject identity point with proper error message"
                );
            },
            _ => panic!("Should return GenericError for identity point"),
        }
    }

    #[test]
    fn test_compute_challenge_invalid_commitment_validation() {
        let blob = Blob::from_raw_data(b"test with various invalid commitments");

        // Test 1: Identity point (already covered above, but included for completeness)
        let identity_point = G1Affine::identity();
        let result1 = compute_challenge(&blob, &identity_point);
        assert!(result1.is_err(), "Identity point should be rejected");

        // Test 2: Valid point should work (sanity check)
        let mut rng = ark_std::test_rng();
        let valid_commitment = G1Affine::rand(&mut rng);
        let result2 = compute_challenge(&blob, &valid_commitment);
        assert!(result2.is_ok(), "Valid commitment should work");

        // Test 3: Verify that the validation catches the right conditions
        // (The function checks: is_on_curve, is_in_correct_subgroup, and not is_zero)
        // We can't easily construct invalid points due to arkworks safety,
        // but we can verify the identity case which should be rejected
        assert!(identity_point.is_on_curve(), "Identity should be on curve");
        assert!(
            identity_point.is_in_correct_subgroup_assuming_on_curve(),
            "Identity should be in correct subgroup"
        );
        assert_eq!(
            identity_point,
            G1Affine::identity(),
            "Identity point should equal G1Affine::identity()"
        );
    }

    #[test]
    fn test_compute_challenge_same_content_different_format() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);

        // Test that the challenge depends on the actual blob format, not just content
        let data1 = b"test data";
        let mut data2 = Vec::new();
        data2.extend_from_slice(b"test");
        data2.extend_from_slice(b" data");

        let blob1 = Blob::from_raw_data(data1);
        let blob2 = Blob::from_raw_data(&data2);

        let challenge1 = compute_challenge(&blob1, &commitment).unwrap();
        let challenge2 = compute_challenge(&blob2, &commitment).unwrap();

        // Should be the same since the underlying data is identical
        assert_eq!(
            challenge1, challenge2,
            "Same data should produce same challenge regardless of construction"
        );
    }

    #[test]
    fn test_compute_challenge_boundary_conditions() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);

        // Test with data that exactly fills field element boundaries
        let exactly_32_bytes = vec![0x01u8; 32];
        let exactly_64_bytes = vec![0x02u8; 64];
        let exactly_96_bytes = vec![0x03u8; 96];

        let blob32 = Blob::from_raw_data(&exactly_32_bytes);
        let blob64 = Blob::from_raw_data(&exactly_64_bytes);
        let blob96 = Blob::from_raw_data(&exactly_96_bytes);

        let challenge32 = compute_challenge(&blob32, &commitment).unwrap();
        let challenge64 = compute_challenge(&blob64, &commitment).unwrap();
        let challenge96 = compute_challenge(&blob96, &commitment).unwrap();

        assert_ne!(
            challenge32, challenge64,
            "Different sized blobs should produce different challenges"
        );
        assert_ne!(
            challenge64, challenge96,
            "Different sized blobs should produce different challenges"
        );
        assert_ne!(
            challenge32, challenge96,
            "Different sized blobs should produce different challenges"
        );
    }

    #[test]
    fn test_compute_challenge_domain_separation() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);
        let blob = Blob::from_raw_data(b"test data for domain separation");

        // Compute the challenge normally
        let normal_challenge = compute_challenge(&blob, &commitment).unwrap();

        // Manually construct what the hash input should look like
        let blob_poly = blob.to_polynomial_eval_form().unwrap();
        let mut expected_input = Vec::new();

        // Domain separator
        expected_input.extend_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN);

        // Number of field elements (8 bytes, big-endian)
        let num_elements = blob_poly.len();
        let num_elements_bytes = usize_to_be_bytes(num_elements);
        expected_input.extend_from_slice(&num_elements_bytes);

        // Blob data
        let blob_data = rust_kzg_bn254_primitives::helpers::to_byte_array(
            blob_poly.evaluations(),
            blob_poly.len() * BYTES_PER_FIELD_ELEMENT,
        );
        expected_input.extend_from_slice(&blob_data);

        // Commitment bytes
        let mut commitment_bytes = Vec::new();
        commitment
            .serialize_compressed(&mut commitment_bytes)
            .unwrap();
        expected_input.extend_from_slice(&commitment_bytes);

        // Hash manually and compare
        let manual_challenge = hash_to_field_element(&expected_input);

        assert_eq!(
            normal_challenge, manual_challenge,
            "Manual challenge construction should match function output"
        );
    }

    #[test]
    fn test_compute_challenge_large_blob() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);

        // Test with a large blob (but not too large to avoid test timeouts)
        let large_data = vec![0x42u8; 100_000]; // 100KB
        let large_blob = Blob::from_raw_data(&large_data);

        let result = compute_challenge(&large_blob, &commitment);
        assert!(
            result.is_ok(),
            "Large blob should not cause compute_challenge to fail"
        );

        let challenge = result.unwrap();
        assert_ne!(
            challenge,
            Fr::from(0u64),
            "Large blob challenge should not be zero"
        );
    }

    #[test]
    fn test_compute_challenge_buffer_size_calculation() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);

        // Test that the buffer size calculation is correct by verifying internal consistency
        let test_data = b"buffer size test data";
        let blob = Blob::from_raw_data(test_data);
        let blob_poly = blob.to_polynomial_eval_form().unwrap();

        // Calculate expected size manually
        let expected_size = FIAT_SHAMIR_PROTOCOL_DOMAIN.len()
            + 8  // size of usize in bytes
            + (blob_poly.len() * BYTES_PER_FIELD_ELEMENT)
            + SIZE_OF_G1_AFFINE_COMPRESSED;

        // The function should not panic due to buffer size issues
        let result = compute_challenge(&blob, &commitment);
        assert!(result.is_ok(), "Buffer size calculation should be correct");

        // Verify our size calculation matches what the function expects
        // (This is more of a sanity check for our understanding)
        assert!(expected_size > 0, "Expected size should be positive");
        assert!(
            expected_size < 1_000_000,
            "Expected size should be reasonable"
        );
    }

    #[test]
    fn test_compute_challenge_consistent_with_hash_function() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);
        let blob = Blob::from_raw_data(b"hash consistency test");

        // Compute challenge twice
        let challenge1 = compute_challenge(&blob, &commitment).unwrap();
        let challenge2 = compute_challenge(&blob, &commitment).unwrap();

        // Should be identical (testing hash function determinism)
        assert_eq!(
            challenge1, challenge2,
            "Hash function should be deterministic"
        );

        // Test that even tiny changes produce completely different results
        let slightly_different_blob = Blob::from_raw_data(b"hash consistency tesT"); // Changed last char
        let different_challenge = compute_challenge(&slightly_different_blob, &commitment).unwrap();

        assert_ne!(
            challenge1, different_challenge,
            "Small input changes should produce very different challenges (avalanche effect)"
        );
    }

    #[test]
    fn test_compute_challenge_oversized_blob_error() {
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);

        // Create a blob that's too large for the SRS
        // MAINNET_SRS_G1_SIZE is 131072, so we need more field elements than that
        // Each field element is 32 bytes, so we need more than 131072 * 32 bytes of data
        let oversized_data_size = (MAINNET_SRS_G1_SIZE + 1) * BYTES_PER_FIELD_ELEMENT;
        let oversized_data = vec![0x42u8; oversized_data_size];
        let oversized_blob = Blob::from_raw_data(&oversized_data);

        // This should fail when converting to polynomial eval form
        let result = compute_challenge(&oversized_blob, &commitment);
        assert!(
            result.is_err(),
            "Oversized blob should cause compute_challenge to fail"
        );

        // Verify the specific error type
        match result.unwrap_err() {
            rust_kzg_bn254_primitives::errors::KzgError::GenericError(msg) => {
                assert_eq!(
                    msg, "Input size exceeds maximum polynomial size",
                    "Should fail with oversized polynomial error"
                );
            },
            _ => panic!("Should return GenericError for oversized polynomial"),
        }
    }

    #[test]
    fn test_compute_challenge_error_propagation() {
        // Test that errors from underlying functions are properly propagated
        let mut rng = ark_std::test_rng();
        let commitment = G1Affine::rand(&mut rng);

        // Test 1: Verify that valid blobs still work (sanity check)
        let valid_blob = Blob::from_raw_data(b"valid test data");
        let result = compute_challenge(&valid_blob, &commitment);
        assert!(result.is_ok(), "Valid blob should work");

        // Test 2: Edge case - try to create a blob that's exactly at the size limit
        let max_valid_size = MAINNET_SRS_G1_SIZE * BYTES_PER_FIELD_ELEMENT;
        let max_valid_data = vec![0x01u8; max_valid_size];
        let max_valid_blob = Blob::from_raw_data(&max_valid_data);

        let max_result = compute_challenge(&max_valid_blob, &commitment);
        // This might succeed or fail depending on padding, but it shouldn't panic
        match max_result {
            Ok(_) => {
                // If it succeeds, that's fine
            },
            Err(rust_kzg_bn254_primitives::errors::KzgError::GenericError(msg)) => {
                // If it fails with oversized error, that's also fine
                assert!(
                    msg.contains("Input size exceeds maximum polynomial size")
                        || msg.contains("SRS"),
                    "Should fail with size-related error"
                );
            },
            Err(other) => {
                panic!("Unexpected error type: {:?}", other);
            },
        }
    }

    #[test]
    fn test_compute_challenge_stress_test() {
        let mut rng = ark_std::test_rng();

        // Test with many different blob/commitment combinations to ensure robustness
        for i in 0..50 {
            let test_data = vec![i as u8; (i + 1) * 100]; // Variable sized data
            let blob = Blob::from_raw_data(&test_data);
            let commitment = G1Affine::rand(&mut rng);

            let result = compute_challenge(&blob, &commitment);
            assert!(result.is_ok(), "Stress test iteration {} should succeed", i);

            let challenge = result.unwrap();
            // Each challenge should be different (with extremely high probability)
            // We'll just check that we get valid field elements
            assert_ne!(
                challenge,
                Fr::from(0u64),
                "Challenge {} should not be zero",
                i
            );
        }
    }
}
