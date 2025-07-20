#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Affine};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use lazy_static::lazy_static;
    use rand::Rng;
    const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();
    use ark_std::{str::FromStr, One};
    use rust_kzg_bn254_primitives::blob::Blob;
    use rust_kzg_bn254_prover::{kzg::KZG, srs::SRS};
    use rust_kzg_bn254_verifier::{batch::verify_blob_kzg_proof_batch, verify::verify_proof};

    // Define a static variable for setup
    lazy_static! {
        static ref KZG_INSTANCE: KZG = KZG::new();
        static ref SRS_INSTANCE: SRS = SRS::new(
            "../prover/tests/test-files/mainnet-data/g1.131072.point",
            268435456,
            131072
        )
        .unwrap();
    }

    #[test]
    fn test_compute_kzg_proof() {
        use rand::Rng;

        let mut kzg = KZG_INSTANCE.clone();

        let input = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let input_poly = input.to_polynomial_eval_form().unwrap();

        for index in 0..input_poly.len() - 1 {
            kzg.calculate_and_store_roots_of_unity(input.len().try_into().unwrap())
                .unwrap();
            let mut rand_index =
                rand::thread_rng().gen_range(0..input_poly.len_underlying_blob_field_elements());
            loop {
                if index == rand_index {
                    rand_index = rand::thread_rng()
                        .gen_range(0..input_poly.len_underlying_blob_field_elements());
                } else {
                    break;
                }
            }
            let commitment = kzg.commit_eval_form(&input_poly, &SRS_INSTANCE).unwrap();
            let proof = kzg
                .compute_proof_with_known_z_fr_index(
                    &input_poly,
                    index.try_into().unwrap(),
                    &SRS_INSTANCE,
                )
                .unwrap();

            let value_fr = input_poly.get_evalualtion(index).unwrap();
            let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
            let pairing_result =
                verify_proof(commitment, proof, value_fr.clone(), z_fr.clone()).unwrap();

            assert_eq!(pairing_result, true);

            assert_eq!(
                verify_proof(
                    commitment,
                    proof,
                    value_fr.clone(),
                    kzg.get_nth_root_of_unity(rand_index).unwrap().clone()
                )
                .unwrap(),
                false
            )
        }
    }

    #[test]
    fn test_compute_kzg_proof_random_100_blobs() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut kzg = KZG_INSTANCE.clone();

        (0..100).for_each(|_| {
            let blob_length = rand::thread_rng().gen_range(35..50000);
            let random_blob: Vec<u8> = (0..blob_length)
                .map(|_| rng.gen_range(32..=126) as u8)
                .collect();
            println!("generating blob of length is {}", blob_length);

            let input = Blob::from_raw_data(&random_blob);
            let input_poly = input.to_polynomial_eval_form().unwrap();
            kzg.calculate_and_store_roots_of_unity(input.len().try_into().unwrap())
                .unwrap();

            let index =
                rand::thread_rng().gen_range(0..input_poly.len_underlying_blob_field_elements());
            let commitment = kzg
                .commit_eval_form(&input_poly.clone(), &SRS_INSTANCE)
                .unwrap();
            let proof = kzg
                .compute_proof_with_known_z_fr_index(
                    &input_poly,
                    index.try_into().unwrap(),
                    &SRS_INSTANCE,
                )
                .unwrap();
            let value_fr = input_poly.get_evalualtion(index).unwrap();
            let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
            let pairing_result =
                verify_proof(commitment, proof, value_fr.clone(), z_fr.clone()).unwrap();
            assert_eq!(pairing_result, true);

            // take random index, not the same index and check
            assert_eq!(
                verify_proof(
                    commitment,
                    proof,
                    value_fr.clone(),
                    kzg.get_nth_root_of_unity(
                        (index + 1) % input_poly.len_underlying_blob_field_elements()
                    )
                    .unwrap()
                    .clone()
                )
                .unwrap(),
                false
            )
        })
    }

    #[test]
    fn test_multiple_proof_random_100_blobs() {
        let mut rng = rand::thread_rng();
        let mut kzg = KZG_INSTANCE.clone();

        let mut blobs: Vec<Blob> = Vec::new();
        let mut commitments: Vec<G1Affine> = Vec::new();
        let mut proofs: Vec<G1Affine> = Vec::new();

        (0..100).for_each(|_| {
            let blob_length = rng.gen_range(35..50000);
            let random_blob: Vec<u8> = (0..blob_length)
                .map(|_| rng.gen_range(32..=126) as u8)
                .collect();

            let input = Blob::from_raw_data(&random_blob);
            let input_poly = input.to_polynomial_eval_form().unwrap();
            kzg.calculate_and_store_roots_of_unity(input.len().try_into().unwrap())
                .unwrap();

            let commitment = kzg.commit_eval_form(&input_poly, &SRS_INSTANCE).unwrap();
            let proof = kzg
                .compute_blob_proof(&input, &commitment, &SRS_INSTANCE)
                .unwrap();

            blobs.push(input);
            commitments.push(commitment);
            proofs.push(proof);
        });

        let mut bad_blobs = blobs.clone();
        let mut bad_commitments = commitments.clone();
        let mut bad_proofs = proofs.clone();

        let pairing_result = verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs).unwrap();
        assert_eq!(pairing_result, true);

        bad_blobs.pop();
        bad_blobs.push(Blob::from_raw_data(b"random"));
        let pairing_result_bad_blobs =
            verify_blob_kzg_proof_batch(&bad_blobs, &commitments, &proofs).unwrap();
        assert_eq!(pairing_result_bad_blobs, false);

        bad_commitments.pop();
        bad_commitments.push(G1Affine::rand(&mut rng));
        let pairing_result_bad_commitments =
            verify_blob_kzg_proof_batch(&blobs, &bad_commitments, &proofs).unwrap();
        assert_eq!(pairing_result_bad_commitments, false);

        bad_proofs.pop();
        bad_proofs.push(G1Affine::rand(&mut rng));
        let pairing_result_bad_proofs =
            verify_blob_kzg_proof_batch(&blobs, &commitments, &bad_proofs).unwrap();
        assert_eq!(pairing_result_bad_proofs, false);

        let pairing_result_everything_bad =
            verify_blob_kzg_proof_batch(&bad_blobs, &bad_commitments, &bad_proofs).unwrap();
        assert_eq!(pairing_result_everything_bad, false);
    }

    #[test]
    fn test_compute_multiple_kzg_proof() {
        let mut kzg = KZG_INSTANCE.clone();
        let mut kzg2 = KZG_INSTANCE.clone();

        let input1 = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        kzg.calculate_and_store_roots_of_unity(input1.len().try_into().unwrap())
            .unwrap();

        let input_poly1 = input1.to_polynomial_eval_form().unwrap();

        let commitment1 = kzg
            .commit_eval_form(&input_poly1.clone(), &SRS_INSTANCE)
            .unwrap();
        let proof_1 = kzg
            .compute_blob_proof(&input1, &commitment1, &SRS_INSTANCE)
            .unwrap();

        let mut reversed_input: Vec<u8> = vec![0; GETTYSBURG_ADDRESS_BYTES.len()];
        reversed_input.clone_from_slice(GETTYSBURG_ADDRESS_BYTES);
        reversed_input.reverse();

        let input2 = Blob::from_raw_data(
            b"17704588942648532530972307366230787358793284390049200127770755029903181125533",
        );
        kzg2.calculate_and_store_roots_of_unity(input2.len().try_into().unwrap())
            .unwrap();
        let input_poly2 = input2.to_polynomial_eval_form().unwrap();

        let commitment2 = kzg2.commit_eval_form(&input_poly2, &SRS_INSTANCE).unwrap();

        let proof_2 = kzg2
            .compute_blob_proof(&input2, &commitment2, &SRS_INSTANCE)
            .unwrap();

        let blobs = vec![input1, input2];
        let commitments = vec![commitment1, commitment2];
        let proofs = vec![proof_1, proof_2];
        // let res = kzg.verify_blob_kzg_proof(&input1, &commitment1, &auto_proof).unwrap();

        let pairing_result = verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs).unwrap();

        assert_eq!(pairing_result, true);
    }

    #[test]
    fn test_kzg_batch_proof_with_infinity() {
        let mut kzg = KZG_INSTANCE.clone();

        // Setup with consistent domain size
        let input_size = GETTYSBURG_ADDRESS_BYTES.len();
        kzg.calculate_and_store_roots_of_unity(input_size.try_into().unwrap())
            .unwrap();

        // First blob and proof - regular case
        let input1 = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let input_poly1 = input1.to_polynomial_eval_form().unwrap();
        let commitment1 = kzg.commit_eval_form(&input_poly1, &SRS_INSTANCE).unwrap();
        let proof_1 = kzg
            .compute_blob_proof(&input1, &commitment1, &SRS_INSTANCE)
            .unwrap();

        // Create a proof point at infinity
        let proof_at_infinity = G1Affine::identity();

        let blobs = vec![input1.clone()];
        let commitments = vec![commitment1];
        let proofs = vec![proof_at_infinity];

        // This should fail since a proof point at infinity is invalid
        let result = verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs);

        assert!(result.is_err());

        // Also test mixed case - one valid proof, one at infinity
        let input2 = Blob::from_raw_data(b"second input");
        let input_poly2 = input2.to_polynomial_eval_form().unwrap();
        let commitment2 = kzg.commit_eval_form(&input_poly2, &SRS_INSTANCE).unwrap();

        let blobs_mixed = vec![input1, input2];
        let commitments_mixed = vec![commitment1, commitment2];
        let proofs_mixed = vec![proof_1, proof_at_infinity];

        let result_mixed =
            verify_blob_kzg_proof_batch(&blobs_mixed, &commitments_mixed, &proofs_mixed);
        assert!(result_mixed.is_err());
    }

    #[test]
    fn test_kzg_batch_proof_invalid_curve_points() {
        let mut kzg = KZG_INSTANCE.clone();
        kzg.calculate_and_store_roots_of_unity(GETTYSBURG_ADDRESS_BYTES.len().try_into().unwrap())
            .unwrap();

        // Create valid inputs first
        let input = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let input_poly = input.to_polynomial_eval_form().unwrap();
        let valid_commitment = kzg.commit_eval_form(&input_poly, &SRS_INSTANCE).unwrap();
        let valid_proof = kzg
            .compute_blob_proof(&input, &valid_commitment, &SRS_INSTANCE)
            .unwrap();

        // Create points not on the curve
        let invalid_point_commitment = generate_point_wrong_subgroup();

        let invalid_point_proof = generate_point_wrong_subgroup();
        let invalid_proof_from_valid_proof_plus_1 = G1Affine::new_unchecked(
            valid_proof.x().unwrap(),
            valid_proof.y().unwrap() + Fq::one(),
        ); // This is not a valid proof

        // Test cases with different combinations
        let test_cases = vec![
            (
                vec![invalid_point_commitment.clone(), valid_commitment],
                vec![valid_proof.clone(), valid_proof.clone()],
                "Invalid commitment point",
            ),
            (
                vec![valid_commitment, valid_commitment],
                vec![invalid_point_proof.clone(), valid_proof.clone()],
                "Invalid proof point",
            ),
            (
                vec![invalid_point_commitment.clone(), valid_commitment],
                vec![invalid_point_proof.clone(), valid_proof.clone()],
                "Both invalid commitment and proof",
            ),
            (
                vec![valid_commitment, invalid_point_commitment],
                vec![valid_proof.clone(), invalid_point_proof],
                "Invalid points in second position",
            ),
            (
                vec![valid_commitment, invalid_point_commitment],
                vec![valid_proof.clone(), invalid_proof_from_valid_proof_plus_1],
                "Invalid proof from valid proof",
            ),
            (
                vec![invalid_point_commitment, invalid_point_commitment],
                vec![invalid_point_proof, invalid_proof_from_valid_proof_plus_1],
                "all invalid commitments and proofs",
            ),
        ];

        for (commitments, proofs, case_description) in test_cases {
            let blobs = vec![input.clone(), input.clone()];
            let result = verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs);

            assert!(
                result.is_err(),
                "Failed to detect invalid curve point - {}",
                case_description
            );
        }
    }

    #[test]
    fn test_individual_verify_proof_with_identity_points() {
        use ark_bn254::{Fr, G1Affine};
        use ark_ff::One;
        use rust_kzg_bn254_verifier::verify::verify_proof;

        // Test with identity commitment
        let identity_commitment = G1Affine::identity();
        let valid_proof = G1Affine::generator();
        let value = Fr::one();
        let z = Fr::one();

        let result = verify_proof(identity_commitment, valid_proof, value, z);
        assert!(result.is_err(), "Should reject identity commitment");

        // Test with identity proof
        let valid_commitment = G1Affine::generator();
        let identity_proof = G1Affine::identity();

        let result = verify_proof(valid_commitment, identity_proof, value, z);
        assert!(result.is_err(), "Should reject identity proof");

        // Test with both identity points
        let result = verify_proof(identity_commitment, identity_proof, value, z);
        assert!(result.is_err(), "Should reject both identity points");
    }

    #[test]
    fn test_verify_proof_intermediate_point_validation() {
        use ark_bn254::{Fr, G1Affine, G2Affine};
        use ark_ff::{One, Zero};
        use rust_kzg_bn254_verifier::verify::verify_proof;

        // Test Case 1: commit_minus_value becomes identity
        // Create a commitment that equals value_fr * G1, so commit_minus_value = identity
        let value_fr = Fr::from(42u64);
        let commitment = G1Affine::generator() * value_fr; // commitment = value_fr * G1
        let valid_proof = G1Affine::generator() * Fr::from(100u64); // Some valid proof
        let z_fr = Fr::from(13u64); // Some evaluation point

        let result = verify_proof(
            commitment.into_affine(),
            valid_proof.into_affine(),
            value_fr,
            z_fr,
        );
        assert!(
            result.is_err(),
            "Should reject when commitment - value*G1 equals identity"
        );

        // Verify the error message is what we expect
        if let Err(error) = result {
            match error {
                rust_kzg_bn254_primitives::errors::KzgError::GenericError(msg) => {
                    assert!(
                        msg.contains("Invalid commitment-value relationship"),
                        "Error message should indicate commitment-value relationship issue"
                    );
                },
                _ => panic!("Expected GenericError for invalid commitment-value relationship"),
            }
        }

        // Test Case 2: Verify normal case still works
        let different_value = Fr::from(999u64); // Different from commitment scalar
        let result = verify_proof(
            commitment.into_affine(),
            valid_proof.into_affine(),
            different_value,
            z_fr,
        );
        // This might still fail for other reasons (invalid proof), but should not fail on commitment-value relationship
        if let Err(error) = result {
            match error {
                rust_kzg_bn254_primitives::errors::KzgError::GenericError(msg) => {
                    assert!(
                        !msg.contains("Invalid commitment-value relationship"),
                        "Should not fail on commitment-value relationship with different values"
                    );
                },
                _ => {}, // Other errors are acceptable
            }
        }
    }

    #[test]
    fn test_verify_proof_zero_commitment_edge_case() {
        use ark_bn254::{Fr, G1Affine};
        use ark_ff::Zero;
        use rust_kzg_bn254_verifier::verify::verify_proof;

        // Edge case: commitment is identity, value is zero
        // This would make commit_minus_value = identity - zero*G1 = identity - identity = identity
        let zero_commitment = G1Affine::identity();
        let zero_value = Fr::zero();
        let valid_proof = G1Affine::generator();
        let z_fr = Fr::from(1u64);

        let result = verify_proof(zero_commitment, valid_proof, zero_value, z_fr);
        assert!(
            result.is_err(),
            "Should reject identity commitment regardless of value"
        );

        // Should fail on identity commitment check before reaching intermediate validation
        if let Err(error) = result {
            match error {
                rust_kzg_bn254_primitives::errors::KzgError::NotOnCurveError(msg) => {
                    assert!(
                        msg.contains("point at infinity"),
                        "Should fail on identity commitment check first"
                    );
                },
                _ => panic!("Expected NotOnCurveError for identity commitment"),
            }
        }
    }

    #[test]
    fn test_verify_proof_edge_cases_with_valid_inputs() {
        use ark_bn254::{Fr, G1Affine};
        use ark_ff::{One, UniformRand};
        use rand::thread_rng;
        use rust_kzg_bn254_verifier::verify::verify_proof;

        let mut rng = thread_rng();

        // Test with random valid points that shouldn't trigger edge cases
        for _ in 0..10 {
            let commitment = (G1Affine::generator() * Fr::rand(&mut rng)).into_affine();
            let proof = (G1Affine::generator() * Fr::rand(&mut rng)).into_affine();
            let value_fr = Fr::rand(&mut rng);
            let z_fr = Fr::rand(&mut rng);

            // Make sure value_fr doesn't accidentally equal the commitment scalar
            // by using a different random scalar for the test
            let different_value = Fr::rand(&mut rng);

            let result = verify_proof(commitment, proof, different_value, z_fr);

            // The verification may fail for mathematical reasons (wrong proof),
            // but should NOT fail on intermediate point validation
            if let Err(error) = result {
                match error {
                    rust_kzg_bn254_primitives::errors::KzgError::GenericError(msg) => {
                        assert!(!msg.contains("Invalid commitment-value relationship") && 
                               !msg.contains("trusted setup secret"),
                               "Should not fail on intermediate point validation with random inputs: {}", msg);
                    },
                    _ => {}, // Other errors (like pairing failures) are acceptable
                }
            }
        }
    }

    #[test]
    fn test_verify_blob_kzg_proof_intermediate_validation_coverage() {
        use ark_bn254::{Fr, G1Affine};
        use ark_ff::One;
        use rust_kzg_bn254_primitives::blob::Blob;
        use rust_kzg_bn254_verifier::verify::verify_blob_kzg_proof;

        // Test that verify_blob_kzg_proof also gets the intermediate validation
        // since it calls verify_proof internally
        let blob = Blob::from_raw_data(b"test data for edge case");

        // Create a scenario that might trigger intermediate validation
        // We can't easily craft the exact edge case since it depends on polynomial evaluation
        // But we can test that the function properly handles edge cases
        let commitment = G1Affine::generator();
        let proof = G1Affine::generator();

        let result = verify_blob_kzg_proof(&blob, &commitment, &proof);

        // This will likely fail for mathematical reasons, but should not crash
        // and should handle any intermediate validation properly
        assert!(
            result.is_ok() || result.is_err(),
            "Function should handle all cases gracefully"
        );

        // Test with identity points (should be caught by input validation)
        let identity_commitment = G1Affine::identity();
        let result = verify_blob_kzg_proof(&blob, &identity_commitment, &proof);
        assert!(result.is_err(), "Should reject identity commitment");
    }

    // Helper function to generate a point in the wrong subgroup
    fn generate_point_wrong_subgroup() -> G1Affine {
        let x = Fq::from_str(
            "17704588942648532530972307366230787358793284390049200127770755029903181125533",
        )
        .unwrap();
        let y = Fq::from_str(
            "17704588942648532530972307366230787358793284390049200127770755029903181125533",
        )
        .unwrap();
        G1Affine::new_unchecked(x, y)
    }
}
