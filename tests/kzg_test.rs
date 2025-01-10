#[cfg(test)]
mod tests {
    use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
    use ark_ec::AffineRepr;
    use ark_ff::{BigInt, PrimeField, UniformRand};
    use lazy_static::lazy_static;
    use rand::Rng;
    use rust_kzg_bn254::{
        blob::Blob, consts::PRIMITIVE_ROOTS_OF_UNITY, errors::KzgError, kzg::KZG,
        polynomial::PolynomialCoeffForm,
    };
    use std::{env, fs::File, io::BufReader};
    const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();
    use ark_std::{str::FromStr, One};

    // Function to determine the setup based on an environment variable
    fn determine_setup() -> KZG {
        match env::var("KZG_ENV") {
            Ok(val) if val == "mainnet-data" => KZG::setup(
                "tests/test-files/mainnet-data/g1.131072.point",
                "",
                "tests/test-files/mainnet-data/g2.point.powerOf2",
                268435456,
                131072,
            )
            .unwrap(),
            _ => KZG::setup(
                "tests/test-files/g1.point",
                "tests/test-files/g2.point",
                "tests/test-files/g2.point.powerOf2",
                3000,
                3000,
            )
            .unwrap(),
        }
    }

    // Define a static variable for setup
    lazy_static! {
        static ref KZG_INSTANCE: KZG = determine_setup();
        static ref KZG_3000: KZG = KZG::setup(
            "tests/test-files/g1.point",
            "tests/test-files/g2.point",
            "tests/test-files/g2.point.powerOf2",
            3000,
            3000,
        )
        .unwrap();
    }

    #[test]
    fn test_commit_errors() {
        let mut coeffs = vec![];
        for _ in 0..4000 {
            coeffs.push(Fr::one());
        }

        let polynomial = PolynomialCoeffForm::new(coeffs);
        let result = KZG_3000.commit_coeff_form(&polynomial);
        assert_eq!(
            result,
            Err(KzgError::SerializationError(
                "polynomial length is not correct".to_string()
            ))
        );
    }

    #[test]
    fn test_kzg_setup_errors() {
        let kzg1 = KZG::setup("tests/test-files/g1.point", "", "", 3000, 3000);
        assert_eq!(
            kzg1,
            Err(KzgError::GenericError(
                "both g2 point files are empty, need the proper file specified".to_string()
            ))
        );

        let mut kzg2 = KZG::setup(
            "tests/test-files/g1.point",
            "tests/test-files/g2.point",
            "tests/test-files/g2.point.powerOf2",
            2,
            2,
        )
        .unwrap();

        let result = kzg2.data_setup_mins(4, 4);
        assert_eq!(
            result,
            Err(KzgError::SerializationError(
                "the supplied encoding parameters are not valid with respect to the SRS."
                    .to_string()
            ))
        );

        let kzg3 = KZG::setup(
            "tests/test-files/g1.point",
            "tests/test-files/g2.point",
            "tests/test-files/g2.point.powerOf2",
            3000,
            3001,
        );
        assert_eq!(
            kzg3,
            Err(KzgError::GenericError(
                "number of points to load is more than the srs order".to_string()
            ))
        );
    }

    #[test]
    fn test_g2_power_of_2_readin() {
        use ark_bn254::{Fq, Fq2, G2Projective};
        use rust_kzg_bn254::helpers::is_on_curve_g2;
        use std::io::BufRead;

        let kzg = KZG::setup(
            "tests/test-files/g1.point",
            "",
            "tests/test-files/g2.point.powerOf2",
            3000,
            3000,
        )
        .unwrap();

        assert_eq!(kzg.get_g2_points().len(), 28);

        let file = File::open("tests/test-files/g2.powerOf2.string.txt").unwrap();
        let reader = BufReader::new(file);
        let kzg_g2_points = kzg.get_g2_points();

        // Iterate over each line in the file
        for (i, line_result) in reader.lines().enumerate() {
            let mut line = line_result.unwrap(); // Retrieve the line, handling potential I/O errors
            line = line.trim_end().to_string();

            let parts: Vec<&str> = line.split(',').collect();

            let x_c0 = Fq::from_str(parts[0]).expect("should be fine");
            let x_c1 = Fq::from_str(parts[1]).expect("should be fine");

            let y_c0 = Fq::from_str(parts[2]).expect("should be fine");
            let y_c1 = Fq::from_str(parts[3]).expect("should be fine");

            let x = Fq2::new(x_c0, x_c1);
            let y = Fq2::new(y_c0, y_c1);
            let point = G2Affine::new_unchecked(x, y);
            assert_eq!(is_on_curve_g2(&G2Projective::from(point)), true);
            assert_eq!(point, kzg_g2_points[i]);
        }
    }

    #[test]
    fn test_roots_of_unity_setup() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        let mut kzg_clone1: KZG = KZG_3000.clone();
        let mut kzg_clone2: KZG = KZG_3000.clone();

        (0..10000).for_each(|_| {
            let blob_length: u64 = rand::thread_rng().gen_range(35..40000);
            let random_blob: Vec<u8> = (0..blob_length)
                .map(|_| rng.gen_range(32..=126) as u8)
                .collect();

            let input = Blob::from_raw_data(&random_blob);
            kzg_clone1
                .data_setup_custom(1, input.len().try_into().unwrap())
                .unwrap();
            kzg_clone2
                .calculate_roots_of_unity(input.len().try_into().unwrap())
                .unwrap();

            let polynomial_input = input.to_polynomial_coeff_form();
            let expanded_roots_of_unity_vec_1: Vec<&Fr> = (0..polynomial_input.len())
                .map(|i| kzg_clone1.get_nth_root_of_unity(i).unwrap())
                .collect();
            let expanded_roots_of_unity_vec_2: Vec<&Fr> = (0..polynomial_input.len())
                .map(|i| kzg_clone2.get_nth_root_of_unity(i).unwrap())
                .collect();

            assert_eq!(expanded_roots_of_unity_vec_1, expanded_roots_of_unity_vec_2);
        });
    }

    #[test]
    fn test_blob_to_kzg_commitment() {
        use ark_bn254::Fq;

        let blob = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let fn_output = KZG_3000.commit_blob(&blob).unwrap();
        let commitment_from_da = G1Affine::new_unchecked(
            Fq::from_str(
                "2961155957874067312593973807786254905069537311739090798303675273531563528369",
            )
            .unwrap(),
            Fq::from_str(
                "159565752702690920280451512738307422982252330088949702406468210607852362941",
            )
            .unwrap(),
        );
        assert_eq!(commitment_from_da, fn_output);
    }

    #[test]
    fn test_compute_kzg_proof_random_100_blobs() {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let mut kzg = KZG_INSTANCE.clone();

        (0..1).for_each(|_| {
            let blob_length = rand::thread_rng().gen_range(35..50000);
            let random_blob: Vec<u8> = (0..blob_length)
                .map(|_| rng.gen_range(32..=126) as u8)
                .collect();
            println!("generating blob of length is {}", blob_length);

            let input = Blob::from_raw_data(&random_blob);
            let input_poly = input.to_polynomial_eval_form();
            kzg.data_setup_custom(1, input.len().try_into().unwrap())
                .unwrap();

            let index =
                rand::thread_rng().gen_range(0..input_poly.len_underlying_blob_field_elements());
            let commitment = kzg.commit_eval_form(&input_poly.clone()).unwrap();
            let proof = kzg
                .compute_proof_with_known_z_fr_index(&input_poly, index.try_into().unwrap())
                .unwrap();
            let value_fr = input_poly.get_at_index(index).unwrap();
            let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
            let pairing_result = kzg
                .verify_proof(commitment, proof, value_fr.clone(), z_fr.clone())
                .unwrap();
            assert_eq!(pairing_result, true);

            // take random index, not the same index and check
            assert_eq!(
                kzg.verify_proof(
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
    fn test_compute_kzg_proof() {
        use rand::Rng;

        let mut kzg = KZG_INSTANCE.clone();

        let input = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let input_poly = input.to_polynomial_eval_form();

        for index in 0..input_poly.len() - 1 {
            kzg.data_setup_custom(4, input.len().try_into().unwrap())
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
            let commitment = kzg.commit_eval_form(&input_poly).unwrap();
            let proof = kzg
                .compute_proof_with_known_z_fr_index(&input_poly, index.try_into().unwrap())
                .unwrap();

            let value_fr = input_poly.get_at_index(index).unwrap();
            let z_fr = kzg.get_nth_root_of_unity(index).unwrap();
            let pairing_result = kzg
                .verify_proof(commitment, proof, value_fr.clone(), z_fr.clone())
                .unwrap();

            assert_eq!(pairing_result, true);

            assert_eq!(
                kzg.verify_proof(
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
    fn test_g1_ifft() {
        use ark_bn254::Fq;
        use std::io::BufRead;

        let file = File::open("tests/test-files/lagrangeG1SRS.txt").unwrap();
        let reader = BufReader::new(file);

        let kzg_g1_points = KZG_3000.g1_ifft(64).unwrap();

        // Iterate over each line in the file
        for (i, line_result) in reader.lines().enumerate() {
            let mut line = line_result.unwrap(); // Retrieve the line, handling potential I/O errors
            line = line.trim_end().to_string();

            // Split the line at each comma and process the parts
            let parts: Vec<&str> = line.split(',').collect();

            let x = Fq::from_str(parts[0]).expect("should be fine");
            let y = Fq::from_str(parts[1]).expect("should be fine");

            let point = G1Affine::new_unchecked(x, y);
            assert_eq!(point, kzg_g1_points[i], "failed on {i}");
        }
    }

    #[test]
    fn test_read_g1_point_from_bytes_be() {
        use ark_bn254::Fq;
        use ark_std::str::FromStr;
        use std::io::BufRead;

        let file = File::open("tests/test-files/srs.g1.points.string").unwrap();
        let reader = BufReader::new(file);
        let kzg_g1_points = KZG_3000.get_g1_points();

        // Iterate over each line in the file
        for (i, line_result) in reader.lines().enumerate() {
            let mut line = line_result.unwrap(); // Retrieve the line, handling potential I/O errors
            line = line.trim_end().to_string();

            // Split the line at each comma and process the parts
            let parts: Vec<&str> = line.split(',').collect();

            let x = Fq::from_str(parts[0]).expect("should be fine");
            let y = Fq::from_str(parts[1]).expect("should be fine");

            let point = G1Affine::new_unchecked(x, y);
            assert_eq!(point, kzg_g1_points[i]);
        }
    }

    #[test]
    fn test_read_g2_point_from_bytes_be() {
        use ark_bn254::{Fq, Fq2};
        use ark_std::str::FromStr;
        use std::io::BufRead;

        let file = File::open("tests/test-files/srs.g2.points.string").unwrap();
        let reader = BufReader::new(file);
        let kzg_g2_points = KZG_3000.get_g2_points();

        let mut custom_points_list: usize = 0;
        // Iterate over each line in the file
        for (i, line_result) in reader.lines().enumerate() {
            let mut line = line_result.unwrap(); // Retrieve the line, handling potential I/O errors
            line = line.trim_end().to_string();

            let parts: Vec<&str> = line.split(',').collect();

            let x_c0 = Fq::from_str(parts[0]).expect("should be fine");
            let x_c1 = Fq::from_str(parts[1]).expect("should be fine");

            let y_c0 = Fq::from_str(parts[2]).expect("should be fine");
            let y_c1 = Fq::from_str(parts[3]).expect("should be fine");

            let x = Fq2::new(x_c0, x_c1);
            let y = Fq2::new(y_c0, y_c1);
            let point = G2Affine::new_unchecked(x, y);
            custom_points_list += 1;
            assert_eq!(point, kzg_g2_points[i]);
        }
        assert_eq!(custom_points_list, kzg_g2_points.len());
    }

    #[test]
    fn test_multiple_proof_random_100_blobs() {
        let mut rng = rand::thread_rng();
        let mut kzg = KZG_INSTANCE.clone();

        let mut blobs: Vec<Blob> = Vec::new();
        let mut commitments: Vec<G1Affine> = Vec::new();
        let mut proofs: Vec<G1Affine> = Vec::new();

        (0..1).for_each(|_| {
            let blob_length = rand::thread_rng().gen_range(35..50000);
            let random_blob: Vec<u8> = (0..blob_length)
                .map(|_| rng.gen_range(32..=126) as u8)
                .collect();

            let input = Blob::from_raw_data(&random_blob);
            let input_poly = input.to_polynomial_eval_form();
            kzg.data_setup_custom(1, input.len().try_into().unwrap())
                .unwrap();

            let commitment = kzg.commit_eval_form(&input_poly).unwrap();
            let proof = kzg.compute_blob_proof(&input, &commitment).unwrap();

            blobs.push(input);
            commitments.push(commitment);
            proofs.push(proof);
        });

        let mut bad_blobs = blobs.clone();
        let mut bad_commitments = commitments.clone();
        let mut bad_proofs = proofs.clone();

        let pairing_result = kzg
            .verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs)
            .unwrap();
        assert_eq!(pairing_result, true);

        bad_blobs.pop();
        bad_blobs.push(Blob::from_raw_data(b"random"));
        let pairing_result_bad_blobs = kzg
            .verify_blob_kzg_proof_batch(&bad_blobs, &commitments, &proofs)
            .unwrap();
        assert_eq!(pairing_result_bad_blobs, false);

        bad_commitments.pop();
        bad_commitments.push(G1Affine::rand(&mut rng));
        let pairing_result_bad_commitments = kzg
            .verify_blob_kzg_proof_batch(&blobs, &bad_commitments, &proofs)
            .unwrap();
        assert_eq!(pairing_result_bad_commitments, false);

        bad_proofs.pop();
        bad_proofs.push(G1Affine::rand(&mut rng));
        let pairing_result_bad_proofs = kzg
            .verify_blob_kzg_proof_batch(&blobs, &commitments, &bad_proofs)
            .unwrap();
        assert_eq!(pairing_result_bad_proofs, false);

        let pairing_result_everything_bad = kzg
            .verify_blob_kzg_proof_batch(&bad_blobs, &bad_commitments, &bad_proofs)
            .unwrap();
        assert_eq!(pairing_result_everything_bad, false);
    }

    #[test]
    fn test_compute_multiple_kzg_proof() {
        let mut kzg = KZG_INSTANCE.clone();
        let mut kzg2 = KZG_INSTANCE.clone();

        let input1 = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        kzg.data_setup_custom(4, input1.len().try_into().unwrap())
            .unwrap();

        let input_poly1 = input1.to_polynomial_eval_form();

        let commitment1 = kzg.commit_eval_form(&input_poly1.clone()).unwrap();
        let proof_1 = kzg.compute_blob_proof(&input1, &commitment1).unwrap();

        let mut reversed_input: Vec<u8> = vec![0; GETTYSBURG_ADDRESS_BYTES.len()];
        reversed_input.clone_from_slice(GETTYSBURG_ADDRESS_BYTES);
        reversed_input.reverse();

        let input2 = Blob::from_raw_data(
            b"17704588942648532530972307366230787358793284390049200127770755029903181125533",
        );
        kzg2.calculate_roots_of_unity(input2.len().try_into().unwrap())
            .unwrap();
        let input_poly2 = input2.to_polynomial_eval_form();

        let commitment2 = kzg2.commit_eval_form(&input_poly2).unwrap();

        let proof_2 = kzg2.compute_blob_proof(&input2, &commitment2).unwrap();

        let blobs = vec![input1, input2];
        let commitments = vec![commitment1, commitment2];
        let proofs = vec![proof_1, proof_2];
        // let res = kzg.verify_blob_kzg_proof(&input1, &commitment1, &auto_proof).unwrap();

        let pairing_result = kzg
            .verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs)
            .unwrap();

        assert_eq!(pairing_result, true);
    }

    #[test]
    fn test_kzg_batch_proof_with_infinity() {
        let mut kzg = KZG_INSTANCE.clone();

        // Setup with consistent domain size
        let input_size = GETTYSBURG_ADDRESS_BYTES.len();
        kzg.data_setup_custom(4, input_size.try_into().unwrap())
            .unwrap();

        // First blob and proof - regular case
        let input1 = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let input_poly1 = input1.to_polynomial_eval_form();
        let commitment1 = kzg.commit_eval_form(&input_poly1).unwrap();
        let proof_1 = kzg.compute_blob_proof(&input1, &commitment1).unwrap();

        // Create a proof point at infinity
        let proof_at_infinity = G1Affine::identity();

        let blobs = vec![input1.clone()];
        let commitments = vec![commitment1];
        let proofs = vec![proof_at_infinity];

        // This should fail since a proof point at infinity is invalid
        let result = kzg.verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs);

        assert!(result.is_err());

        // Also test mixed case - one valid proof, one at infinity
        let input2 = Blob::from_raw_data(b"second input");
        let input_poly2 = input2.to_polynomial_eval_form();
        let commitment2 = kzg.commit_eval_form(&input_poly2).unwrap();

        let blobs_mixed = vec![input1, input2];
        let commitments_mixed = vec![commitment1, commitment2];
        let proofs_mixed = vec![proof_1, proof_at_infinity];

        let result_mixed =
            kzg.verify_blob_kzg_proof_batch(&blobs_mixed, &commitments_mixed, &proofs_mixed);
        assert!(result_mixed.is_err());
    }

    #[test]
    fn test_kzg_batch_proof_invalid_curve_points() {
        let mut kzg = KZG_INSTANCE.clone();
        kzg.data_setup_custom(4, GETTYSBURG_ADDRESS_BYTES.len().try_into().unwrap())
            .unwrap();

        // Create valid inputs first
        let input = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let input_poly = input.to_polynomial_eval_form();
        let valid_commitment = kzg.commit_eval_form(&input_poly).unwrap();
        let valid_proof = kzg.compute_blob_proof(&input, &valid_commitment).unwrap();

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
            let result = kzg.verify_blob_kzg_proof_batch(&blobs, &commitments, &proofs);

            assert!(
                result.is_err(),
                "Failed to detect invalid curve point - {}",
                case_description
            );
        }
    }

    #[test]
    fn test_evaluate_polynomial_in_evaluation_form_random_blob_all_indexes() {
        let mut rng = rand::thread_rng();
        let mut kzg = KZG_INSTANCE.clone();
        let blob_length: u64 = rand::thread_rng().gen_range(35..40000);
        let random_blob: Vec<u8> = (0..blob_length)
            .map(|_| rng.gen_range(32..=126) as u8)
            .collect();

        let input = Blob::from_raw_data(&random_blob);
        let input_poly = input.to_polynomial_eval_form();

        for i in 0..input_poly.len_underlying_blob_field_elements() {
            kzg.calculate_roots_of_unity(input.len().try_into().unwrap())
                .unwrap();
            let z_fr = kzg.get_nth_root_of_unity(i).unwrap();
            let claimed_y_fr =
                KZG::evaluate_polynomial_in_evaluation_form(&input_poly, z_fr, 3000).unwrap();
            assert_eq!(claimed_y_fr, input_poly.evaluations()[i]);
        }
    }

    #[test]
    fn test_primitive_roots_from_bigint_to_fr() {
        let data: [&str; 29] = [
            "1",
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
            "21888242871839275217838484774961031246007050428528088939761107053157389710902",
            "19540430494807482326159819597004422086093766032135589407132600596362845576832",
            "14940766826517323942636479241147756311199852622225275649687664389641784935947",
            "4419234939496763621076330863786513495701855246241724391626358375488475697872",
            "9088801421649573101014283686030284801466796108869023335878462724291607593530",
            "10359452186428527605436343203440067497552205259388878191021578220384701716497",
            "3478517300119284901893091970156912948790432420133812234316178878452092729974",
            "6837567842312086091520287814181175430087169027974246751610506942214842701774",
            "3161067157621608152362653341354432744960400845131437947728257924963983317266",
            "1120550406532664055539694724667294622065367841900378087843176726913374367458",
            "4158865282786404163413953114870269622875596290766033564087307867933865333818",
            "197302210312744933010843010704445784068657690384188106020011018676818793232",
            "20619701001583904760601357484951574588621083236087856586626117568842480512645",
            "20402931748843538985151001264530049874871572933694634836567070693966133783803",
            "421743594562400382753388642386256516545992082196004333756405989743524594615",
            "12650941915662020058015862023665998998969191525479888727406889100124684769509",
            "11699596668367776675346610687704220591435078791727316319397053191800576917728",
            "15549849457946371566896172786938980432421851627449396898353380550861104573629",
            "17220337697351015657950521176323262483320249231368149235373741788599650842711",
            "13536764371732269273912573961853310557438878140379554347802702086337840854307",
            "12143866164239048021030917283424216263377309185099704096317235600302831912062",
            "934650972362265999028062457054462628285482693704334323590406443310927365533",
            "5709868443893258075976348696661355716898495876243883251619397131511003808859",
            "19200870435978225707111062059747084165650991997241425080699860725083300967194",
            "7419588552507395652481651088034484897579724952953562618697845598160172257810",
            "2082940218526944230311718225077035922214683169814847712455127909555749686340",
            "19103219067921713944291392827692070036145651957329286315305642004821462161904",
        ];
        let fr_s = data
            .iter()
            .map(|s: &&str| Fr::from_str(*s).unwrap())
            .collect::<Vec<_>>();

        for i in 0..PRIMITIVE_ROOTS_OF_UNITY.len() {
            let found_root_of_unity_bigint = PRIMITIVE_ROOTS_OF_UNITY[i];
            let found_root_of_unity =
                Fr::from_bigint(BigInt::new(found_root_of_unity_bigint)).unwrap();
            assert_eq!(found_root_of_unity, fr_s[i]);
        }
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
