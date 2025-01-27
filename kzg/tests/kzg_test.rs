#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use lazy_static::lazy_static;
    use rand::Rng;
    const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();
    use rust_kzg_bn254::{kzg::KZG, srs::SRS, verify};
    use rust_kzg_bn254_primitives::{
        blob::Blob, errors::KzgError, polynomial::PolynomialCoeffForm,
    };

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
    fn test_commit_errors() {
        let mut coeffs = vec![];
        let mut rng = rand::thread_rng();
        coeffs.resize(5000000, Fr::rand(&mut rng));
        let polynomial = PolynomialCoeffForm::new(coeffs);
        let result = KZG_INSTANCE.commit_coeff_form(&polynomial, &SRS_INSTANCE);
        assert_eq!(
            result,
            Err(KzgError::SerializationError(
                "polynomial length is not correct".to_string()
            ))
        );
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
            let input_poly = input.to_polynomial_eval_form();
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
                verify::proof(commitment, proof, value_fr.clone(), z_fr.clone()).unwrap();
            assert_eq!(pairing_result, true);

            // take random index, not the same index and check
            assert_eq!(
                verify::proof(
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
                verify::proof(commitment, proof, value_fr.clone(), z_fr.clone()).unwrap();

            assert_eq!(pairing_result, true);

            assert_eq!(
                verify::proof(
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
        let input_poly = input.to_polynomial_eval_form();

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
}
