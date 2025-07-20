#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use lazy_static::lazy_static;
    use rand::Rng;
    use rust_kzg_bn254_primitives::{
        blob::Blob, consts::MAINNET_SRS_G1_SIZE, errors::KzgError, polynomial::PolynomialCoeffForm
    };
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
}
