#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use rust_kzg_bn254_primitives::{
        blob::Blob,
        consts::{BYTES_PER_FIELD_ELEMENT, MAINNET_SRS_G1_SIZE},
        errors::KzgError,
        polynomial::{PolynomialCoeffForm, PolynomialEvalForm},
    };
    const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();

    #[test]
    fn test_to_fr_array() {
        let blob = Blob::from_raw_data(
            vec![
                42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27,
                116, 108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
            .as_slice(),
        );
        let poly = blob.to_polynomial_coeff_form().unwrap();
        assert_eq!(
            &poly.to_bytes_be()[0..blob.data().len()],
            blob.data(),
            "should be deserialized properly"
        );

        assert_eq!(
            blob.to_raw_data().unwrap(),
            vec![
                42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27,
                116, 108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            ],
            "should be deserialized properly"
        );

        let long_blob = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let long_poly = long_blob.to_polynomial_coeff_form().unwrap();
        // let ga_converted_fr = to_fr_array(&ga_converted);
        assert_eq!(
            long_blob.data(),
            &long_poly.to_bytes_be()[0..long_blob.data().len()],
            "should be deserialized properly"
        );
    }

    #[test]
    fn test_transform_form() {
        let blob = Blob::from_raw_data(
            vec![
                42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27,
                116, 108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40,
            ]
            .as_slice(),
        );
        let poly_coeff = blob.to_polynomial_coeff_form().unwrap();

        let poly_eval = poly_coeff.to_eval_form().unwrap();
        let poly_coeff_back = poly_eval.to_coeff_form().unwrap();
        assert_eq!(
            &poly_coeff_back.to_bytes_be()[0..blob.data().len()],
            blob.data(),
            "start and finish bytes should be the same"
        );
    }

    #[test]
    fn test_polynomial_lengths() {
        let poly_coeff =
            PolynomialCoeffForm::new(vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8)]).unwrap();
        assert_eq!(
            poly_coeff.coeffs().len(),
            4,
            "poly should be padded to the next power of 2"
        );

        let poly_evals =
            PolynomialEvalForm::new(vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8)]).unwrap();
        assert_eq!(
            poly_evals.evaluations().len(),
            4,
            "poly should be padded to the next power of 2"
        );

        let poly_coeff_4mb =
            PolynomialCoeffForm::new(vec![Fr::from(1u8); MAINNET_SRS_G1_SIZE]).unwrap();
        assert_eq!(
            poly_coeff_4mb.coeffs().len(),
            MAINNET_SRS_G1_SIZE,
            "poly size is already power of 2 and is of MAINNET_SRS_G1_SIZE length"
        );

        // Test error condition for PolynomialCoeffForm
        let poly_coeff_large =
            PolynomialCoeffForm::new(vec![Fr::from(1u8); MAINNET_SRS_G1_SIZE + 1]);
        assert_eq!(poly_coeff_large.is_err(), true);
        assert_eq!(
            poly_coeff_large.err().unwrap().to_string(),
            KzgError::GenericError("Input size exceeds maximum polynomial size".to_string())
                .to_string()
        );

        // Test error condition for PolynomialEvalForm  
        let poly_eval_large =
            PolynomialEvalForm::new(vec![Fr::from(1u8); MAINNET_SRS_G1_SIZE + 1]);
        assert_eq!(poly_eval_large.is_err(), true);
        assert_eq!(
            poly_eval_large.err().unwrap().to_string(),
            KzgError::GenericError("Input size exceeds maximum polynomial size".to_string())
                .to_string()
        );
    }

    #[test]
    fn test_transform_length_stays_same() {
        let poly_coeff =
            PolynomialCoeffForm::new(vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8)]).unwrap();
        let poly_eval = poly_coeff.to_eval_form().unwrap();
        let poly_coeff_back = poly_eval.to_coeff_form().unwrap();
        assert_eq!(
            poly_coeff.coeffs().len(),
            poly_coeff_back.coeffs().len(),
            "length of poly should remain the same when converting between forms"
        );
    }

    #[test]
    fn test_transform_form_large_blob() {
        let blob = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let poly_coeff = blob.to_polynomial_coeff_form().unwrap();

        let poly_eval = poly_coeff.to_eval_form().unwrap();
        let poly_coeff_back = poly_eval.to_coeff_form().unwrap();
        assert_eq!(
            // TODO: we might want to change the API to return the underlying blob data len?
            // right now this info is lost after converting between forms.
            &poly_coeff_back.to_bytes_be()[0..blob.data().len()],
            blob.data(),
            "start and finish bytes should be the same"
        );
    }

    #[test]
    fn test_is_empty() {
        // Due to power-of-two padding, polynomials created through normal constructors
        // will never be truly empty (minimum size is 1 after padding)
        
        // Test with empty blob data - results in polynomial with 1 element (zero-padded)
        let empty_blob = Blob::from_raw_data("".as_bytes());
        
        let empty_poly_coeff = empty_blob.to_polynomial_coeff_form().unwrap();
        assert!(!empty_poly_coeff.is_empty(), "polynomial coeff form is not empty due to power-of-two padding");
        assert_eq!(empty_poly_coeff.len(), 1, "empty input should result in polynomial of length 1");
        
        let empty_poly_eval = empty_blob.to_polynomial_eval_form().unwrap();
        assert!(!empty_poly_eval.is_empty(), "polynomial eval form is not empty due to power-of-two padding");
        assert_eq!(empty_poly_eval.len(), 1, "empty input should result in polynomial of length 1");
        
        // Test with directly created polynomials from field elements
        let poly_coeff_direct = PolynomialCoeffForm::new(vec![Fr::from(1u8), Fr::from(2u8)]).unwrap();
        assert!(!poly_coeff_direct.is_empty(), "directly created polynomial coeff form should not be empty");
        
        let poly_eval_direct = PolynomialEvalForm::new(vec![Fr::from(1u8), Fr::from(2u8)]).unwrap();
        assert!(!poly_eval_direct.is_empty(), "directly created polynomial eval form should not be empty");
        
        // Test with directly created polynomial from empty vector - still results in non-empty due to padding
        let poly_coeff_from_empty = PolynomialCoeffForm::new(vec![]).unwrap();
        assert!(!poly_coeff_from_empty.is_empty(), "polynomial from empty vector is not empty due to padding");
        assert_eq!(poly_coeff_from_empty.len(), 1, "empty vector input should result in polynomial of length 1");
        
        let poly_eval_from_empty = PolynomialEvalForm::new(vec![]).unwrap();
        assert!(!poly_eval_from_empty.is_empty(), "polynomial from empty vector is not empty due to padding");
        assert_eq!(poly_eval_from_empty.len(), 1, "empty vector input should result in polynomial of length 1");
    }

    #[test]
    fn test_to_bytes_be() {
        // Test to_bytes_be() method on both polynomial forms
        
        // Test with known input data
        let test_data = b"hello world test data";
        let blob = Blob::from_raw_data(test_data);
        
        // Test PolynomialCoeffForm::to_bytes_be()
        let poly_coeff = blob.to_polynomial_coeff_form().unwrap();
        let bytes_from_coeff = poly_coeff.to_bytes_be();
        
        // The output should match the original blob data (which is padded)
        assert_eq!(bytes_from_coeff, blob.data(), "to_bytes_be() should match blob data for coeff form");
        
        // Test PolynomialEvalForm::to_bytes_be() 
        let poly_eval = blob.to_polynomial_eval_form().unwrap();
        let bytes_from_eval = poly_eval.to_bytes_be();
        
        // The output should match the original blob data
        assert_eq!(bytes_from_eval, blob.data(), "to_bytes_be() should match blob data for eval form");
    }

    #[test]
    fn test_len_underlying_blob_field_elements() {
        // Test len_underlying_blob_field_elements() method on both polynomial forms
        
        // Test with known field element count
        let field_elements = vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8)];
        let poly_coeff = PolynomialCoeffForm::new(field_elements.clone()).unwrap();
        let poly_eval = PolynomialEvalForm::new(field_elements.clone()).unwrap();
        
        // Should return 3 field elements for both forms
        assert_eq!(poly_coeff.len_underlying_blob_field_elements(), 3, "coeff form should have 3 underlying field elements");
        assert_eq!(poly_eval.len_underlying_blob_field_elements(), 3, "eval form should have 3 underlying field elements");
        
        // Verify the relationship: field_elements * BYTES_PER_FIELD_ELEMENT = underlying_blob_bytes
        assert_eq!(poly_coeff.len_underlying_blob_field_elements() * 32, poly_coeff.len_underlying_blob_bytes(), "field elements * 32 should equal blob bytes");
        assert_eq!(poly_eval.len_underlying_blob_field_elements() * 32, poly_eval.len_underlying_blob_bytes(), "field elements * 32 should equal blob bytes");
        
        // Test with blob-derived polynomials
        let test_data = b"hello world test data that spans multiple field elements";
        let blob = Blob::from_raw_data(test_data);
        let blob_poly_coeff = blob.to_polynomial_coeff_form().unwrap();
        let blob_poly_eval = blob.to_polynomial_eval_form().unwrap();
        
        let expected_field_elements = blob.data().len() / BYTES_PER_FIELD_ELEMENT;
        assert_eq!(blob_poly_coeff.len_underlying_blob_field_elements(), expected_field_elements, "blob coeff form should have correct field element count");
        assert_eq!(blob_poly_eval.len_underlying_blob_field_elements(), expected_field_elements, "blob eval form should have correct field element count");
        
        // Test with large polynomial at size limit
        let max_size_poly_coeff = PolynomialCoeffForm::new(vec![Fr::from(1u8); MAINNET_SRS_G1_SIZE]).unwrap();
        assert_eq!(max_size_poly_coeff.len_underlying_blob_field_elements(), MAINNET_SRS_G1_SIZE, "max size polynomial should have correct field element count");
    }

    #[test]
    fn test_get_at_index() {
        // Test get_at_index() method on PolynomialCoeffForm
        let field_elements = vec![Fr::from(1u8), Fr::from(2u8), Fr::from(3u8)];
        let poly_coeff = PolynomialCoeffForm::new(field_elements.clone()).unwrap();
        
        // Test valid indices
        assert_eq!(poly_coeff.get_at_index(0), Some(&Fr::from(1u8)), "should retrieve first element");
        assert_eq!(poly_coeff.get_at_index(1), Some(&Fr::from(2u8)), "should retrieve second element");
        assert_eq!(poly_coeff.get_at_index(2), Some(&Fr::from(3u8)), "should retrieve third element");
        assert_eq!(poly_coeff.get_at_index(3), Some(&Fr::from(0u8)), "should retrieve padded zero element");
        
        // Test invalid indices
        assert_eq!(poly_coeff.get_at_index(4), None, "should return None for out of bounds index");
        assert_eq!(poly_coeff.get_at_index(100), None, "should return None for large out of bounds index");
        
        // Test with empty polynomial
        let empty_poly_coeff = PolynomialCoeffForm::new(vec![]).unwrap();
        assert_eq!(empty_poly_coeff.get_at_index(0), Some(&Fr::from(0u8)), "empty polynomial should have one zero element");
        assert_eq!(empty_poly_coeff.get_at_index(1), None, "should return None for index beyond padded size");
        
        // Test with large polynomial
        let large_elements = vec![Fr::from(42u8); 100];
        let large_poly_coeff = PolynomialCoeffForm::new(large_elements).unwrap();
        
        assert_eq!(large_poly_coeff.get_at_index(127), Some(&Fr::from(0u8)), "should retrieve zero at end of padded polynomial");
        assert_eq!(large_poly_coeff.get_at_index(128), None, "should return None beyond polynomial length");
        
        // Verify the polynomial was padded to next power of two (128)
        assert_eq!(large_poly_coeff.len(), 128, "large polynomial should be padded to 128 elements");
    }

    #[test]
    fn test_get_evalualtion() {
        // Test get_evalualtion() method on PolynomialEvalForm
        let field_elements = vec![Fr::from(5u8), Fr::from(10u8), Fr::from(15u8)];
        let poly_eval = PolynomialEvalForm::new(field_elements.clone()).unwrap();
        
        // Test valid indices
        assert_eq!(poly_eval.get_evalualtion(0), Some(&Fr::from(5u8)), "should retrieve first evaluation");
        assert_eq!(poly_eval.get_evalualtion(1), Some(&Fr::from(10u8)), "should retrieve second evaluation");
        assert_eq!(poly_eval.get_evalualtion(2), Some(&Fr::from(15u8)), "should retrieve third evaluation");
        assert_eq!(poly_eval.get_evalualtion(3), Some(&Fr::from(0u8)), "should retrieve padded zero evaluation");
        
        // Test invalid indices
        assert_eq!(poly_eval.get_evalualtion(4), None, "should return None for out of bounds index");
        assert_eq!(poly_eval.get_evalualtion(100), None, "should return None for large out of bounds index");
        
        // Test with blob-derived polynomial
        let test_data = b"test data for evaluations";
        let blob = Blob::from_raw_data(test_data);
        let blob_poly_eval = blob.to_polynomial_eval_form().unwrap();
        
        // Should be able to retrieve evaluations up to polynomial length
        assert!(blob_poly_eval.get_evalualtion(0).is_some(), "should retrieve first evaluation from blob polynomial");
        assert!(blob_poly_eval.get_evalualtion(blob_poly_eval.len() - 1).is_some(), "should retrieve last evaluation");
        assert_eq!(blob_poly_eval.get_evalualtion(blob_poly_eval.len()), None, "should return None beyond length");
        
        // Test with empty polynomial
        let empty_poly_eval = PolynomialEvalForm::new(vec![]).unwrap();
        assert_eq!(empty_poly_eval.get_evalualtion(0), Some(&Fr::from(0u8)), "empty polynomial should have one zero evaluation");
        assert_eq!(empty_poly_eval.get_evalualtion(1), None, "should return None for index beyond padded size");
    }

}
