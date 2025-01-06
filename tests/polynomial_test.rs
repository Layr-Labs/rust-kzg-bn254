#[cfg(test)]
mod tests {
    use rust_kzg_bn254::blob::Blob;
    const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();

    #[test]
    fn test_to_fr_array() {
        let blob = Blob::from_raw_data(
            vec![
                42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27,
                116, 108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40,
            ]
            .as_slice(),
        );
        let poly = blob.to_polynomial_coeff_form();
        assert_eq!(
            poly.to_bytes_be(),
            blob.data(),
            "should be deserialized properly"
        );

        assert_eq!(
            blob.to_raw_data(),
            vec![
                42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27,
                116, 108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40
            ],
            "should be deserialized properly"
        );

        let long_blob = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let long_poly = long_blob.to_polynomial_coeff_form();
        // let ga_converted_fr = to_fr_array(&ga_converted);
        assert_eq!(
            long_blob.data(),
            &long_poly.to_bytes_be(),
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
        let poly_coeff = blob.to_polynomial_coeff_form();

        let poly_eval = poly_coeff.to_eval_form().unwrap();
        let poly_coeff_back = poly_eval.to_coef_form().unwrap();
        assert_eq!(
            &poly_coeff_back.to_bytes_be(),
            blob.data(),
            "start and finish bytes should be the same"
        );
    }

    #[test]
    fn test_transform_form_large_blob() {
        let blob = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);
        let poly_coeff = blob.to_polynomial_coeff_form();

        let poly_eval = poly_coeff.to_eval_form().unwrap();
        let poly_coeff_back = poly_eval.to_coef_form().unwrap();
        assert_eq!(
            &poly_coeff_back.to_bytes_be(),
            blob.data(),
            "start and finish bytes should be the same"
        );
    }
}
