#[cfg(test)]
mod tests {
    use rand::Rng;
    use rayon::prelude::*;
    use rust_kzg_bn254_primitives::{
        blob::Blob,
        helpers::{self, pad_payload},
    };

    const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();

    #[test]
    fn test_is_empty() {
        let blob_empty = Blob::from_raw_data("".as_bytes());
        assert!(blob_empty.is_empty(), "blob should be empty");

        let blob = Blob::from_raw_data("hi".as_bytes());
        assert!(!blob.is_empty(), "blob should not be empty");
    }

    #[test]
    fn test_validate_blob_data_as_canonical_field_elements() {
        let mut rng = rand::thread_rng();
        let test_1 = &GETTYSBURG_ADDRESS_BYTES[0..62];
        let test_1_with_padding = helpers::pad_payload(test_1);

        Blob::new(test_1_with_padding.as_slice()).expect("should succeed");

        let wrong_set = &GETTYSBURG_ADDRESS_BYTES[0..64];
        Blob::new(wrong_set).expect_err("should fail: not valid elements");

        let test_2 = &GETTYSBURG_ADDRESS_BYTES[0..3];
        Blob::new(test_2).expect_err("should fail: not a multiple of 32");

        let test_3 = [0xff; 32];
        let test_3_with_padding = helpers::pad_payload(&test_3);
        Blob::new(&test_3).expect_err("should fail: bad element");
        Blob::new(test_3_with_padding.as_slice()).expect("should succeed");
        assert_eq!(test_3_with_padding.len() % 32, 0);

        let test_4 = [0xff; 62];
        let test_4_with_padding = helpers::pad_payload(&test_4);
        Blob::new(&test_4).expect_err("should fail: not multiple of 32");
        Blob::new(test_4_with_padding.as_slice()).expect("should succeed");

        // a random blob of max 16MB after padding. So it's 16252928 before padding.
        let mut random_blob: Vec<u8> = (0..16252928).map(|_| rng.gen::<u8>()).collect();
        random_blob = helpers::pad_payload(&random_blob);

        assert_eq!(random_blob.len(), 16 * 1024 * 1024);
        Blob::new(random_blob.as_slice()).expect("should succeed");

        // testing 30 bytes set to 0xff
    }

    #[test]
    fn test_from_padded_bytes_unchecked() {
        let blob = Blob::from_raw_data(&GETTYSBURG_ADDRESS_BYTES[0..31]);
        let blob_data_padded = helpers::pad_payload(&GETTYSBURG_ADDRESS_BYTES[0..31]);
        let blob_unchecked =
            Blob::new(blob_data_padded.as_slice()).expect("Should create valid blob");

        assert_eq!(blob, blob_unchecked, "blob should be equal");
    }

    #[test]
    fn test_convert_by_padding_empty_byte() {
        let mut blob = Blob::from_raw_data("hi".as_bytes());
        assert_eq!(
            blob.data(),
            &[
                0, 104, 105, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0
            ],
            "testing adding padding"
        );
        assert_eq!(blob.data(), pad_payload("hi".as_bytes()));

        blob = Blob::from_raw_data(GETTYSBURG_ADDRESS_BYTES);

        assert_eq!(blob.to_raw_data().unwrap().len(), 1488);

        // parallel processing for faster testing of large blobs
        (0..1000).into_par_iter().for_each(|_| {
            // each thread gets its own RNG to avoid contention
            let mut thread_rng = rand::thread_rng();

            // random blob (about 16MB)
            let random_blob: Vec<u8> = (0..16252928).map(|_| thread_rng.gen::<u8>()).collect();
            let blob = Blob::from_raw_data(&random_blob);

            assert_eq!(
                random_blob.len() > (blob.to_raw_data().unwrap().len() - 32),
                true
            );
            assert_eq!(random_blob.len() <= blob.to_raw_data().unwrap().len(), true);
        });
    }
}
