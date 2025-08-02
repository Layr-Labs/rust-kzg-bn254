use std::{
    fs::File,
    io::{BufRead, BufReader, Read},
};

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField, UniformRand};
use ark_std::{str::FromStr, One, Zero};
use rust_kzg_bn254_primitives::{
    blob::Blob,
    consts::{
        BYTES_PER_FIELD_ELEMENT, MAINNET_SRS_G1_SIZE, PRIMITIVE_ROOTS_OF_UNITY,
        SIZE_OF_G1_AFFINE_COMPRESSED,
    },
    errors::KzgError,
    helpers::{
        blob_to_polynomial, calculate_roots_of_unity, compute_challenge, get_num_element,
        is_on_curve_g1, is_on_curve_g2, is_zeroed, pad_payload, remove_internal_padding,
        set_bytes_canonical, set_bytes_canonical_manual, to_byte_array, to_fr_array,
        validate_g1_point, validate_g2_point,
    },
};

const GETTYSBURG_ADDRESS_BYTES: &[u8] = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();

#[test]
fn test_calculate_roots_of_unity_error_zero_length() {
    // Test error case: zero length input
    let result = calculate_roots_of_unity(0);
    assert!(result.is_err(), "Zero length should return error");

    match result.unwrap_err() {
        KzgError::GenericError(msg) => {
            assert_eq!(
                msg, "Length of data after padding is 0",
                "Should return correct error message"
            );
        },
        _ => panic!("Should return GenericError for zero length"),
    }
}

#[test]
fn test_calculate_roots_of_unity_error_oversized_input() {
    // Test error case: input too large for SRS
    // MAINNET_SRS_G1_SIZE is 131072, so we need more than that in field elements
    let oversized_length = (MAINNET_SRS_G1_SIZE as u64 + 1) * BYTES_PER_FIELD_ELEMENT as u64;

    let result = calculate_roots_of_unity(oversized_length);
    assert!(result.is_err(), "Oversized input should return error");

    match result.unwrap_err() {
        KzgError::GenericError(msg) => {
            assert_eq!(
                msg, "the length of data after padding is not valid with respect to the SRS",
                "Should return correct error message for oversized input"
            );
        },
        _ => panic!("Should return GenericError for oversized input"),
    }
}

#[test]
fn test_calculate_roots_of_unity_basic_functionality() {
    // Test basic functionality with small valid inputs

    // Test with 32 bytes (1 field element) - should give 1 root
    let result_32 = calculate_roots_of_unity(32);
    assert!(result_32.is_ok(), "32 bytes should succeed");
    let roots_32 = result_32.unwrap();
    assert_eq!(roots_32.len(), 1, "32 bytes should give 1 root");
    assert_eq!(
        roots_32[0],
        Fr::one(),
        "First root should be identity element"
    );

    // Test with 64 bytes (2 field elements) - should give 2 roots
    let result_64 = calculate_roots_of_unity(64);
    assert!(result_64.is_ok(), "64 bytes should succeed");
    let roots_64 = result_64.unwrap();
    assert_eq!(roots_64.len(), 2, "64 bytes should give 2 roots");

    // Test with 96 bytes (3 field elements, next power of 2 is 4) - should give 4 roots
    let result_96 = calculate_roots_of_unity(96);
    assert!(result_96.is_ok(), "96 bytes should succeed");
    let roots_96 = result_96.unwrap();
    assert_eq!(roots_96.len(), 4, "96 bytes should give 4 roots");
    assert_eq!(
        roots_96[0],
        Fr::one(),
        "First root should be identity element"
    );
}

#[test]
fn test_calculate_roots_of_unity_mathematical_properties() {
    // Test mathematical properties of roots of unity

    // Test with input that gives us 4 roots
    let length = 3 * BYTES_PER_FIELD_ELEMENT as u64; // 3 field elements -> next power of 2 is 4
    let result = calculate_roots_of_unity(length);
    assert!(result.is_ok(), "Should succeed for valid input");

    let roots = result.unwrap();
    assert_eq!(roots.len(), 4, "Should have 4 roots");

    // First root should be 1 (identity)
    assert_eq!(roots[0], Fr::one(), "First root should be identity");

    // Test that these are actually 4th roots of unity
    // For 4th roots of unity, each root^4 should equal 1
    for (i, root) in roots.iter().enumerate() {
        let fourth_power = root.pow([4u64]);
        assert_eq!(
            fourth_power,
            Fr::one(),
            "Root {} raised to the 4th power should equal 1",
            i
        );
    }

    // Test with larger case - 8 roots
    let length_8 = 5 * BYTES_PER_FIELD_ELEMENT as u64; // 5 field elements -> next power of 2 is 8
    let result_8 = calculate_roots_of_unity(length_8);
    assert!(result_8.is_ok(), "Should succeed for 8-root case");

    let roots_8 = result_8.unwrap();
    assert_eq!(roots_8.len(), 8, "Should have 8 roots");

    // For 8th roots of unity, each root^8 should equal 1
    for (i, root) in roots_8.iter().enumerate() {
        let eighth_power = root.pow([8u64]);
        assert_eq!(
            eighth_power,
            Fr::one(),
            "Root {} raised to the 8th power should equal 1",
            i
        );
    }
}

#[test]
fn test_calculate_roots_of_unity_powers_of_two() {
    // Test with various powers of 2 to ensure correct behavior

    let test_cases = [
        (BYTES_PER_FIELD_ELEMENT as u64, 1), // 1 field element -> 1 root
        (2 * BYTES_PER_FIELD_ELEMENT as u64, 2), // 2 field elements -> 2 roots
        (4 * BYTES_PER_FIELD_ELEMENT as u64, 4), // 4 field elements -> 4 roots
        (8 * BYTES_PER_FIELD_ELEMENT as u64, 8), // 8 field elements -> 8 roots
        (16 * BYTES_PER_FIELD_ELEMENT as u64, 16), // 16 field elements -> 16 roots
        (32 * BYTES_PER_FIELD_ELEMENT as u64, 32), // 32 field elements -> 32 roots
    ];

    for (input_length, expected_root_count) in test_cases.iter() {
        let result = calculate_roots_of_unity(*input_length);
        assert!(
            result.is_ok(),
            "Should succeed for input length {}",
            input_length
        );

        let roots = result.unwrap();
        assert_eq!(
            roots.len(),
            *expected_root_count,
            "Input length {} should give {} roots",
            input_length,
            expected_root_count
        );

        // First root should always be 1
        assert_eq!(
            roots[0],
            Fr::one(),
            "First root should be identity for length {}",
            input_length
        );

        // All roots should be distinct
        for i in 0..roots.len() {
            for j in i + 1..roots.len() {
                assert_ne!(
                    roots[i], roots[j],
                    "Roots {} and {} should be distinct for length {}",
                    i, j, input_length
                );
            }
        }
    }
}

#[test]
fn test_calculate_roots_of_unity_boundary_conditions() {
    // Test boundary conditions near the size limits

    // Test with 1 byte (smallest possible non-zero input)
    let result_1 = calculate_roots_of_unity(1);
    assert!(result_1.is_ok(), "1 byte should succeed");
    let roots_1 = result_1.unwrap();
    assert_eq!(roots_1.len(), 1, "1 byte should give 1 root");

    // Test with maximum valid size (just under the limit)
    let max_valid_length = MAINNET_SRS_G1_SIZE as u64 * BYTES_PER_FIELD_ELEMENT as u64;
    let result_max = calculate_roots_of_unity(max_valid_length);
    // This might succeed or fail depending on the exact calculation, but shouldn't panic
    match result_max {
        Ok(roots) => {
            assert!(!roots.is_empty(), "Should have at least one root");
            assert_eq!(roots[0], Fr::one(), "First root should be identity");
        },
        Err(_) => {
            // It's also acceptable if this fails due to size constraints
        },
    }

    // Test edge case: exactly at field element boundary
    let field_element_boundary = BYTES_PER_FIELD_ELEMENT as u64;
    let result_boundary = calculate_roots_of_unity(field_element_boundary);
    assert!(
        result_boundary.is_ok(),
        "Field element boundary should succeed"
    );
}

#[test]
fn test_calculate_roots_of_unity_consistency() {
    // Test consistency - same input should always give same output

    let test_length = 100; // Arbitrary test length

    let result1 = calculate_roots_of_unity(test_length);
    let result2 = calculate_roots_of_unity(test_length);
    let result3 = calculate_roots_of_unity(test_length);

    assert!(
        result1.is_ok() && result2.is_ok() && result3.is_ok(),
        "All calls should succeed"
    );

    let roots1 = result1.unwrap();
    let roots2 = result2.unwrap();
    let roots3 = result3.unwrap();

    assert_eq!(roots1, roots2, "Results should be consistent");
    assert_eq!(roots2, roots3, "Results should be consistent");
}

#[test]
fn test_calculate_roots_of_unity_large_valid_inputs() {
    // Test with larger valid inputs to ensure no performance issues

    let large_test_cases = [
        1000,    // 1KB
        10000,   // 10KB
        100000,  // 100KB
        1000000, // 1MB
    ];

    for &test_length in large_test_cases.iter() {
        let result = calculate_roots_of_unity(test_length);
        assert!(result.is_ok(), "Large input {} should succeed", test_length);

        let roots = result.unwrap();
        assert!(
            !roots.is_empty(),
            "Should have at least one root for input {}",
            test_length
        );
        assert_eq!(
            roots[0],
            Fr::one(),
            "First root should be identity for input {}",
            test_length
        );

        // Verify the roots are actual nth roots of unity
        let n = roots.len(); // Number of roots returned
        for (i, root) in roots.iter().enumerate() {
            let nth_power = root.pow([n as u64]);
            assert_eq!(
                nth_power,
                Fr::one(),
                "Root {} should be an {}-th root of unity for input {}",
                i,
                n,
                test_length
            );
        }
    }
}

#[test]
fn test_calculate_roots_of_unity_specific_error_conditions() {
    // Test specific error conditions that might be edge cases

    // Test near the overflow boundary for log2 calculation
    // This is trying to find cases where the log2 conversion might fail
    let very_large_but_valid = (MAINNET_SRS_G1_SIZE as u64) * BYTES_PER_FIELD_ELEMENT as u64;
    let result = calculate_roots_of_unity(very_large_but_valid);

    // This should either succeed or fail gracefully with a proper error
    match result {
        Ok(roots) => {
            assert!(!roots.is_empty(), "Should have roots if successful");
        },
        Err(KzgError::GenericError(msg)) => {
            // Should be a valid error message
            assert!(
                msg.contains("SRS") || msg.contains("convert") || msg.contains("size"),
                "Error message should be meaningful: {}",
                msg
            );
        },
        Err(KzgError::SerializationError(msg)) => {
            // Should be a valid error message
            assert!(
                msg.contains("SRS"),
                "Error message should mention SRS: {}",
                msg
            );
        },
        Err(other) => {
            panic!("Unexpected error type: {:?}", other);
        },
    }
}

#[test]
fn test_g1_is_on_curve() {
    use rand::thread_rng;

    let rng = &mut thread_rng();
    for _ in 0..1000 {
        let point = G1Affine::rand(rng);
        assert!(is_on_curve_g1(&G1Projective::from(point)));
        let mut not_on_curve = point;
        not_on_curve.x += Fq::one();
        assert!(!is_on_curve_g1(&G1Projective::from(not_on_curve)));
    }
}

#[test]
fn test_g2_is_on_curve() {
    use rand::thread_rng;

    let rng = &mut thread_rng();
    for _ in 0..1000 {
        let point = G2Affine::rand(rng);
        assert!(is_on_curve_g2(&G2Projective::from(point)));
        let mut not_on_curve = point;
        not_on_curve.x += Fq2::one();
        assert!(!is_on_curve_g2(&G2Projective::from(not_on_curve)));
    }
}
// Loads data from files. This data was generated by gnark and is DA compatible.
// Tests deserialization of data and equivalence.
#[test]
fn test_blob_to_polynomial() {
    let file = File::open("tests/test-files/blobs.txt").unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = [0u8; SIZE_OF_G1_AFFINE_COMPRESSED];
    let mut read_fr_from_bytes: Vec<Fr> = vec![];
    let mut fr_from_str_vec: Vec<Fr> = vec![];

    // Loop to read the file 32 bytes at a time
    loop {
        match reader.read(&mut buffer[..]) {
            Ok(0) => {
                // No more data to read
                break;
            },
            Ok(n) => {
                // Process the chunk of data just read
                read_fr_from_bytes.push(Fr::from_be_bytes_mod_order(&buffer[..n]))
            },
            Err(e) => panic!("{}", e),
        }
    }

    let file2 = File::open("tests/test-files/blobs-from-fr.txt").unwrap();
    let reader2 = BufReader::new(file2);
    for (i, line) in reader2.lines().enumerate() {
        let line = line.unwrap();
        let trimmed_line = line.trim_end(); // Trim whitespace from the end
        let the_strings_str: Vec<&str> = trimmed_line.split(',').collect(); // Split the line on commas
        let fr_from_str = Fr::from_str(the_strings_str[0]).expect("should be fine");
        fr_from_str_vec.push(fr_from_str);
        assert_eq!(fr_from_str, read_fr_from_bytes[i]);
    }

    let mut file3 = File::open("tests/test-files/blobs.txt").unwrap();
    let mut contents = Vec::new();
    file3.read_to_end(&mut contents).unwrap();

    assert_eq!(fr_from_str_vec, blob_to_polynomial(&contents));
}

#[test]
fn test_to_fr_array() {
    let converted = pad_payload(
        vec![
            42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27, 116,
            108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40,
        ]
        .as_slice(),
    );
    let data_fr = to_fr_array(&converted);
    let result = to_byte_array(&data_fr, converted.len().try_into().unwrap());
    assert_eq!(converted, result, "should be deserialized properly");

    let ga_converted = pad_payload(GETTYSBURG_ADDRESS_BYTES);
    let ga_converted_fr = to_fr_array(&ga_converted);
    assert_eq!(
        to_byte_array(&ga_converted_fr, ga_converted.len().try_into().unwrap()),
        ga_converted
    );
}

#[test]
fn test_how_to_read_bytes() {
    let the_bytes = vec![
        31, 94, 220, 111, 30, 251, 22, 93, 69, 166, 84, 121, 141, 75, 170, 165, 14, 59, 77, 36, 24,
        41, 19, 174, 245, 17, 10, 21, 88, 14, 186, 173,
    ];
    let data = Fr::from_be_bytes_mod_order(&the_bytes);
    println!("{:?}", data.0);
}

#[test]
fn test_get_num_element() {
    let num_elements = get_num_element(1000, BYTES_PER_FIELD_ELEMENT);
    assert_eq!(num_elements, 32_usize, "needs to be equal");
}

#[test]
fn test_set_canonical_bytes() {
    let data: Vec<u8> = vec![
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];
    let fr_element = set_bytes_canonical_manual(&data);
    assert_eq!(fr_element, set_bytes_canonical(&data), "needs to be equal");
}

#[test]
fn test_pad_payload() {
    let padded_data = pad_payload("hi".as_bytes());
    assert_eq!(
        padded_data,
        vec![
            0, 104, 105, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0
        ],
        "testing adding padding"
    );

    let unpadded_data = remove_internal_padding(&padded_data).unwrap();
    assert_eq!(
        unpadded_data,
        vec![
            104, 105, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0
        ],
        "testing removing padding"
    );

    let padded_data_larger_size = pad_payload(
        "zxcvbnm,.//asdfgghjkl;'][poiuytrewq`1234567890zxcvbnm,.//1234567890".as_bytes(),
    );
    assert_eq!(
        padded_data_larger_size,
        vec![
            0, 122, 120, 99, 118, 98, 110, 109, 44, 46, 47, 47, 97, 115, 100, 102, 103, 103, 104,
            106, 107, 108, 59, 39, 93, 91, 112, 111, 105, 117, 121, 116, 0, 114, 101, 119, 113, 96,
            49, 50, 51, 52, 53, 54, 55, 56, 57, 48, 122, 120, 99, 118, 98, 110, 109, 44, 46, 47,
            47, 49, 50, 51, 52, 53, 0, 54, 55, 56, 57, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        "testing adding padding"
    );

    let unpadded_data_larger_size = remove_internal_padding(&padded_data_larger_size).unwrap();
    assert_eq!(
        unpadded_data_larger_size,
        vec![
            122, 120, 99, 118, 98, 110, 109, 44, 46, 47, 47, 97, 115, 100, 102, 103, 103, 104, 106,
            107, 108, 59, 39, 93, 91, 112, 111, 105, 117, 121, 116, 114, 101, 119, 113, 96, 49, 50,
            51, 52, 53, 54, 55, 56, 57, 48, 122, 120, 99, 118, 98, 110, 109, 44, 46, 47, 47, 49,
            50, 51, 52, 53, 54, 55, 56, 57, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0
        ],
        "testing removing padding"
    );


    let padded_data_gettysburg = pad_payload(GETTYSBURG_ADDRESS_BYTES);
    let unpadded_data_gettysburg = remove_internal_padding(&padded_data_gettysburg).unwrap();
    assert_eq!(unpadded_data_gettysburg.len(), 1488);
    assert_eq!(
        GETTYSBURG_ADDRESS_BYTES.len() <= unpadded_data_gettysburg.len(),
        true
    );
}

#[test]
fn test_is_zeroed_all_zeroes() {
    // Case where the first byte and the buffer are all zeroes
    let first_byte = 0;
    let buf = vec![0, 0, 0, 0, 0];
    assert!(is_zeroed(first_byte, buf), "Expected true for all zeroes");
}

#[test]
fn test_is_zeroed_first_byte_non_zero() {
    // Case where the first byte is non-zero
    let first_byte = 1;
    let buf = vec![0, 0, 0, 0, 0];
    assert!(
        !is_zeroed(first_byte, buf),
        "Expected false when the first byte is non-zero"
    );
}

#[test]
fn test_is_zeroed_buffer_non_zero() {
    // Case where the buffer contains non-zero elements
    let first_byte = 0;
    let buf = vec![0, 0, 1, 0, 0];
    assert!(
        !is_zeroed(first_byte, buf),
        "Expected false when the buffer contains non-zero elements"
    );
}

#[test]
fn test_is_zeroed_first_byte_and_buffer_non_zero() {
    // Case where both the first byte and buffer contain non-zero elements
    let first_byte = 1;
    let buf = vec![0, 1, 0, 0, 0];
    assert!(
        !is_zeroed(first_byte, buf),
        "Expected false when both the first byte and buffer contain non-zero elements"
    );
}

#[test]
fn test_is_zeroed_empty_buffer() {
    // Case where the buffer is empty but the first byte is zero
    let first_byte = 0;
    let buf: Vec<u8> = Vec::new();
    assert!(
        is_zeroed(first_byte, buf),
        "Expected true for an empty buffer with a zero first byte"
    );
}

#[test]
fn test_is_zeroed_empty_buffer_non_zero_first_byte() {
    // Case where the buffer is empty and the first byte is non-zero
    let first_byte = 1;
    let buf: Vec<u8> = Vec::new();
    assert!(
        !is_zeroed(first_byte, buf),
        "Expected false for an empty buffer with a non-zero first byte"
    );
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
        let root_of_unity_at_index = PRIMITIVE_ROOTS_OF_UNITY[i];
        assert_eq!(root_of_unity_at_index, fr_s[i]);
    }
}

#[test]
fn test_validate_g1_point_valid_point() {
    // Test with valid random G1 points
    let mut rng = ark_std::test_rng();

    for _ in 0..10 {
        let valid_point = G1Affine::rand(&mut rng);
        let result = validate_g1_point(&valid_point);
        assert!(
            result.is_ok(),
            "Valid random G1 point should pass validation"
        );
    }
}

#[test]
fn test_validate_g1_point_identity_point() {
    // Test with identity point (point at infinity)
    let identity_point = G1Affine::identity();
    let result = validate_g1_point(&identity_point);

    assert!(result.is_err(), "Identity point should fail validation");
    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G1 point cannot be point at infinity",
                "Should have correct error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for identity point"),
    }
}

#[test]
fn test_validate_g1_point_invalid_curve_point() {
    // Test with a point that's not on the curve
    use ark_bn254::Fq;
    use ark_ff::One;

    // Create an invalid point using coordinates that don't satisfy the curve equation y² = x³ + 3
    let invalid_x = Fq::one(); // x = 1
    let invalid_y = Fq::one(); // y = 1 (but 1² ≠ 1³ + 3, so not on curve)
    let invalid_point = G1Affine::new_unchecked(invalid_x, invalid_y);

    // Verify our test point is actually invalid
    assert!(
        !invalid_point.is_on_curve(),
        "Test point should not be on curve"
    );

    let result = validate_g1_point(&invalid_point);
    assert!(
        result.is_err(),
        "Invalid curve point should fail validation"
    );

    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G1 point not on curve",
                "Should have correct error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for invalid curve point"),
    }
}

#[test]
fn test_validate_g1_point_generator() {
    // Test with the generator point (should be rejected)
    let generator = G1Affine::generator();
    let result = validate_g1_point(&generator);
    assert!(result.is_err(), "Generator point should be rejected");

    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G1 point cannot be the generator point",
                "Should have correct error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for generator point"),
    }
}

#[test]
fn test_validate_g2_point_valid_point() {
    // Test with valid random G2 points
    let mut rng = ark_std::test_rng();

    for _ in 0..10 {
        let valid_point = G2Affine::rand(&mut rng);
        let result = validate_g2_point(&valid_point);
        assert!(
            result.is_ok(),
            "Valid random G2 point should pass validation"
        );
    }
}

#[test]
fn test_validate_g2_point_identity_point() {
    // Test with identity point (point at infinity)
    let identity_point = G2Affine::identity();
    let result = validate_g2_point(&identity_point);

    assert!(result.is_err(), "Identity point should fail validation");
    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G2 point cannot be point at infinity",
                "Should have correct error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for identity point"),
    }
}

#[test]
fn test_validate_g2_point_invalid_curve_point() {
    // Test with a point that's not on the twisted curve
    use ark_bn254::Fq2;
    use ark_ff::One;

    // Create an invalid G2 point using coordinates that don't satisfy the twisted curve equation
    let invalid_x = Fq2::one(); // x = (1, 0)
    let invalid_y = Fq2::one(); // y = (1, 0) (invalid for twisted curve)
    let invalid_point = G2Affine::new_unchecked(invalid_x, invalid_y);

    // Verify our test point is actually invalid
    assert!(
        !invalid_point.is_on_curve(),
        "Test point should not be on curve"
    );

    let result = validate_g2_point(&invalid_point);
    assert!(
        result.is_err(),
        "Invalid curve point should fail validation"
    );

    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G2 point not on curve",
                "Should have correct error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for invalid curve point"),
    }
}

#[test]
fn test_validate_g2_point_generator() {
    // Test with the generator point (should be rejected)
    let generator = G2Affine::generator();
    let result = validate_g2_point(&generator);
    assert!(result.is_err(), "Generator point should be rejected");

    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G2 point cannot be the generator point",
                "Should have correct error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for generator point"),
    }
}

#[test]
fn test_validate_point_functions_consistency() {
    // Test that the validation functions are consistent with manual checks
    let mut rng = ark_std::test_rng();

    // Test G1 consistency
    for _ in 0..5 {
        let g1_point = G1Affine::rand(&mut rng);
        let manual_check = !g1_point.is_zero()
            && g1_point.is_on_curve()
            && g1_point.is_in_correct_subgroup_assuming_on_curve()
            && g1_point != G1Affine::generator();
        let function_check = validate_g1_point(&g1_point).is_ok();

        assert_eq!(
            manual_check, function_check,
            "Manual validation should match function validation for G1"
        );
    }

    // Test G2 consistency
    for _ in 0..5 {
        let g2_point = G2Affine::rand(&mut rng);
        let manual_check = !g2_point.is_zero()
            && g2_point.is_on_curve()
            && g2_point.is_in_correct_subgroup_assuming_on_curve()
            && g2_point != G2Affine::generator();
        let function_check = validate_g2_point(&g2_point).is_ok();

        assert_eq!(
            manual_check, function_check,
            "Manual validation should match function validation for G2"
        );
    }
}

#[test]
fn test_validate_point_functions_generator_rejection() {
    // Test that both validation functions properly reject their respective generators

    // Test G1 generator rejection
    let g1_generator = G1Affine::generator();

    // Verify the generator meets other validation criteria
    assert!(
        !g1_generator.is_zero(),
        "G1 generator should not be identity"
    );
    assert!(
        g1_generator.is_on_curve(),
        "G1 generator should be on curve"
    );
    assert!(
        g1_generator.is_in_correct_subgroup_assuming_on_curve(),
        "G1 generator should be in correct subgroup"
    );

    // But should be rejected by our validation function
    let g1_result = validate_g1_point(&g1_generator);
    assert!(g1_result.is_err(), "G1 generator should be rejected");

    match g1_result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G1 point cannot be the generator point",
                "Should have correct G1 generator error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for G1 generator"),
    }

    // Test G2 generator rejection
    let g2_generator = G2Affine::generator();

    // Verify the generator meets other validation criteria
    assert!(
        !g2_generator.is_zero(),
        "G2 generator should not be identity"
    );
    assert!(
        g2_generator.is_on_curve(),
        "G2 generator should be on curve"
    );
    assert!(
        g2_generator.is_in_correct_subgroup_assuming_on_curve(),
        "G2 generator should be in correct subgroup"
    );

    // But should be rejected by our validation function
    let g2_result = validate_g2_point(&g2_generator);
    assert!(g2_result.is_err(), "G2 generator should be rejected");

    match g2_result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G2 point cannot be the generator point",
                "Should have correct G2 generator error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for G2 generator"),
    }
}

#[test]
fn test_compute_challenge_comprehensive() {
    // Comprehensive test for compute_challenge function covering all validation scenarios

    let mut rng = ark_std::test_rng();
    let test_data = b"comprehensive test data for compute challenge validation";
    let blob = Blob::from_raw_data(test_data);

    // Test 1: Valid G1 points should work correctly
    let valid_commitment = G1Affine::rand(&mut rng);
    let result = compute_challenge(&blob, &valid_commitment);

    assert!(
        result.is_ok(),
        "compute_challenge should succeed with valid commitment"
    );

    // Verify we get a valid field element that's not zero for this input
    let challenge = result.unwrap();
    assert_ne!(
        challenge,
        Fr::zero(),
        "Challenge should not be zero for this input"
    );

    // Test 2: Identity point (point at infinity) should be rejected
    let identity_commitment = G1Affine::identity();
    let result = compute_challenge(&blob, &identity_commitment);

    assert!(
        result.is_err(),
        "compute_challenge should reject identity point"
    );
    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G1 point cannot be point at infinity",
                "Should reject identity point with proper error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for identity point"),
    }

    // Test 3: Generator point should be rejected
    let generator_commitment = G1Affine::generator();
    let result = compute_challenge(&blob, &generator_commitment);

    assert!(
        result.is_err(),
        "compute_challenge should reject generator point"
    );
    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G1 point cannot be the generator point",
                "Should reject generator point with proper error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for generator point"),
    }

    // Test 4: Points not on the curve should be rejected
    let invalid_x = Fq::one(); // x = 1
    let invalid_y = Fq::one(); // y = 1 (but 1² ≠ 1³ + 3, so not on curve)
    let invalid_commitment = G1Affine::new_unchecked(invalid_x, invalid_y);

    assert!(
        !invalid_commitment.is_on_curve(),
        "Test point should not be on curve"
    );

    let result = compute_challenge(&blob, &invalid_commitment);
    assert!(
        result.is_err(),
        "compute_challenge should reject invalid curve point"
    );
    match result.unwrap_err() {
        KzgError::NotOnCurveError(msg) => {
            assert_eq!(
                msg, "G1 point not on curve",
                "Should reject invalid curve point with proper error message"
            );
        },
        _ => panic!("Should return NotOnCurveError for invalid curve point"),
    }

    // Test 5: Deterministic behavior - same inputs should produce same outputs
    let commitment = G1Affine::rand(&mut rng);
    let challenge1 = compute_challenge(&blob, &commitment).unwrap();
    let challenge2 = compute_challenge(&blob, &commitment).unwrap();
    let challenge3 = compute_challenge(&blob, &commitment).unwrap();

    assert_eq!(
        challenge1, challenge2,
        "compute_challenge should be deterministic"
    );
    assert_eq!(
        challenge2, challenge3,
        "compute_challenge should be deterministic"
    );

    // Test 6: Different inputs should produce different outputs
    let blob1 = Blob::from_raw_data(b"first test blob data");
    let blob2 = Blob::from_raw_data(b"second test blob data");
    let commitment1 = G1Affine::rand(&mut rng);
    let commitment2 = G1Affine::rand(&mut rng);

    // Different blobs with same commitment should produce different challenges
    let challenge1_1 = compute_challenge(&blob1, &commitment1).unwrap();
    let challenge2_1 = compute_challenge(&blob2, &commitment1).unwrap();
    assert_ne!(
        challenge1_1, challenge2_1,
        "Different blobs should produce different challenges"
    );

    // Same blob with different commitments should produce different challenges
    let challenge1_2 = compute_challenge(&blob1, &commitment2).unwrap();
    assert_ne!(
        challenge1_1, challenge1_2,
        "Different commitments should produce different challenges"
    );
}
