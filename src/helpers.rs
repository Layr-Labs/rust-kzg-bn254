use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AffineRepr;
use ark_ff::{sbb, BigInt, BigInteger, Field, LegendreSymbol, PrimeField};
use ark_std::{str::FromStr, vec::Vec, One, Zero};
use std::cmp;

use crate::{
    arith,
    consts::{BYTES_PER_FIELD_ELEMENT, SIZE_OF_G1_AFFINE_COMPRESSED, SIZE_OF_G2_AFFINE_COMPRESSED},
};

pub fn blob_to_polynomial(blob: &Vec<u8>) -> Vec<Fr> {
    to_fr_array(&blob)
}

pub fn set_bytes_canonical_manual(data: &[u8]) -> Fr {
    let mut arrays: [u64; 4] = Default::default(); // Initialize an array of four [u8; 8] arrays

    for (i, chunk) in data.chunks(8).enumerate() {
        arrays[i] = u64::from_be_bytes(chunk.try_into().expect("Slice with incorrect length"));
    }
    arrays.reverse();
    Fr::from_bigint(BigInt::new(arrays)).unwrap()
}

// Functions being used

pub fn convert_by_padding_empty_byte(data: &[u8]) -> Vec<u8> {
    let data_size = data.len();
    let parse_size = BYTES_PER_FIELD_ELEMENT - 1;
    let put_size = BYTES_PER_FIELD_ELEMENT;

    let data_len = (data_size + parse_size - 1) / parse_size;
    let mut valid_data = vec![0u8; data_len * put_size];
    let mut valid_end = valid_data.len();

    for i in 0..data_len {
        let start = i * parse_size;
        let mut end = (i + 1) * parse_size;
        if end > data_size {
            end = data_size;
            valid_end = end - start + 1 + i * put_size;
        }

        // Set the first byte of each chunk to 0
        valid_data[i * BYTES_PER_FIELD_ELEMENT] = 0x00;
        // Copy data from original to new vector, adjusting for the initial zero byte
        valid_data[i * BYTES_PER_FIELD_ELEMENT + 1..i * BYTES_PER_FIELD_ELEMENT + 1 + end - start]
            .copy_from_slice(&data[start..end]);
    }

    valid_data.truncate(valid_end);
    valid_data
}

pub fn remove_empty_byte_from_padded_bytes(data: &[u8]) -> Vec<u8> {
    let data_size = data.len();
    let parse_size = BYTES_PER_FIELD_ELEMENT;
    let data_len = (data_size + parse_size - 1) / parse_size;

    let put_size = BYTES_PER_FIELD_ELEMENT - 1;
    let mut valid_data = vec![0u8; data_len * put_size];
    let mut valid_len = valid_data.len();

    for i in 0..data_len {
        let start = i * parse_size + 1; // Skip the first byte which is the empty byte
        let mut end = (i + 1) * parse_size;

        if end > data_size {
            end = data_size;
            valid_len = i * put_size + end - start;
        }

        // Calculate the end of the slice in the output vector
        let output_end = i * put_size + end - start;
        valid_data[i * put_size..output_end].copy_from_slice(&data[start..end]);
    }

    valid_data.truncate(valid_len);
    valid_data
}

pub fn set_bytes_canonical(data: &[u8]) -> Fr {
    return Fr::from_be_bytes_mod_order(&data);
}

fn get_num_element(data_len: usize, symbol_size: usize) -> usize {
    (data_len + symbol_size - 1) / symbol_size
}

pub fn to_fr_array(data: &[u8]) -> Vec<Fr> {
    let num_ele = get_num_element(data.len(), BYTES_PER_FIELD_ELEMENT);
    let mut eles = vec![Fr::zero(); num_ele]; // Initialize with zero elements

    for i in 0..num_ele {
        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;
        if end > data.len() {
            let mut padded = vec![0u8; BYTES_PER_FIELD_ELEMENT];
            padded[..data.len() - start].copy_from_slice(&data[start..]);
            eles[i] = set_bytes_canonical(&padded);
        } else {
            eles[i] = set_bytes_canonical(&data[start..end]);
        }
    }
    eles
}

pub fn to_byte_array(data_fr: &[Fr], max_data_size: usize) -> Vec<u8> {
    let n = data_fr.len();
    let data_size = cmp::min(n * BYTES_PER_FIELD_ELEMENT, max_data_size);
    let mut data = vec![0u8; data_size];

    for i in 0..n {
        let v: Vec<u8> = data_fr[i].into_bigint().to_bytes_be();

        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;

        if end > max_data_size {
            let slice_end = cmp::min(v.len(), max_data_size - start);
            data[start..start + slice_end].copy_from_slice(&v[..slice_end]);
            break;
        } else {
            let actual_end = cmp::min(end, data_size);
            data[start..actual_end].copy_from_slice(&v[..actual_end - start]);
        }
    }
    data
}

pub fn is_zeroed(first_byte: u8, buf: Vec<u8>) -> bool {
    if first_byte != 0 {
        return false;
    }

    for i in 0..buf.len() {
        if buf[i] != 0 {
            return false;
        }
    }
    true
}

pub fn str_vec_to_fr_vec(input: Vec<&str>) -> Result<Vec<Fr>, &str> {
    let mut output: Vec<Fr> = Vec::<Fr>::with_capacity(input.len());

    for i in 0..input.len() {
        if input[i] == "-1" {
            let mut test = Fr::one();
            test.neg_in_place();
            output.push(test);
        } else {
            let fr_data = Fr::from_str(input[i]).expect("could not load string to Fr");
            output.push(fr_data);
        }
    }

    Ok(output)
}

pub fn lexicographically_largest(z: &Fq) -> bool {
    // This can be determined by checking to see if the element is
    // larger than (p - 1) // 2. If we subtract by ((p - 1) // 2) + 1
    // and there is no underflow, then the element must be larger than
    // (p - 1) // 2.

    // First, because self is in Montgomery form we need to reduce it
    let tmp = arith::montgomery_reduce(&z.0 .0[0], &z.0 .0[1], &z.0 .0[2], &z.0 .0[3]);
    let mut borrow: u64 = 0;

    // (_, borrow) = sbb(tmp.0, 0x9E10460B6C3E7EA4, 0);
    // (_, borrow) = sbb(tmp.1, 0xCBC0B548B438E546, borrow);
    // (_, borrow) = sbb(tmp.2, 0xDC2822DB40C0AC2E, borrow);
    // (_, borrow) = sbb(tmp.3, 0x183227397098D014, borrow);

    sbb!(tmp.0, 0x9E10460B6C3E7EA4, &mut borrow);
    sbb!(tmp.1, 0xCBC0B548B438E546, &mut borrow);
    sbb!(tmp.2, 0xDC2822DB40C0AC2E, &mut borrow);
    sbb!(tmp.3, 0x183227397098D014, &mut borrow);

    // If the element was smaller, the subtraction will underflow
    // producing a borrow value of 0xffff...ffff, otherwise it will
    // be zero. We create a Choice representing true if there was
    // overflow (and so this element is not lexicographically larger
    // than its negation) and then negate it.

    borrow == 0
}

pub fn read_g2_point_from_bytes_be(g2_bytes_be: &Vec<u8>) -> Result<G2Affine, &str> {
    if g2_bytes_be.len() != SIZE_OF_G2_AFFINE_COMPRESSED {
        return Err("not enough bytes for g2 point");
    }

    let m_mask: u8 = 0b11 << 6;
    let m_compressed_infinity: u8 = 0b01 << 6;
    let m_compressed_smallest: u8 = 0b10 << 6;
    let m_compressed_largest: u8 = 0b11 << 6;

    let m_data = g2_bytes_be[0] & m_mask;

    if m_data == m_compressed_infinity {
        if !is_zeroed(
            g2_bytes_be[0] & !m_mask,
            g2_bytes_be[1..SIZE_OF_G2_AFFINE_COMPRESSED].to_vec(),
        ) {
            return Err("point at infinity not coded properly for g2");
        }
        return Ok(G2Affine::zero());
    }

    let mut x_bytes = [0u8; SIZE_OF_G2_AFFINE_COMPRESSED];
    x_bytes.copy_from_slice(g2_bytes_be);
    x_bytes[0] &= !m_mask;
    let half_size = SIZE_OF_G2_AFFINE_COMPRESSED / 2;

    let c1 = Fq::from_be_bytes_mod_order(&x_bytes[..half_size]);
    let c0 = Fq::from_be_bytes_mod_order(&x_bytes[half_size..]);
    let x = Fq2::new(c0, c1);
    let y_squared = x * x * x;

    // this is bTwistCurveCoeff
    let twist_curve_coeff = get_b_twist_curve_coeff();

    let added_result = y_squared + twist_curve_coeff;
    if added_result.legendre() == LegendreSymbol::QuadraticNonResidue {
        return Err("invalid compressed coordinate: square root doesn't exist");
    }

    let mut y_sqrt = added_result.sqrt().ok_or("no square root found").unwrap();

    let mut lexicographical_check_result = false;

    if y_sqrt.c1.0.is_zero() {
        lexicographical_check_result = lexicographically_largest(&y_sqrt.c0);
    } else {
        lexicographical_check_result = lexicographically_largest(&y_sqrt.c1);
    }

    if lexicographical_check_result {
        if m_data == m_compressed_smallest {
            y_sqrt.neg_in_place();
        }
    } else {
        if m_data == m_compressed_largest {
            y_sqrt.neg_in_place();
        }
    }

    let point = G2Affine::new_unchecked(x, y_sqrt);
    if !point.is_in_correct_subgroup_assuming_on_curve()
        && is_on_curve_g2(&G2Projective::from(point))
    {
        return Err("point couldn't be created");
    }
    Ok(point)
}

pub fn read_g1_point_from_bytes_be(g1_bytes_be: &Vec<u8>) -> Result<G1Affine, &str> {
    if g1_bytes_be.len() != SIZE_OF_G1_AFFINE_COMPRESSED {
        return Err("not enough bytes for g1 point");
    }

    let m_mask: u8 = 0b11 << 6;
    let m_compressed_infinity: u8 = 0b01 << 6;
    let m_compressed_smallest: u8 = 0b10 << 6;
    let m_compressed_largest: u8 = 0b11 << 6;

    let m_data = g1_bytes_be[0] & m_mask;

    if m_data == m_compressed_infinity {
        if !is_zeroed(g1_bytes_be[0] & !m_mask, g1_bytes_be[1..32].to_vec()) {
            return Err("point at infinity not coded properly for g1");
        }
        return Ok(G1Affine::zero());
    }

    let mut x_bytes = [0u8; SIZE_OF_G1_AFFINE_COMPRESSED];
    x_bytes.copy_from_slice(g1_bytes_be);
    x_bytes[0] &= !m_mask;
    let x = Fq::from_be_bytes_mod_order(&x_bytes);
    let y_squared = x * x * x + Fq::from(3);
    let mut y_sqrt = y_squared.sqrt().ok_or("no item1").unwrap();

    if lexicographically_largest(&y_sqrt) {
        if m_data == m_compressed_smallest {
            y_sqrt.neg_in_place();
        }
    } else {
        if m_data == m_compressed_largest {
            y_sqrt.neg_in_place();
        }
    }
    let point = G1Affine::new_unchecked(x, y_sqrt);
    if !point.is_in_correct_subgroup_assuming_on_curve()
        && is_on_curve_g1(&G1Projective::from(point))
    {
        return Err("point couldn't be created");
    }
    Ok(point)
}

fn get_b_twist_curve_coeff() -> Fq2 {
    let twist_c0 = Fq::from(9);
    let twist_c1 = Fq::from(1);

    // this is bTwistCurveCoeff
    let mut twist_curve_coeff = Fq2::new(twist_c0, twist_c1);
    twist_curve_coeff = *twist_curve_coeff.inverse_in_place().unwrap();

    twist_curve_coeff.c0 = twist_curve_coeff.c0 * Fq::from(3);
    twist_curve_coeff.c1 = twist_curve_coeff.c1 * Fq::from(3);
    twist_curve_coeff
}

pub fn is_on_curve_g1(g1: &G1Projective) -> bool {
    let b_curve_coeff: Fq = Fq::from_str("3").unwrap();

    let mut left = g1.y;
    left.square_in_place();

    let mut right = g1.x;
    right.square_in_place();
    right *= &g1.x;

    let mut tmp = g1.z;
    tmp.square_in_place();
    tmp.square_in_place();
    tmp *= &g1.z;
    tmp *= &g1.z;
    tmp *= b_curve_coeff;
    right += &tmp;
    left == right
}

pub fn is_on_curve_g2(g2: &G2Projective) -> bool {
    let mut left = g2.y;
    left.square_in_place();

    let mut right = g2.x;
    right.square_in_place();
    right *= &g2.x;

    let mut tmp = g2.z;
    tmp.square_in_place();
    tmp.square_in_place();
    tmp *= &g2.z;
    tmp *= &g2.z;
    tmp *= &get_b_twist_curve_coeff();
    right += &tmp;
    left == right
}

#[test]
fn test_g1_is_on_curve() {
    use ark_ff::UniformRand;
    use rand::thread_rng;

    let rng = &mut thread_rng();
    for _ in 0..1000 {
        let point = G1Affine::rand(rng);
        assert_eq!(is_on_curve_g1(&G1Projective::from(point)), true);
        let mut not_on_curve = point;
        not_on_curve.x += Fq::one();
        assert_eq!(is_on_curve_g1(&G1Projective::from(not_on_curve)), false);
    }
}

#[test]
fn test_g2_is_on_curve() {
    use ark_ff::UniformRand;
    use rand::thread_rng;

    let rng = &mut thread_rng();
    for _ in 0..1000 {
        let point = G2Affine::rand(rng);
        assert_eq!(is_on_curve_g2(&G2Projective::from(point)), true);
        let mut not_on_curve = point;
        not_on_curve.x += Fq2::one();
        assert_eq!(is_on_curve_g2(&G2Projective::from(not_on_curve)), false);
    }
}
// Loads data from files. This data was generated by gnark and is DA compatible.
// Tests deserialization of data and equivalence.
#[test]
fn test_blob_to_polynomial() {
    use ark_serialize::Read;
    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };

    let file = File::open("src/test-files/blobs.txt").unwrap();
    let mut reader = BufReader::new(file);
    let mut buffer = vec![0u8; SIZE_OF_G1_AFFINE_COMPRESSED];
    let mut read_fr_from_bytes: Vec<Fr> = vec![];
    let mut fr_from_str_vec: Vec<Fr> = vec![];

    // Loop to read the file 32 bytes at a time
    loop {
        match reader.read(&mut buffer[..]) {
            Ok(0) => {
                // No more data to read
                break;
            }
            Ok(n) => {
                // Process the chunk of data just read
                read_fr_from_bytes.push(Fr::from_be_bytes_mod_order(&buffer[..n]))
            }
            Err(e) => panic!("{}", e),
        }
    }

    let file2 = File::open("src/test-files/blobs-from-fr.txt").unwrap();
    let reader2 = BufReader::new(file2);
    for (i, line) in reader2.lines().enumerate() {
        let line = line.unwrap();
        let trimmed_line = line.trim_end(); // Trim whitespace from the end
        let the_strings_str: Vec<&str> = trimmed_line.split(',').collect(); // Split the line on commas
        let fr_from_str = Fr::from_str(the_strings_str[0]).expect("should be fine");
        fr_from_str_vec.push(fr_from_str);
        assert_eq!(fr_from_str, read_fr_from_bytes[i]);
    }

    let mut file3 = File::open("src/test-files/blobs.txt").unwrap();
    let mut contents = Vec::new();
    file3.read_to_end(&mut contents).unwrap();

    assert_eq!(fr_from_str_vec, blob_to_polynomial(&contents));
}

#[test]
fn test_to_fr_array() {
    use crate::consts::GETTYSBURG_ADDRESS_BYTES;
    let converted = convert_by_padding_empty_byte(
        vec![
            42, 212, 238, 227, 192, 237, 178, 128, 19, 108, 50, 204, 87, 81, 63, 120, 232, 27, 116,
            108, 74, 168, 109, 84, 89, 9, 6, 233, 144, 200, 125, 40,
        ]
        .as_slice(),
    );
    let data_fr = to_fr_array(&converted);
    let result = to_byte_array(&data_fr, converted.len().try_into().unwrap());
    assert_eq!(converted, result, "should be deserialized properly");

    let ga_converted = convert_by_padding_empty_byte(GETTYSBURG_ADDRESS_BYTES);
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
fn test_convert_by_padding_empty_byte() {
    let mut padded_data = convert_by_padding_empty_byte("hi".as_bytes());
    assert_eq!(padded_data, vec![0, 104, 105], "testing adding padding");

    let mut unpadded_data = remove_empty_byte_from_padded_bytes(&padded_data);
    assert_eq!(unpadded_data, vec![104, 105], "testing removing padding");

    let long_string = "Fourscore and seven years ago our fathers brought forth, on this continent, a new nation, conceived in liberty, and dedicated to the proposition that all men are created equal. Now we are engaged in a great civil war, testing whether that nation, or any nation so conceived, and so dedicated, can long endure. We are met on a great battle-field of that war. We have come to dedicate a portion of that field, as a final resting-place for those who here gave their lives, that that nation might live. It is altogether fitting and proper that we should do this. But, in a larger sense, we cannot dedicate, we cannot consecrate—we cannot hallow—this ground. The brave men, living and dead, who struggled here, have consecrated it far above our poor power to add or detract. The world will little note, nor long remember what we say here, but it can never forget what they did here. It is for us the living, rather, to be dedicated here to the unfinished work which they who fought here have thus far so nobly advanced. It is rather for us to be here dedicated to the great task remaining before us—that from these honored dead we take increased devotion to that cause for which they here gave the last full measure of devotion—that we here highly resolve that these dead shall not have died in vain—that this nation, under God, shall have a new birth of freedom, and that government of the people, by the people, for the people, shall not perish from the earth.".as_bytes();
    let result: Vec<u8> = vec![
        0, 70, 111, 117, 114, 115, 99, 111, 114, 101, 32, 97, 110, 100, 32, 115, 101, 118, 101,
        110, 32, 121, 101, 97, 114, 115, 32, 97, 103, 111, 32, 111, 0, 117, 114, 32, 102, 97, 116,
        104, 101, 114, 115, 32, 98, 114, 111, 117, 103, 104, 116, 32, 102, 111, 114, 116, 104, 44,
        32, 111, 110, 32, 116, 104, 0, 105, 115, 32, 99, 111, 110, 116, 105, 110, 101, 110, 116,
        44, 32, 97, 32, 110, 101, 119, 32, 110, 97, 116, 105, 111, 110, 44, 32, 99, 111, 110, 0,
        99, 101, 105, 118, 101, 100, 32, 105, 110, 32, 108, 105, 98, 101, 114, 116, 121, 44, 32,
        97, 110, 100, 32, 100, 101, 100, 105, 99, 97, 116, 101, 0, 100, 32, 116, 111, 32, 116, 104,
        101, 32, 112, 114, 111, 112, 111, 115, 105, 116, 105, 111, 110, 32, 116, 104, 97, 116, 32,
        97, 108, 108, 32, 109, 0, 101, 110, 32, 97, 114, 101, 32, 99, 114, 101, 97, 116, 101, 100,
        32, 101, 113, 117, 97, 108, 46, 32, 78, 111, 119, 32, 119, 101, 32, 97, 114, 0, 101, 32,
        101, 110, 103, 97, 103, 101, 100, 32, 105, 110, 32, 97, 32, 103, 114, 101, 97, 116, 32, 99,
        105, 118, 105, 108, 32, 119, 97, 114, 44, 0, 32, 116, 101, 115, 116, 105, 110, 103, 32,
        119, 104, 101, 116, 104, 101, 114, 32, 116, 104, 97, 116, 32, 110, 97, 116, 105, 111, 110,
        44, 32, 111, 0, 114, 32, 97, 110, 121, 32, 110, 97, 116, 105, 111, 110, 32, 115, 111, 32,
        99, 111, 110, 99, 101, 105, 118, 101, 100, 44, 32, 97, 110, 100, 32, 0, 115, 111, 32, 100,
        101, 100, 105, 99, 97, 116, 101, 100, 44, 32, 99, 97, 110, 32, 108, 111, 110, 103, 32, 101,
        110, 100, 117, 114, 101, 46, 32, 0, 87, 101, 32, 97, 114, 101, 32, 109, 101, 116, 32, 111,
        110, 32, 97, 32, 103, 114, 101, 97, 116, 32, 98, 97, 116, 116, 108, 101, 45, 102, 105, 0,
        101, 108, 100, 32, 111, 102, 32, 116, 104, 97, 116, 32, 119, 97, 114, 46, 32, 87, 101, 32,
        104, 97, 118, 101, 32, 99, 111, 109, 101, 32, 116, 0, 111, 32, 100, 101, 100, 105, 99, 97,
        116, 101, 32, 97, 32, 112, 111, 114, 116, 105, 111, 110, 32, 111, 102, 32, 116, 104, 97,
        116, 32, 102, 105, 0, 101, 108, 100, 44, 32, 97, 115, 32, 97, 32, 102, 105, 110, 97, 108,
        32, 114, 101, 115, 116, 105, 110, 103, 45, 112, 108, 97, 99, 101, 32, 102, 0, 111, 114, 32,
        116, 104, 111, 115, 101, 32, 119, 104, 111, 32, 104, 101, 114, 101, 32, 103, 97, 118, 101,
        32, 116, 104, 101, 105, 114, 32, 108, 105, 0, 118, 101, 115, 44, 32, 116, 104, 97, 116, 32,
        116, 104, 97, 116, 32, 110, 97, 116, 105, 111, 110, 32, 109, 105, 103, 104, 116, 32, 108,
        105, 118, 0, 101, 46, 32, 73, 116, 32, 105, 115, 32, 97, 108, 116, 111, 103, 101, 116, 104,
        101, 114, 32, 102, 105, 116, 116, 105, 110, 103, 32, 97, 110, 100, 0, 32, 112, 114, 111,
        112, 101, 114, 32, 116, 104, 97, 116, 32, 119, 101, 32, 115, 104, 111, 117, 108, 100, 32,
        100, 111, 32, 116, 104, 105, 115, 46, 0, 32, 66, 117, 116, 44, 32, 105, 110, 32, 97, 32,
        108, 97, 114, 103, 101, 114, 32, 115, 101, 110, 115, 101, 44, 32, 119, 101, 32, 99, 97,
        110, 0, 110, 111, 116, 32, 100, 101, 100, 105, 99, 97, 116, 101, 44, 32, 119, 101, 32, 99,
        97, 110, 110, 111, 116, 32, 99, 111, 110, 115, 101, 99, 114, 0, 97, 116, 101, 226, 128,
        148, 119, 101, 32, 99, 97, 110, 110, 111, 116, 32, 104, 97, 108, 108, 111, 119, 226, 128,
        148, 116, 104, 105, 115, 32, 103, 0, 114, 111, 117, 110, 100, 46, 32, 84, 104, 101, 32, 98,
        114, 97, 118, 101, 32, 109, 101, 110, 44, 32, 108, 105, 118, 105, 110, 103, 32, 97, 110, 0,
        100, 32, 100, 101, 97, 100, 44, 32, 119, 104, 111, 32, 115, 116, 114, 117, 103, 103, 108,
        101, 100, 32, 104, 101, 114, 101, 44, 32, 104, 97, 118, 0, 101, 32, 99, 111, 110, 115, 101,
        99, 114, 97, 116, 101, 100, 32, 105, 116, 32, 102, 97, 114, 32, 97, 98, 111, 118, 101, 32,
        111, 117, 114, 32, 0, 112, 111, 111, 114, 32, 112, 111, 119, 101, 114, 32, 116, 111, 32,
        97, 100, 100, 32, 111, 114, 32, 100, 101, 116, 114, 97, 99, 116, 46, 32, 84, 0, 104, 101,
        32, 119, 111, 114, 108, 100, 32, 119, 105, 108, 108, 32, 108, 105, 116, 116, 108, 101, 32,
        110, 111, 116, 101, 44, 32, 110, 111, 114, 32, 0, 108, 111, 110, 103, 32, 114, 101, 109,
        101, 109, 98, 101, 114, 32, 119, 104, 97, 116, 32, 119, 101, 32, 115, 97, 121, 32, 104,
        101, 114, 101, 44, 0, 32, 98, 117, 116, 32, 105, 116, 32, 99, 97, 110, 32, 110, 101, 118,
        101, 114, 32, 102, 111, 114, 103, 101, 116, 32, 119, 104, 97, 116, 32, 116, 0, 104, 101,
        121, 32, 100, 105, 100, 32, 104, 101, 114, 101, 46, 32, 73, 116, 32, 105, 115, 32, 102,
        111, 114, 32, 117, 115, 32, 116, 104, 101, 32, 0, 108, 105, 118, 105, 110, 103, 44, 32,
        114, 97, 116, 104, 101, 114, 44, 32, 116, 111, 32, 98, 101, 32, 100, 101, 100, 105, 99, 97,
        116, 101, 100, 0, 32, 104, 101, 114, 101, 32, 116, 111, 32, 116, 104, 101, 32, 117, 110,
        102, 105, 110, 105, 115, 104, 101, 100, 32, 119, 111, 114, 107, 32, 119, 104, 0, 105, 99,
        104, 32, 116, 104, 101, 121, 32, 119, 104, 111, 32, 102, 111, 117, 103, 104, 116, 32, 104,
        101, 114, 101, 32, 104, 97, 118, 101, 32, 116, 0, 104, 117, 115, 32, 102, 97, 114, 32, 115,
        111, 32, 110, 111, 98, 108, 121, 32, 97, 100, 118, 97, 110, 99, 101, 100, 46, 32, 73, 116,
        32, 105, 0, 115, 32, 114, 97, 116, 104, 101, 114, 32, 102, 111, 114, 32, 117, 115, 32, 116,
        111, 32, 98, 101, 32, 104, 101, 114, 101, 32, 100, 101, 100, 105, 0, 99, 97, 116, 101, 100,
        32, 116, 111, 32, 116, 104, 101, 32, 103, 114, 101, 97, 116, 32, 116, 97, 115, 107, 32,
        114, 101, 109, 97, 105, 110, 105, 0, 110, 103, 32, 98, 101, 102, 111, 114, 101, 32, 117,
        115, 226, 128, 148, 116, 104, 97, 116, 32, 102, 114, 111, 109, 32, 116, 104, 101, 115, 101,
        32, 0, 104, 111, 110, 111, 114, 101, 100, 32, 100, 101, 97, 100, 32, 119, 101, 32, 116, 97,
        107, 101, 32, 105, 110, 99, 114, 101, 97, 115, 101, 100, 32, 0, 100, 101, 118, 111, 116,
        105, 111, 110, 32, 116, 111, 32, 116, 104, 97, 116, 32, 99, 97, 117, 115, 101, 32, 102,
        111, 114, 32, 119, 104, 105, 99, 0, 104, 32, 116, 104, 101, 121, 32, 104, 101, 114, 101,
        32, 103, 97, 118, 101, 32, 116, 104, 101, 32, 108, 97, 115, 116, 32, 102, 117, 108, 108,
        32, 0, 109, 101, 97, 115, 117, 114, 101, 32, 111, 102, 32, 100, 101, 118, 111, 116, 105,
        111, 110, 226, 128, 148, 116, 104, 97, 116, 32, 119, 101, 32, 104, 0, 101, 114, 101, 32,
        104, 105, 103, 104, 108, 121, 32, 114, 101, 115, 111, 108, 118, 101, 32, 116, 104, 97, 116,
        32, 116, 104, 101, 115, 101, 32, 100, 0, 101, 97, 100, 32, 115, 104, 97, 108, 108, 32, 110,
        111, 116, 32, 104, 97, 118, 101, 32, 100, 105, 101, 100, 32, 105, 110, 32, 118, 97, 105,
        110, 0, 226, 128, 148, 116, 104, 97, 116, 32, 116, 104, 105, 115, 32, 110, 97, 116, 105,
        111, 110, 44, 32, 117, 110, 100, 101, 114, 32, 71, 111, 100, 44, 0, 32, 115, 104, 97, 108,
        108, 32, 104, 97, 118, 101, 32, 97, 32, 110, 101, 119, 32, 98, 105, 114, 116, 104, 32, 111,
        102, 32, 102, 114, 101, 101, 0, 100, 111, 109, 44, 32, 97, 110, 100, 32, 116, 104, 97, 116,
        32, 103, 111, 118, 101, 114, 110, 109, 101, 110, 116, 32, 111, 102, 32, 116, 104, 101, 0,
        32, 112, 101, 111, 112, 108, 101, 44, 32, 98, 121, 32, 116, 104, 101, 32, 112, 101, 111,
        112, 108, 101, 44, 32, 102, 111, 114, 32, 116, 104, 101, 0, 32, 112, 101, 111, 112, 108,
        101, 44, 32, 115, 104, 97, 108, 108, 32, 110, 111, 116, 32, 112, 101, 114, 105, 115, 104,
        32, 102, 114, 111, 109, 32, 0, 116, 104, 101, 32, 101, 97, 114, 116, 104, 46,
    ];

    padded_data = convert_by_padding_empty_byte(long_string);
    assert_eq!(padded_data, result, "testing adding padding");

    unpadded_data = remove_empty_byte_from_padded_bytes(&padded_data);

    assert_eq!(unpadded_data, long_string, "testing adding padding");
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_read_g2_point_from_bytes_be_errors() {
        // Case where the buffer is empty and the first byte is non-zero
        let binding = vec![];
        let result = read_g2_point_from_bytes_be(&binding);
        assert_eq!(result, Err("not enough bytes for g2 point"));
    }
}
