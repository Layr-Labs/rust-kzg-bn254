use ark_bn254::{Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{sbb, BigInt, BigInteger, Field, LegendreSymbol, PrimeField};
use ark_std::{str::FromStr, vec::Vec, One, Zero};
use crossbeam_channel::Receiver;
use std::cmp;

use crate::{
    arith,
    consts::{
        Endianness, BYTES_PER_FIELD_ELEMENT, KZG_ENDIANNESS, SIZE_OF_G1_AFFINE_COMPRESSED,
        SIZE_OF_G2_AFFINE_COMPRESSED,
    },
    errors::KzgError,
    traits::ReadPointFromBytes,
};
use ark_ec::AdditiveGroup;

pub fn blob_to_polynomial(blob: &[u8]) -> Vec<Fr> {
    to_fr_array(blob)
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

pub fn remove_empty_byte_from_padded_bytes_unchecked(data: &[u8]) -> Vec<u8> {
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
    Fr::from_be_bytes_mod_order(data)
}

pub fn get_num_element(data_len: usize, symbol_size: usize) -> usize {
    (data_len + symbol_size - 1) / symbol_size
}

pub fn to_fr_array(data: &[u8]) -> Vec<Fr> {
    let num_ele = get_num_element(data.len(), BYTES_PER_FIELD_ELEMENT);
    let mut eles = vec![Fr::zero(); num_ele]; // Initialize with zero elements

    for (i, element) in eles.iter_mut().enumerate().take(num_ele) {
        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;
        if end > data.len() {
            let mut padded = vec![0u8; BYTES_PER_FIELD_ELEMENT];
            padded[..data.len() - start].copy_from_slice(&data[start..]);
            *element = set_bytes_canonical(&padded);
        } else {
            *element = set_bytes_canonical(&data[start..end]);
        }
    }
    eles
}

pub fn to_byte_array(data_fr: &[Fr], max_data_size: usize) -> Vec<u8> {
    // Calculate the number of field elements in input
    let n = data_fr.len();

    // Calculate actual data size as minimum of:
    // - Total size needed for all elements (n * bytes per element)
    // - Maximum allowed size
    let data_size = cmp::min(n * BYTES_PER_FIELD_ELEMENT, max_data_size);

    // Initialize output buffer with zeros
    // Size is determined by data_size calculation above
    let mut data = vec![0u8; data_size];

    // Iterate through each field element
    // Using enumerate().take(n) to process elements up to n
    for (i, element) in data_fr.iter().enumerate().take(n) {
        // Convert field element to bytes based on configured endianness
        let v: Vec<u8> = match KZG_ENDIANNESS {
            Endianness::Big => element.into_bigint().to_bytes_be(), // Big-endian conversion
            Endianness::Little => element.into_bigint().to_bytes_le(), // Little-endian conversion
        };

        // Calculate start and end indices for this element in output buffer
        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;

        if end > max_data_size {
            // Handle case where this element would exceed max_data_size
            // Calculate how many bytes we can actually copy
            let slice_end = cmp::min(v.len(), max_data_size - start);

            // Copy partial element and break the loop
            // We can't fit any more complete elements
            data[start..start + slice_end].copy_from_slice(&v[..slice_end]);
            break;
        } else {
            // Normal case: element fits within max_data_size
            // Calculate actual end index considering data_size limit
            let actual_end = cmp::min(end, data_size);

            // Copy element bytes to output buffer
            // Only copy up to actual_end in case this is the last partial element
            data[start..actual_end].copy_from_slice(&v[..actual_end - start]);
        }
    }

    data
}

pub fn is_zeroed(first_byte: u8, buf: Vec<u8>) -> bool {
    if first_byte != 0 {
        return false;
    }

    for byte in &buf {
        if *byte != 0 {
            return false;
        }
    }
    true
}

pub fn str_vec_to_fr_vec(input: Vec<&str>) -> Result<Vec<Fr>, &str> {
    let mut output: Vec<Fr> = Vec::<Fr>::with_capacity(input.len());

    for element in &input {
        if *element == "-1" {
            let mut test = Fr::one();
            test.neg_in_place();
            output.push(test);
        } else {
            let fr_data = Fr::from_str(element).expect("could not load string to Fr");
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

pub fn read_g2_point_from_bytes_be(g2_bytes_be: &[u8]) -> Result<G2Affine, &str> {
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

    let lexicographical_check_result = if y_sqrt.c1.0.is_zero() {
        lexicographically_largest(&y_sqrt.c0)
    } else {
        lexicographically_largest(&y_sqrt.c1)
    };

    if lexicographical_check_result {
        if m_data == m_compressed_smallest {
            y_sqrt.neg_in_place();
        }
    } else if m_data == m_compressed_largest {
        y_sqrt.neg_in_place();
    }

    let point = G2Affine::new_unchecked(x, y_sqrt);
    if !point.is_in_correct_subgroup_assuming_on_curve()
        && is_on_curve_g2(&G2Projective::from(point))
    {
        return Err("point couldn't be created");
    }
    Ok(point)
}

pub fn read_g1_point_from_bytes_be(g1_bytes_be: &[u8]) -> Result<G1Affine, &str> {
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
    } else if m_data == m_compressed_largest {
        y_sqrt.neg_in_place();
    }
    let point = G1Affine::new_unchecked(x, y_sqrt);
    if !point.is_in_correct_subgroup_assuming_on_curve()
        && is_on_curve_g1(&G1Projective::from(point))
    {
        return Err("point couldn't be created");
    }
    Ok(point)
}

pub fn process_chunks<T>(receiver: Receiver<(Vec<u8>, usize, bool)>) -> Vec<(T, usize)>
where
    T: ReadPointFromBytes,
{
    // TODO: should we use rayon to process this in parallel?
    receiver
        .iter()
        .map(|(chunk, position, is_native)| {
            let point: T = if is_native {
                T::read_point_from_bytes_native_compressed(&chunk)
                    .expect("Failed to read point from bytes")
            } else {
                T::read_point_from_bytes_be(&chunk).expect("Failed to read point from bytes")
            };
            (point, position)
        })
        .collect()
}

fn get_b_twist_curve_coeff() -> Fq2 {
    let twist_c0 = Fq::from(9);
    let twist_c1 = Fq::from(1);

    // this is bTwistCurveCoeff
    let mut twist_curve_coeff = Fq2::new(twist_c0, twist_c1);
    twist_curve_coeff = *twist_curve_coeff.inverse_in_place().unwrap();

    twist_curve_coeff.c0 *= Fq::from(3);
    twist_curve_coeff.c1 *= Fq::from(3);
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

/// Computes powers of a field element up to a given exponent.
///
/// For a given field element x, computes [1, x, x², x³, ..., x^(count-1)]
///
/// # Arguments
/// * `base` - The field element to compute powers of
/// * `count` - The number of powers to compute (0 to count-1)
///
/// # Returns
/// * Vector of field elements containing powers: [x⁰, x¹, x², ..., x^(count-1)]
pub fn compute_powers(base: &Fr, count: usize) -> Vec<Fr> {
    // Pre-allocate vector to avoid reallocations
    let mut powers = Vec::with_capacity(count);

    // Start with x⁰ = 1
    let mut current = Fr::one();

    // Compute successive powers by multiplying by base
    for _ in 0..count {
        // Add current power to vector
        powers.push(current);
        // Compute next power: x^(i+1) = x^i * x
        current *= base;
    }

    powers
}

/// Computes a linear combination of G1 points weighted by scalar coefficients.
///
/// Given points P₁, P₂, ..., Pₙ and scalars s₁, s₂, ..., sₙ
/// Computes: s₁P₁ + s₂P₂ + ... + sₙPₙ
/// Uses Multi-Scalar Multiplication (MSM) for efficient computation.
///
/// # Arguments
/// * `points` - Array of G1 points in affine form
/// * `scalars` - Array of field elements as scalar weights
///
/// # Returns
/// * Single G1 point in affine form representing the linear combination
pub fn g1_lincomb(points: &[G1Affine], scalars: &[Fr]) -> Result<G1Affine, KzgError> {
    // Use MSM (Multi-Scalar Multiplication) for efficient linear combination
    // MSM is much faster than naive point addition and scalar multiplication
    let lincomb =
        G1Projective::msm(points, scalars).map_err(|e| KzgError::MsmError(e.to_string()))?;

    // Convert result back to affine coordinates
    // This is typically needed as most protocols expect points in affine form
    Ok(lincomb.into_affine())
}
