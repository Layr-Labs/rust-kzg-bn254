use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::AdditiveGroup;
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{sbb, BigInt, BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::format;
use ark_std::{str::FromStr, vec, vec::Vec, One, Zero};

use libm::log2;
use num_traits::ToPrimitive;

extern crate alloc;
use alloc::string::ToString;
use core::cmp;
use sha2::{Digest, Sha256};

use crate::{
    arith,
    blob::Blob,
    consts::{
        BYTES_PER_FIELD_ELEMENT, FIAT_SHAMIR_PROTOCOL_DOMAIN, MAINNET_SRS_G1_SIZE,
        PRIMITIVE_ROOTS_OF_UNITY, SIZE_OF_G1_AFFINE_COMPRESSED,
    },
    errors::KzgError,
    polynomial::PolynomialEvalForm,
};

pub fn blob_to_polynomial(blob: &[u8]) -> Vec<Fr> {
    to_fr_array(blob)
}

pub fn set_bytes_canonical_manual(data: &[u8]) -> Fr {
    if data.len() != 32 {
        return Fr::zero();
    }

    let mut arrays: [u64; 4] = Default::default(); // Initialize an array of four [u8; 8] arrays

    for (i, chunk) in data.chunks(8).enumerate() {
        arrays[i] = u64::from_be_bytes(chunk.try_into().expect("Slice with incorrect length"));
    }
    arrays.reverse();
    Fr::from_bigint(BigInt::new(arrays)).expect("valid field element")
}

// Functions being used

/// Copies the referenced bytes array argument into a Vec, inserting an empty
/// byte at the front of every 31 bytes. The empty byte is padded at the low
/// address, because we use big endian to interpret a field element.
/// This ensures every 32 bytes is within the valid range of a field element for
/// the bn254 curve. If the input data is not a multiple of 31 bytes, the
/// remainder is added to the output by inserting a 0 and the remainder. The
/// output is thus not necessarily a multiple of 32.
/// Note: this function is not used in the codebase, but is kept for reference and is replaced by pad_payload
pub fn convert_by_padding_empty_byte(data: &[u8]) -> Vec<u8> {
    let data_size = data.len();
    let parse_size = BYTES_PER_FIELD_ELEMENT - 1;
    let put_size = BYTES_PER_FIELD_ELEMENT;

    let data_len = data_size.div_ceil(parse_size);
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

/// Removes the first byte from each 32-byte chunk in a byte slice (including the last potentially incomplete one).
///
/// This function is the reverse of `convert_by_padding_empty_byte`. It takes a byte slice that it assumed contains
/// field elements, where each complete field element is 32 bytes and begins with an empty padding byte
/// that needs to be removed. The final element may be smaller than 32 bytes, but should also be 0-byte prefixed.
///
/// # Arguments
/// * `data` - 0-byte prefixed big-endian encoded 32-byte chunks representing bn254 field elements. The final element may be shorter.
///
/// # Returns
/// A new `Vec<u8>` with the first byte of each field element removed. For complete elements,
/// this removes one byte per 32 bytes. For the final partial element (if any), it still
/// removes the first byte.
///
/// # Safety
/// This function is marked "unchecked" because it assumes without verification that:
/// * The input contains bn254-encoded field elements are exactly 32 bytes
/// * The first byte of each field element is safe to remove
///
/// # Example
/// ```text
/// [0, 1, 2, 3, ..., 31, 0, 1, 2, 3] -> [1, 2, 3, ..., 31, 1, 2, 3]
/// ```
///
/// ```
/// # use rust_kzg_bn254_primitives::helpers::remove_empty_byte_from_padded_bytes_unchecked;
/// let mut input = vec![1u8; 70]; // Two complete 32-byte element plus 6 bytes
/// input[0] = 0; input[32] = 0;
///
/// let output = remove_empty_byte_from_padded_bytes_unchecked(&input);
///
/// assert_eq!(output, vec![1u8; 67]); // Two complete 31-byte element plus 5 bytes
/// ```
///
/// # Implementation Detail: this function is equivalent to this simple iterator chain:
/// ```ignore
/// data.chunks(BYTES_PER_FIELD_ELEMENT).flat_map(|chunk| &chunk[1..]).copied().collect()
/// ```
/// However, it is ~30x faster than the above because of the pre-allocation + SIMD instructions optimization.
pub fn remove_empty_byte_from_padded_bytes_unchecked(data: &[u8]) -> Vec<u8> {
    // We pre-allocate the exact size of the output vector by calculating the number
    // of zero bytes that will be removed from the input.
    let empty_bytes_to_remove = data.len().div_ceil(BYTES_PER_FIELD_ELEMENT);
    let mut output = Vec::with_capacity(data.len() - empty_bytes_to_remove);

    // We first process all the complete 32-byte chunks (representing bn254 encoded field elements).
    // We remove the first byte of each chunk, assuming (but unchecked) that it is a zero byte.
    // Note: we could use a single iterator loop, but separating like this allows the compiler to generate
    // simd instructions for this main loop, which is much faster (see https://en.wikipedia.org/wiki/Automatic_vectorization).
    for chunk in data.chunks_exact(BYTES_PER_FIELD_ELEMENT) {
        output.extend_from_slice(&chunk[1..]);
    }
    // We handle the last chunk separately, still assuming (but unchecked) that
    // it represents a zero prefixed partial field element.
    let remainder = data.chunks_exact(BYTES_PER_FIELD_ELEMENT).remainder();
    if !remainder.is_empty() {
        output.extend_from_slice(&remainder[1..]);
    }
    output
}

pub fn set_bytes_canonical(data: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(data)
}

pub fn get_num_element(data_len: usize, symbol_size: usize) -> usize {
    data_len.div_ceil(symbol_size)
}

pub fn to_fr_array(data: &[u8]) -> Vec<Fr> {
    let num_ele = get_num_element(data.len(), BYTES_PER_FIELD_ELEMENT);
    let mut eles = vec![Fr::zero(); num_ele]; // Initialize with zero elements

    for (i, element) in eles.iter_mut().enumerate().take(num_ele) {
        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;

        if end > data.len() {
            // Handle the last chunk that may be incomplete
            let mut padded = vec![0u8; BYTES_PER_FIELD_ELEMENT];
            padded[..data.len() - start].copy_from_slice(&data[start..]);
            *element = set_bytes_canonical(&padded);
        } else {
            *element = set_bytes_canonical(&data[start..end]);
        }
    }
    eles
}

/// Converts a slice of field elements to a byte array with size constraints
///
/// # Arguments
/// * `data_fr` - Slice of field elements to convert to bytes
/// * `max_output_size` - Maximum allowed size in bytes for the output buffer
///
/// # Returns
/// * `Vec<u8>` - Byte array containing the encoded field elements, truncated if needed
///
/// # Details
/// - Each field element is converted to BYTES_PER_FIELD_ELEMENT bytes
/// - Output is truncated to max_output_size if total bytes would exceed it
///
/// # Example
/// ```
/// use rust_kzg_bn254_primitives::blob::Blob;
/// use rust_kzg_bn254_primitives::helpers;

/// let input = Blob::from_raw_data(b"random data for blob");
/// helpers::calculate_roots_of_unity(input.len().try_into().unwrap()).unwrap();
/// ```
pub fn to_byte_array(data_fr: &[Fr], max_output_size: usize) -> Vec<u8> {
    // Calculate the number of field elements in input
    let n = data_fr.len();

    let data_size = cmp::min(n * BYTES_PER_FIELD_ELEMENT, max_output_size);

    let mut data = vec![0u8; data_size];

    // Iterate through each field element
    // Using enumerate().take(n) to process elements up to n
    for (i, element) in data_fr.iter().enumerate().take(n) {
        // Convert field element to bytes based on configured endianness
        let v: Vec<u8> = element.into_bigint().to_bytes_be();

        // Calculate start and end indices for this element in output buffer
        let start = i * BYTES_PER_FIELD_ELEMENT;
        let end = (i + 1) * BYTES_PER_FIELD_ELEMENT;

        if end > max_output_size {
            // Handle case where this element would exceed max_output_size
            // Calculate how many bytes we can actually copy
            let slice_end = cmp::min(v.len(), max_output_size - start);

            // Copy partial element and break the loop
            // We can't fit any more complete elements
            data[start..start + slice_end].copy_from_slice(&v[..slice_end]);
            break;
        } else {
            // Normal case: element fits within max_output_size
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
    let mut y_sqrt = y_squared.sqrt().ok_or("point not on curve")?;

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

fn get_b_twist_curve_coeff() -> Fq2 {
    let twist_c0 = Fq::from(9);
    let twist_c1 = Fq::from(1);

    // this is bTwistCurveCoeff
    let mut twist_curve_coeff = Fq2::new(twist_c0, twist_c1);
    twist_curve_coeff = *twist_curve_coeff
        .inverse_in_place()
        .expect("inverse is required");

    twist_curve_coeff.c0 *= Fq::from(3);
    twist_curve_coeff.c1 *= Fq::from(3);
    twist_curve_coeff
}

pub fn is_on_curve_g1(g1: &G1Projective) -> bool {
    let b_curve_coeff: Fq = Fq::from_str("3").expect("3 is a valid field element");

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
/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#compute_powers
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

/// Retrieves and converts a primitive root of unity to a field element
///
/// # Arguments
/// * `index` - Index of the primitive root to retrieve from PRIMITIVE_ROOTS_OF_UNITY array
///
/// # Returns
/// * `Result<Fr, KzgError>` - Field element representation of the primitive root if successful,
///                           or KzgError if index is invalid or conversion fails
///
/// # Errors
/// - Returns KzgError::GenericError if:
///   - Index is out of bounds for PRIMITIVE_ROOTS_OF_UNITY array
///   - BigInt conversion to field element fails
///
/// # Details
/// - Looks up a primitive root of unity from a predefined array using the given index
/// - Converts the BigInt representation to an Fr field element
/// - Commonly used in FFT and polynomial operations requiring roots of unity
///
/// # Example
/// ```
/// use rust_kzg_bn254_primitives::helpers::get_primitive_root_of_unity;
/// let root = get_primitive_root_of_unity(0); // Gets first primitive root
/// ```
/// Gets the primitive root of unity of order 2^power.
/// For example, power=3 returns a primitive 8th root of unity.
pub fn get_primitive_root_of_unity(power: usize) -> Result<Fr, KzgError> {
    PRIMITIVE_ROOTS_OF_UNITY
        .get(power)
        .ok_or_else(|| KzgError::GenericError("power must be <= 28".to_string()))
        .copied()
}

/// Maps a byte slice to a field element (`Fr`) using SHA-256 from SHA3 family as the
/// hash function.
///
/// # Arguments
///
/// * `msg` - The input byte slice to hash.
///
/// # Returns
///
/// * `Fr` - The resulting field element.
pub fn hash_to_field_element(msg: &[u8]) -> Fr {
    // Perform the hash operation.
    let msg_digest = Sha256::digest(msg);
    let hash_elements = msg_digest.as_slice();

    let fr_element: Fr = Fr::from_be_bytes_mod_order(hash_elements);

    fr_element
}

pub fn pairings_verify(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine) -> bool {
    let neg_b1 = -b1;
    let p = [a1, neg_b1];
    let q = [a2, b2];
    let result = Bn254::multi_pairing(p, q);
    result.is_zero()
}

/// Computes the Fiat-Shamir challenge from a blob and its commitment.
///
/// # Arguments
///
/// * `blob` - A reference to the `Blob` struct.
/// * `commitment` - A reference to the `G1Affine` commitment.
///
/// # Returns
///
/// * `Ok(Fr)` - The resulting field element challenge.
/// * `Err(KzgError)` - If any step fails.
pub fn compute_challenge(blob: &Blob, commitment: &G1Affine) -> Result<Fr, KzgError> {
    // Validate the commitment using the helper function
    validate_g1_point(commitment)?;

    // Convert the blob to a polynomial in evaluation form
    // This is needed to process the blob data for the challenge
    let blob_poly = blob.to_polynomial_eval_form()?;

    // Calculate total size needed for the challenge input buffer:
    // - Length of domain separator
    // - 8 bytes for number of field elements
    // - Size of blob data (number of field elements * bytes per element)
    // - Size of compressed G1 point (commitment)
    let challenge_input_size = FIAT_SHAMIR_PROTOCOL_DOMAIN.len()
        + 8
        + (blob_poly.len() * BYTES_PER_FIELD_ELEMENT)
        + SIZE_OF_G1_AFFINE_COMPRESSED;

    // Initialize buffer to store all data that will be hashed
    let mut digest_bytes = vec![0; challenge_input_size];
    let mut offset = 0;

    // Step 1: Copy the Fiat-Shamir domain separator
    // This provides domain separation for the hash function to prevent
    // attacks that try to confuse different protocol messages
    digest_bytes[offset..offset + FIAT_SHAMIR_PROTOCOL_DOMAIN.len()]
        .copy_from_slice(FIAT_SHAMIR_PROTOCOL_DOMAIN);
    offset += FIAT_SHAMIR_PROTOCOL_DOMAIN.len();

    // Step 2: Copy the number of field elements (blob polynomial length)
    // Convert to bytes using the configured endianness
    let number_of_field_elements = usize_to_be_bytes(blob_poly.len());
    digest_bytes[offset..offset + 8].copy_from_slice(&number_of_field_elements);
    offset += 8;

    // Step 3: Copy the blob data
    // Convert polynomial to bytes using helper function
    let blob_data = to_byte_array(
        blob_poly.evaluations(),
        blob_poly.len() * BYTES_PER_FIELD_ELEMENT,
    );
    digest_bytes[offset..offset + blob_data.len()].copy_from_slice(&blob_data);
    offset += blob_data.len();

    // Step 4: Copy the commitment (compressed G1 point)
    // Serialize the commitment point in compressed form
    let mut commitment_bytes = Vec::with_capacity(SIZE_OF_G1_AFFINE_COMPRESSED);
    commitment
        .serialize_compressed(&mut commitment_bytes)
        .map_err(|_| KzgError::SerializationError("Failed to serialize commitment".to_string()))?;
    digest_bytes[offset..offset + SIZE_OF_G1_AFFINE_COMPRESSED].copy_from_slice(&commitment_bytes);

    // Verify that we wrote exactly the amount of bytes we expected
    // This helps catch any buffer overflow/underflow bugs
    if offset + SIZE_OF_G1_AFFINE_COMPRESSED != challenge_input_size {
        return Err(KzgError::InvalidInputLength);
    }

    // Hash all the data to generate the challenge field element
    // This implements the Fiat-Shamir transform to generate a "random" challenge
    Ok(hash_to_field_element(&digest_bytes))
}

/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#evaluate_polynomial_in_evaluation_form
pub fn evaluate_polynomial_in_evaluation_form(
    polynomial: &PolynomialEvalForm,
    z: &Fr,
) -> Result<Fr, KzgError> {
    let blob_size = polynomial.len_underlying_blob_bytes();

    // Step 2: Calculate roots of unity for the given blob size and SRS order
    let roots_of_unity = calculate_roots_of_unity(blob_size as u64)?;

    // Step 3: Ensure the polynomial length matches the domain length
    if polynomial.len() != roots_of_unity.len() {
        return Err(KzgError::InvalidInputLength);
    }

    let width = polynomial.len();

    if width == 0 {
        return Err(KzgError::GenericError(
            "Empty polynomial domain".to_string(),
        ));
    }
    if width > (1 << 28) {
        // Max supported domain size
        return Err(KzgError::GenericError(
            "Polynomial domain too large".to_string(),
        ));
    }

    // Step 4: Compute inverse_width = 1 / width
    let inverse_width = Fr::from(width as u64)
        .inverse()
        .ok_or(KzgError::InvalidDenominator)?;

    // Step 5: Check if `z` is in the domain
    if let Some(index) = roots_of_unity.iter().position(|&domain_i| domain_i == *z) {
        return polynomial
            .get_evalualtion(index)
            .cloned()
            .ok_or(KzgError::GenericError(
                "Polynomial element missing at the found index.".to_string(),
            ));
    }

    // Step 6: Use the barycentric formula to compute the evaluation
    let sum = polynomial
        .evaluations()
        .iter()
        .zip(roots_of_unity.iter())
        .map(|(f_i, &domain_i)| {
            let a = *f_i * domain_i;
            let b = *z - domain_i;

            if b.is_zero() {
                return Err(KzgError::GenericError(
                    "Division by zero in barycentric evaluation: z equals domain element"
                        .to_string(),
                ));
            }

            Ok(a / b)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .fold(Fr::zero(), |acc, val| acc + val);

    // Step 7: Compute r = z^width - 1
    let r = z.pow([width as u64]) - Fr::one();

    // Step 8: Compute f(z) = (z^width - 1) / width * sum
    let f_z = sum * r * inverse_width;

    Ok(f_z)
}

/// Calculates the roots of unities but doesn't assign it to the struct
/// Used in batch verification process as the roots need to be calculated for each blob
/// because of different length.
///
/// # Arguments
/// * `length_of_data_after_padding` - Length of the blob data after padding in bytes.
///
/// # Returns
/// * `Result<(Params, Vec<Fr>), KzgError>` - Tuple containing:
///   - Params: KZG library operational parameters
///   - Vec<Fr>: Vector of roots of unity
///
/// # Details
/// - Generates roots of unity needed for FFT operations
/// - Calculates KZG operational parameters for commitment scheme
/// ```
pub fn calculate_roots_of_unity(length_of_data_after_padding: u64) -> Result<Vec<Fr>, KzgError> {
    if length_of_data_after_padding == 0 {
        return Err(KzgError::GenericError(
            "Length of data after padding is 0".to_string(),
        ));
    }

    if length_of_data_after_padding.div_ceil(BYTES_PER_FIELD_ELEMENT as u64)
        > MAINNET_SRS_G1_SIZE as u64
    {
        return Err(KzgError::GenericError(
            "the length of data after padding is not valid with respect to the SRS".to_string(),
        ));
    }

    // Calculate log2 of the next power of two of the length of data after padding
    let log2_of_evals = log2(
        length_of_data_after_padding
            .div_ceil(BYTES_PER_FIELD_ELEMENT as u64)
            .next_power_of_two() as f64,
    )
    .to_u8()
    .ok_or_else(|| {
        KzgError::GenericError("Failed to convert length_of_data_after_padding to u8".to_string())
    })?;

    // Check if the length of data after padding is valid with respect to the SRS order
    if log2_of_evals as u64 > MAINNET_SRS_G1_SIZE as u64 {
        return Err(KzgError::SerializationError(
            "the length of data after padding is not valid with respect to the SRS".to_string(),
        ));
    }

    // Find the root of unity corresponding to the calculated log2 value
    let root_of_unity = get_primitive_root_of_unity(log2_of_evals.into())?;

    // Expand the root to get all the roots of unity
    let mut expanded_roots_of_unity = expand_root_of_unity(&root_of_unity);

    // Remove the last element to avoid duplication
    expanded_roots_of_unity.truncate(expanded_roots_of_unity.len() - 1);

    // Return the parameters and the expanded roots of unity
    Ok(expanded_roots_of_unity)
}

/// function to expand the roots based on the configuration
fn expand_root_of_unity(root_of_unity: &Fr) -> Vec<Fr> {
    let mut roots = vec![Fr::one()]; // Initialize with 1
    roots.push(*root_of_unity); // Add the root of unity

    let mut i = 1;

    // This is the maximum number of iterations to avoid infinite loop
    // There is only need to support a max of MAINNET_SRS_G1_SIZE worth of data so
    // the number of iterations is MAINNET_SRS_G1_SIZE + 1 (because the first element is 1)
    let max_iterations: usize = MAINNET_SRS_G1_SIZE + 1;

    while !roots[i].is_one() && i < max_iterations {
        // Continue until the element cycles back to one
        let this = &roots[i];
        i += 1;
        roots.push(this * root_of_unity); // Push the next power of the root
                                          // of unity
    }

    if i >= max_iterations {
        // This should never happen with valid primitive roots, but provides safety
        // Return minimal valid expansion
        return vec![Fr::one()];
    }

    roots
}

/// A helper function for the `verify_blob_kzg_proof_batch` function.
pub fn compute_challenges_and_evaluate_polynomial(
    blobs: &[Blob],
    commitments: &[G1Affine],
) -> Result<(Vec<Fr>, Vec<Fr>), KzgError> {
    // Pre-allocate vectors to store:
    // - evaluation_challenges: Points where polynomials will be evaluated
    // - ys: Results of polynomial evaluations at challenge points
    let mut evaluation_challenges = Vec::with_capacity(blobs.len());
    let mut ys = Vec::with_capacity(blobs.len());

    // Process each blob sequentially
    // TODO: Potential optimizations:
    // 1. Cache roots of unity calculations across iterations
    // 2. Parallelize processing for large numbers of blobs
    // 3. Batch polynomial conversions if possible
    for i in 0..blobs.len() {
        // Step 1: Convert blob to polynomial form
        // This is necessary because we need to evaluate the polynomial
        let polynomial = blobs[i].to_polynomial_eval_form()?;

        // Step 2: Generate Fiat-Shamir challenge
        // This creates a "random" evaluation point based on the blob and commitment
        // The challenge is deterministic but unpredictable, making the proof non-interactive
        let evaluation_challenge = compute_challenge(&blobs[i], &commitments[i])?;

        // Step 3: Evaluate the polynomial at the challenge point
        // This uses the evaluation form for efficient computation
        // The srs_order parameter ensures compatibility with the trusted setup
        let y = evaluate_polynomial_in_evaluation_form(&polynomial, &evaluation_challenge)?;

        // Store both:
        // - The challenge point (where we evaluated)
        // - The evaluation result (what the polynomial equals at that point)
        evaluation_challenges.push(evaluation_challenge);
        ys.push(y);
    }

    // Return tuple of:
    // 1. Vector of evaluation points (challenges)
    // 2. Vector of polynomial evaluations at those points
    // These will be used in the KZG proof verification process
    Ok((evaluation_challenges, ys))
}

/// Converts a usize to a byte array in big-endian format always returning 8 bytes.
pub fn usize_to_be_bytes(number: usize) -> [u8; 8] {
    let mut result = [0u8; 8];
    let number_bytes = number.to_be_bytes();

    if number_bytes.len() == 4 {
        result[4..].copy_from_slice(&number_bytes);
    } else {
        result.copy_from_slice(&number_bytes);
    }
    result
}

/// Validates that the blob data contains valid bn254 field elements.
/// Uses direct deserialization to check if bytes represent canonical field elements.
/// The data provided is expected to be in big-endian format.
pub fn validate_blob_data_as_canonical_field_elements(data: &[u8]) -> Result<(), KzgError> {
    use crate::consts::BYTES_PER_FIELD_ELEMENT;

    if data.len() % BYTES_PER_FIELD_ELEMENT != 0 {
        return Err(KzgError::InvalidInputLength);
    }

    for (i, chunk) in data.chunks(BYTES_PER_FIELD_ELEMENT).enumerate() {
        // Try to deserialize the chunk as a canonical field element
        // There is no difference between the compressed and uncompressed deserialization since
        // it doesn't apply to Fr and also the implementation is done with empty flags on arkworks.
        // The deserialization is done in little-endian format, so we need to reverse the bytes.
        // Use fixed-size array to avoid heap allocation and optimize byte reversal
        let mut chunk_le = [0u8; BYTES_PER_FIELD_ELEMENT];
        chunk_le.copy_from_slice(chunk);
        chunk_le.reverse();

        Fr::deserialize_uncompressed(&chunk_le[..])
            .map(|_| ()) // Discard the field element, we only care about validation
            .map_err(|_| {
                KzgError::InvalidFieldElement(format!(
                    "Field element at position {} is not canonical or invalid",
                    i
                ))
            })?;
    }
    Ok(())
}

/// Validates that a G1 point meets all cryptographic requirements.
///
/// This function checks the following conditions:
/// 1. Point is not the identity (point at infinity)
/// 2. Point is on the BN254 elliptic curve
/// 3. Point is in the correct subgroup
/// 4. Point is not the generator point
///
/// # Arguments
/// * `point` - Reference to the G1Affine point to validate
///
/// # Returns
/// * `Ok(())` if the point passes all validation checks
/// * `Err(KzgError::NotOnCurveError)` with specific error message if validation fails
///
/// # Example
/// ```
/// use ark_bn254::G1Affine;
/// use ark_ff::UniformRand;
/// use ark_ec::AffineRepr;
/// use rust_kzg_bn254_primitives::helpers::validate_g1_point;
///
/// let mut rng = ark_std::test_rng();
/// let valid_point = G1Affine::rand(&mut rng);
/// assert!(validate_g1_point(&valid_point).is_ok());
///
/// let identity_point = G1Affine::identity();
/// assert!(validate_g1_point(&identity_point).is_err());
///
/// let generator_point = G1Affine::generator();
/// assert!(validate_g1_point(&generator_point).is_err());
/// ```
pub fn validate_g1_point(point: &G1Affine) -> Result<(), KzgError> {
    if point.is_zero() {
        return Err(KzgError::NotOnCurveError(
            "G1 point cannot be point at infinity".to_string(),
        ));
    }

    if !point.is_on_curve() {
        return Err(KzgError::NotOnCurveError(
            "G1 point not on curve".to_string(),
        ));
    }

    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(KzgError::NotOnCurveError(
            "G1 point not in correct subgroup".to_string(),
        ));
    }

    if *point == G1Affine::generator() {
        return Err(KzgError::NotOnCurveError(
            "G1 point cannot be the generator point".to_string(),
        ));
    }

    Ok(())
}

/// Validates that a G2 point meets all cryptographic requirements.
///
/// This function checks the following conditions:
/// 1. Point is not the identity (point at infinity)
/// 2. Point is on the BN254 elliptic curve (twisted curve for G2)
/// 3. Point is in the correct subgroup
/// 4. Point is not the generator point
///
/// # Arguments
/// * `point` - Reference to the G2Affine point to validate
///
/// # Returns
/// * `Ok(())` if the point passes all validation checks
/// * `Err(KzgError::NotOnCurveError)` with specific error message if validation fails
///
/// # Example
/// ```
/// use ark_bn254::G2Affine;
/// use ark_ff::UniformRand;
/// use ark_ec::AffineRepr;
/// use rust_kzg_bn254_primitives::helpers::validate_g2_point;
///
/// let mut rng = ark_std::test_rng();
/// let valid_point = G2Affine::rand(&mut rng);
/// assert!(validate_g2_point(&valid_point).is_ok());
///
/// let identity_point = G2Affine::identity();
/// assert!(validate_g2_point(&identity_point).is_err());
///
/// let generator_point = G2Affine::generator();
/// assert!(validate_g2_point(&generator_point).is_err());
/// ```
pub fn validate_g2_point(point: &G2Affine) -> Result<(), KzgError> {
    if point.is_zero() {
        return Err(KzgError::NotOnCurveError(
            "G2 point cannot be point at infinity".to_string(),
        ));
    }

    if !point.is_on_curve() {
        return Err(KzgError::NotOnCurveError(
            "G2 point not on curve".to_string(),
        ));
    }

    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(KzgError::NotOnCurveError(
            "G2 point not in correct subgroup".to_string(),
        ));
    }

    if *point == G2Affine::generator() {
        return Err(KzgError::NotOnCurveError(
            "G2 point cannot be the generator point".to_string(),
        ));
    }

    Ok(())
}

// Internally pads the input data by prepending a 0x00 to each chunk of 31 bytes. This guarantees that
// the data will be a valid field element for the bn254 curve
//
// # Additionally, this function will add necessary padding to align the output to 32 bytes
//
// NOTE: this method is a reimplementation of convert_by_padding_empty_byte, with one meaningful difference: the alignment
// of the output to encoding.BYTES_PER_SYMBOL. This alignment actually makes the padding logic simpler, and the
// code that uses this function needs an aligned output anyway.
pub fn pad_payload(input_data: &[u8]) -> Vec<u8> {
    let bytes_per_chunk = BYTES_PER_FIELD_ELEMENT - 1; // 31 bytes
    let chunk_count = input_data.len().div_ceil(bytes_per_chunk);
    let output_length = chunk_count * BYTES_PER_FIELD_ELEMENT;

    let mut padded_output = vec![0u8; output_length];

    for chunk_idx in 0..chunk_count {
        let input_start = chunk_idx * bytes_per_chunk;
        let input_end = core::cmp::min(input_start + bytes_per_chunk, input_data.len());
        let output_start = chunk_idx * BYTES_PER_FIELD_ELEMENT + 1;

        padded_output[output_start..output_start + (input_end - input_start)]
            .copy_from_slice(&input_data[input_start..input_end]);
    }

    padded_output
}

/// Removes internal padding from data that was processed by `pad_payload`.
///
/// This is the inverse of `pad_payload` - removes the 0x00 prefix from each 32-byte chunk.
/// Uses the same optimization pattern as `remove_empty_byte_from_padded_bytes_unchecked`.
///
/// # Example
/// ```
/// use rust_kzg_bn254_primitives::helpers::{pad_payload, remove_internal_padding};
///
/// let original = b"hello world";
/// let padded = pad_payload(original);
/// let recovered = remove_internal_padding(&padded).unwrap();
/// assert_eq!(original, &recovered[..original.len()]);
/// ```
pub fn remove_internal_padding(padded_data: &[u8]) -> Result<Vec<u8>, KzgError> {
    if padded_data.len() % BYTES_PER_FIELD_ELEMENT != 0 {
        return Err(KzgError::InvalidInputLength);
    }

    let bytes_per_chunk = BYTES_PER_FIELD_ELEMENT - 1;
    let chunk_count = padded_data.len() / BYTES_PER_FIELD_ELEMENT;
    let output_length = chunk_count * bytes_per_chunk;

    // Use capacity-only allocation to avoid zero-initialization waste
    let mut output_data = Vec::with_capacity(output_length);

    // Use chunks_exact for SIMD optimization (same pattern as remove_empty_byte_from_padded_bytes_unchecked)
    for chunk in padded_data.chunks_exact(BYTES_PER_FIELD_ELEMENT) {
        output_data.extend_from_slice(&chunk[1..]);
    }

    Ok(output_data)
}
