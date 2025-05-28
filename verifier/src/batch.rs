use ark_bn254::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use rust_kzg_bn254_primitives::{
    blob::Blob,
    consts::{
        BYTES_PER_FIELD_ELEMENT, G2_TAU, RANDOM_CHALLENGE_KZG_BATCH_DOMAIN,
        SIZE_OF_G1_AFFINE_COMPRESSED,
    },
    errors::KzgError,
    helpers::{self, is_on_curve_g1, usize_to_be_bytes},
    traits::{ReadFrFromBytes, ReadPointFromBytes},
};

extern crate alloc;
use alloc::{string::ToString, vec, vec::Vec};

// verify_blob_kzg_proof_batch_impl is used to verify a batch of KZG proofs where the commitments and proofs are in Affine form
// This accepts Affine points and acts as a helper function for verify_blob_kzg_proof_batch
// but also gives the user the option to verify a batch of proofs directly from Affine points
pub fn verify_blob_kzg_proof_batch_impl(
    blobs: &[Blob],
    commitments: &[G1Affine],
    proofs: &[G1Affine],
) -> Result<bool, KzgError> {
    // First validation check: Ensure all input vectors have matching lengths
    // This is critical for batch verification to work correctly
    if !(commitments.len() == blobs.len() && proofs.len() == blobs.len()) {
        return Err(KzgError::GenericError(
            "length's of the input are not the same".to_string(),
        ));
    }

    // Validate that all commitments are valid points on the G1 curve
    // Using parallel iterator (par_iter) for better performance on large batches
    // This prevents invalid curve attacks
    if commitments.iter().any(|commitment| {
        commitment == &G1Affine::identity()
            || !commitment.is_on_curve()
            || !commitment.is_in_correct_subgroup_assuming_on_curve()
    }) {
        return Err(KzgError::NotOnCurveError(
            "commitment not on curve".to_string(),
        ));
    }

    // Validate that all proofs are valid points on the G1 curve
    // Using parallel iterator for efficiency
    if proofs.iter().any(|proof| {
        proof == &G1Affine::identity()
            || !proof.is_on_curve()
            || !proof.is_in_correct_subgroup_assuming_on_curve()
    }) {
        return Err(KzgError::NotOnCurveError("proof not on curve".to_string()));
    }

    // Compute evaluation challenges and evaluate polynomials at those points
    // This step:
    // 1. Generates random evaluation points for each blob
    // 2. Evaluates each blob's polynomial at its corresponding point
    let (evaluation_challenges, ys) =
        helpers::compute_challenges_and_evaluate_polynomial(blobs, commitments)?;

    // Convert each blob to its polynomial evaluation form and get the length of number of field elements
    // This length value is needed for computing the challenge
    let blobs_as_field_elements_length: Vec<u64> = blobs
        .iter()
        .map(|blob| blob.to_polynomial_eval_form().evaluations().len() as u64)
        .collect();

    // Perform the actual batch verification using the computed values:
    // - commitments: Original KZG commitments
    // - evaluation_challenges: Points where polynomials are evaluated
    // - ys: Values of polynomials at evaluation points
    // - proofs: KZG proofs for each evaluation
    // - blobs_as_field_elements_length: Length of each blob's polynomial
    verify_kzg_proof_batch_impl(
        commitments,
        &evaluation_challenges,
        &ys,
        proofs,
        &blobs_as_field_elements_length,
    )
}

/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof_batch
/// This function is used to verify a batch of KZG proofs where the commitments and proofs are in compressed form
/// The commitments and proofs are expected to be in big endian format
pub fn verify_blob_kzg_proof_batch(
    blobs_bytes: &[Vec<u8>],
    commitments_compressed: &[[u8; SIZE_OF_G1_AFFINE_COMPRESSED]],
    proofs_compressed: &[[u8; SIZE_OF_G1_AFFINE_COMPRESSED]],
) -> Result<bool, KzgError> {
    // Verify that the commitments and proofs are in big endian format
    // We convert each commitment and proof to little endian format because the deserialize_compressed function expects little endian format
    let commitments = commitments_compressed
        .iter()
        .map(|commitment| {
            G1Affine::read_point_from_bytes_native_compressed_be(commitment).map_err(|_| {
                KzgError::SerializationError("Failed to deserialize commitment".to_string())
            })
        })
        .collect::<Result<Vec<G1Affine>, KzgError>>()?;

    let proofs = proofs_compressed
        .iter()
        .map(|proof| {
            G1Affine::read_point_from_bytes_native_compressed_be(proof).map_err(|_| {
                KzgError::SerializationError("Failed to deserialize proof".to_string())
            })
        })
        .collect::<Result<Vec<G1Affine>, KzgError>>()?;

    // Convert the blobs to a Vec<Blob>
    // This function also verifies that the blobs are valid bn254 field elements
    let blobs = blobs_bytes
        .iter()
        .map(|blob| Blob::new(blob))
        .collect::<Vec<Blob>>();
    verify_blob_kzg_proof_batch_impl(&blobs, &commitments, &proofs)
}

/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_kzg_proof_batch
/// A helper function to the `helpers::compute_powers` function. This does the below reference code from the 4844 spec.
/// Ref: `# Append all inputs to the transcript before we hash
///      for commitment, z, y, proof in zip(commitments, zs, ys, proofs):
///          data += commitment + bls_field_to_bytes(z) + bls_field_to_bytes(y) + proof``
fn compute_r_powers(
    commitments: &[G1Affine],
    zs: &[Fr],
    ys: &[Fr],
    proofs: &[G1Affine],
    blobs_as_field_elements_length: &[u64],
) -> Result<Vec<Fr>, KzgError> {
    // Get the number of commitments/proofs we're processing
    let n = commitments.len();

    // Initial data length includes:
    // - 24 bytes for domain separator
    // - 8 bytes for number of field elements per blob
    // - 8 bytes for number of commitments
    let mut initial_data_length: usize = 40;

    // Calculate total input size:
    // - initial_data_length (40 bytes)
    // - For the number of commitments/zs/ys/proofs/blobs_as_field_elements_length (which are all the same length):
    //   * BYTES_PER_FIELD_ELEMENT for commitment
    //   * 2 * BYTES_PER_FIELD_ELEMENT for z and y values
    //   * BYTES_PER_FIELD_ELEMENT for proof
    //   * 8 bytes for blob length
    let input_size = initial_data_length
        + n * (BYTES_PER_FIELD_ELEMENT + 2 * BYTES_PER_FIELD_ELEMENT + BYTES_PER_FIELD_ELEMENT + 8);

    // Initialize buffer for data to be hashed
    let mut data_to_be_hashed: Vec<u8> = vec![0; input_size];

    // Copy domain separator to start of buffer
    // This provides domain separation for the hash function
    data_to_be_hashed[0..24].copy_from_slice(RANDOM_CHALLENGE_KZG_BATCH_DOMAIN);

    // Convert number of commitments to bytes and copy to buffer
    let n_bytes: [u8; 8] = usize_to_be_bytes(n);
    data_to_be_hashed[32..40].copy_from_slice(&n_bytes);

    let target_slice = &mut data_to_be_hashed[24..24 + (n * 8)];
    for (chunk, &length) in target_slice
        .chunks_mut(8)
        .zip(blobs_as_field_elements_length)
    {
        chunk.copy_from_slice(&length.to_be_bytes());
    }
    initial_data_length += n * 8;

    // Process each commitment, proof, and evaluation point/value
    for i in 0..n {
        // Serialize and copy commitment
        let mut v = vec![];

        // TODO(anupsv): Move serialization to helper function. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/32
        commitments[i].serialize_compressed(&mut v).map_err(|_| {
            KzgError::SerializationError("Failed to serialize commitment".to_string())
        })?;
        data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
            .copy_from_slice(&v[..]);
        initial_data_length += BYTES_PER_FIELD_ELEMENT;

        // Convert z point to bytes and copy
        let v = zs[i].into_bigint().to_bytes_be();
        data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
            .copy_from_slice(&v[..]);
        initial_data_length += BYTES_PER_FIELD_ELEMENT;

        // Convert y value to bytes and copy
        let v = ys[i].into_bigint().to_bytes_be();
        data_to_be_hashed[initial_data_length..(v.len() + initial_data_length)]
            .copy_from_slice(&v[..]);
        initial_data_length += BYTES_PER_FIELD_ELEMENT;

        // Serialize and copy proof
        let mut proof_bytes = vec![];
        proofs[i]
            .serialize_compressed(&mut proof_bytes)
            .map_err(|_| KzgError::SerializationError("Failed to serialize proof".to_string()))?;
        data_to_be_hashed[initial_data_length..(proof_bytes.len() + initial_data_length)]
            .copy_from_slice(&proof_bytes[..]);
        initial_data_length += BYTES_PER_FIELD_ELEMENT;
    }

    // Verify we filled the entire buffer
    // This ensures we didn't make any buffer overflow or underflow errors
    if initial_data_length != input_size {
        return Err(KzgError::InvalidInputLength);
    }

    // Hash all the data to get our random challenge
    let r = helpers::hash_to_field_element(&data_to_be_hashed);

    // Compute powers of the random challenge: [r^0, r^1, r^2, ..., r^(n-1)]
    Ok(helpers::compute_powers(&r, n))
}

/// Verifies multiple KZG proofs efficiently.
/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_kzg_proof_batch
/// # Arguments
///
/// * `commitments` - A slice of `G1Affine` commitments.
/// * `zs` - A slice of `Fr` elements representing z values.
/// * `ys` - A slice of `Fr` elements representing y values.
/// * `proofs` - A slice of `G1Affine` proofs.
///
/// # Returns
///
/// * `Ok(true)` if all proofs are valid.
/// * `Ok(false)` if any proof is invalid.
/// * `Err(KzgError)` if an error occurs during verification.
///
fn verify_kzg_proof_batch_impl(
    commitments: &[G1Affine],
    zs: &[Fr],
    ys: &[Fr],
    proofs: &[G1Affine],
    blobs_as_field_elements_length: &[u64],
) -> Result<bool, KzgError> {
    // Verify that all input arrays have the same length
    // This is crucial for batch verification to work correctly
    if !(commitments.len() == zs.len() && zs.len() == ys.len() && ys.len() == proofs.len()) {
        return Err(KzgError::GenericError(
            "length's of the input are not the same".to_string(),
        ));
    }

    // Check that all commitments are valid points on the G1 curve
    // This prevents invalid curve attacks
    if !commitments
        .iter()
        .all(|commitment| is_on_curve_g1(&G1Projective::from(*commitment)))
    {
        return Err(KzgError::NotOnCurveError(
            "commitment not on curve".to_string(),
        ));
    }

    // Check that all proofs are valid points on the G1 curve
    if !proofs
        .iter()
        .all(|proof| is_on_curve_g1(&G1Projective::from(*proof)))
    {
        return Err(KzgError::NotOnCurveError("proof".to_string()));
    }

    // Verify that the trusted setup point τ*G2 is on the G2 curve
    if !helpers::is_on_curve_g2(&G2Projective::from(G2_TAU)) {
        return Err(KzgError::NotOnCurveError("g2 tau".to_string()));
    }

    let n = commitments.len();

    // Initialize vectors to store:
    // c_minus_y: [C_i - [y_i]]  (commitment minus the evaluation point encrypted)
    // r_times_z: [r^i * z_i]    (powers of random challenge times evaluation points)
    let mut c_minus_y: Vec<G1Affine> = Vec::with_capacity(n);
    let mut r_times_z: Vec<Fr> = Vec::with_capacity(n);

    // Compute powers of the random challenge: [r^0, r^1, r^2, ..., r^(n-1)]
    let r_powers = compute_r_powers(commitments, zs, ys, proofs, blobs_as_field_elements_length)?;

    // Compute Σ(r^i * proof_i)
    let proof_lincomb = helpers::g1_lincomb(proofs, &r_powers)?;

    // For each proof i:
    // 1. Compute C_i - [y_i]
    // 2. Compute r^i * z_i
    for i in 0..n {
        // Encrypt y_i as a point on G1
        let ys_encrypted = G1Affine::generator() * ys[i];
        // Compute C_i - [y_i] and convert to affine coordinates
        c_minus_y.push((commitments[i] - ys_encrypted).into_affine());
        // Compute r^i * z_i
        r_times_z.push(r_powers[i] * zs[i]);
    }

    // Compute:
    // proof_z_lincomb = Σ(r^i * z_i * proof_i)
    // c_minus_y_lincomb = Σ(r^i * (C_i - [y_i]))
    let proof_z_lincomb = helpers::g1_lincomb(proofs, &r_times_z)?;
    let c_minus_y_lincomb = helpers::g1_lincomb(&c_minus_y, &r_powers)?;

    // Compute right-hand side of the pairing equation
    let rhs_g1 = c_minus_y_lincomb + proof_z_lincomb;

    // Verify the pairing equation:
    // e(Σ(r^i * proof_i), [τ]) = e(Σ(r^i * (C_i - [y_i])) + Σ(r^i * z_i * proof_i), [1])
    let result =
        helpers::pairings_verify(proof_lincomb, G2_TAU, rhs_g1.into(), G2Affine::generator());
    Ok(result)
}

// This function is used to verify a batch of KZG proofs where the commitments and proofs are in compressed form
// The commitments, proofs, and zs, ys are expected to be in big endian format
pub fn verify_kzg_proof_batch(
    commitments_compressed: &[[u8; SIZE_OF_G1_AFFINE_COMPRESSED]],
    zs: &[[u8; BYTES_PER_FIELD_ELEMENT]],
    ys: &[[u8; BYTES_PER_FIELD_ELEMENT]],
    proofs_compressed: &[[u8; SIZE_OF_G1_AFFINE_COMPRESSED]],
    blobs_as_field_elements_length: &[u64],
) -> Result<bool, KzgError> {
    // Verify that the commitments and proofs are in big endian format
    // We convert each commitment, proof, z, y to little endian format because the deserialize_compressed function expects little endian format
    let commitments = commitments_compressed
        .iter()
        .map(|commitment| {
            G1Affine::read_point_from_bytes_native_compressed_be(commitment).map_err(|_| {
                KzgError::SerializationError("Failed to deserialize commitment".to_string())
            })
        })
        .collect::<Result<Vec<G1Affine>, KzgError>>()?;

    // Verify that the proofs are in big endian format
    let proofs = proofs_compressed
        .iter()
        .map(|proof| {
            G1Affine::read_point_from_bytes_native_compressed_be(proof).map_err(|_| {
                KzgError::SerializationError("Failed to deserialize proof".to_string())
            })
        })
        .collect::<Result<Vec<G1Affine>, KzgError>>()?;

    // Convert the zs and ys to Fr
    let zs = zs
        .iter()
        .map(|z| {
            Fr::deserialize_from_bytes_be(z)
                .map_err(|_| KzgError::SerializationError("Failed to deserialize z".to_string()))
        })
        .collect::<Result<Vec<Fr>, KzgError>>()?;

    let ys = ys
        .iter()
        .map(|y| {
            Fr::deserialize_from_bytes_be(y)
                .map_err(|_| KzgError::SerializationError("Failed to deserialize y".to_string()))
        })
        .collect::<Result<Vec<Fr>, KzgError>>()?;

    verify_kzg_proof_batch_impl(
        &commitments,
        &zs,
        &ys,
        &proofs,
        blobs_as_field_elements_length,
    )
}
