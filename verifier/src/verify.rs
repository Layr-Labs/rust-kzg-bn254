use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use rust_kzg_bn254_primitives::{
    blob::Blob, consts::G2_TAU, errors::KzgError, helpers, traits::G1AffineExt,
};

/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_kzg_proof
/// TODO(anupsv): Accept bytes instead of Fr element and Affine points. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/30
pub fn verify_proof(
    commitment_bytes: &[u8; 32],
    proof_bytes: &[u8; 32],
    value_fr_bytes: &[u8; 32],
    z_fr_bytes: &[u8; 32],
) -> Result<bool, KzgError> {
    // Convert the commitment bytes to a G1Affine point
    let commitment = G1Affine::deserialize_compressed_be(commitment_bytes)?;

    // Convert the commitment bytes to a G1Affine point
    let proof = G1Affine::deserialize_compressed_be(proof_bytes)?;

    // Convert value_fr_bytes to Fr element
    let value_fr = Fr::from_be_bytes_mod_order(value_fr_bytes);

    // Convert z_fr_bytes to Fr element
    let z_fr = Fr::from_be_bytes_mod_order(z_fr_bytes);

    if !commitment.is_on_curve() || !commitment.is_in_correct_subgroup_assuming_on_curve() {
        return Err(KzgError::NotOnCurveError(
            "commitment not on curve".to_string(),
        ));
    }

    if !proof.is_on_curve() || !proof.is_in_correct_subgroup_assuming_on_curve() {
        return Err(KzgError::NotOnCurveError("proof not on curve".to_string()));
    }

    // Get τ*G2 from the trusted setup
    // This is the second generator point multiplied by the trusted setup secret
    let g2_tau = G2_TAU;

    // Compute [value]*G1
    // This encrypts the claimed evaluation value as a point in G1
    let value_g1 = (G1Affine::generator() * value_fr).into_affine();

    // Compute [C - value*G1]
    // This represents the difference between the commitment and claimed value
    // If the claim is valid, this equals H(X)(X - z) in the polynomial equation
    let commit_minus_value = (commitment - value_g1).into_affine();

    // Compute [z]*G2
    // This encrypts the evaluation point as a point in G2
    let z_g2 = (G2Affine::generator() * z_fr).into_affine();

    // Compute [τ - z]*G2
    // This represents (X - z) in the polynomial equation
    // τ is the secret from the trusted setup representing the variable X
    let x_minus_z = (g2_tau - z_g2).into_affine();

    // Verify the pairing equation:
    // e([C - value*G1], G2) = e(proof, [τ - z]*G2)
    // This checks if (C - value*G1) = proof * (τ - z)
    // which verifies the polynomial quotient relationship
    Ok(helpers::pairings_verify(
        commit_minus_value,    // Left side first argument
        G2Affine::generator(), // Left side second argument (G2 generator)
        proof,                 // Right side first argument
        x_minus_z,             // Right side second argument
    ))
}

/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof
/// TODO(anupsv): Accept bytes instead of Affine points. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/31
pub fn verify_blob_kzg_proof(
    blob: &Blob,
    commitment_bytes: &[u8; 32],
    proof_bytes: &[u8; 32],
) -> Result<bool, KzgError> {
    // Convert the commitment bytes to a G1Affine point
    let commitment = G1Affine::deserialize_compressed_be(commitment_bytes)?;

    // Convert the commitment bytes to a G1Affine point
    let proof = G1Affine::deserialize_compressed_be(proof_bytes)?;

    if !commitment.is_on_curve() || !commitment.is_in_correct_subgroup_assuming_on_curve() {
        return Err(KzgError::NotOnCurveError(
            "commitment not on curve".to_string(),
        ));
    }

    if !proof.is_on_curve() || !proof.is_in_correct_subgroup_assuming_on_curve() {
        return Err(KzgError::NotOnCurveError("proof not on curve".to_string()));
    }

    // Convert blob to polynomial
    let polynomial = blob.to_polynomial_eval_form();

    // Compute the evaluation challenge for the blob and commitment
    let evaluation_challenge = helpers::compute_challenge(blob, &commitment)?;

    // Evaluate the polynomial in evaluation form
    let y = helpers::evaluate_polynomial_in_evaluation_form(&polynomial, &evaluation_challenge)?;

    let y_bytes: &[u8; 32] = &y
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .map_err(|_| KzgError::GenericError("slice with incorrect length".to_string()))?;
    let evaluation_challenge_bytes: &[u8; 32] = &evaluation_challenge
        .into_bigint()
        .to_bytes_be()
        .try_into()
        .map_err(|_| KzgError::GenericError("slice with incorrect length".to_string()))?;

    // Verify the KZG proof
    self::verify_proof(
        commitment_bytes,
        proof_bytes,
        y_bytes,
        evaluation_challenge_bytes,
    )
}
