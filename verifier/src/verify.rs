use ark_bn254::{Fr, G1Affine, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup};
use rust_kzg_bn254_primitives::{blob::Blob, consts::G2_TAU, errors::KzgError, helpers};

extern crate alloc;
use alloc::string::ToString;

/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_proof
/// TODO(anupsv): Accept bytes instead of Fr element and Affine points. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/30
pub fn verify_proof(
    commitment: G1Affine,
    proof: G1Affine,
    value_fr: Fr,
    z_fr: Fr,
) -> Result<bool, KzgError> {
    // Validate commitment point using helper function
    // This checks: not identity, on curve, correct subgroup, not generator
    helpers::validate_g1_point(&commitment)?;

    // Validate proof point using helper function
    // This checks: not identity, on curve, correct subgroup, not generator
    helpers::validate_g1_point(&proof)?;

    // This must match the validation in batch verification for consistency
    if !helpers::is_on_curve_g2(&G2Projective::from(G2_TAU)) {
        return Err(KzgError::NotOnCurveError(
            "Invalid trusted setup: G2_TAU not on curve".to_string(),
        ));
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

    if commit_minus_value == G1Affine::identity() {
        return Err(KzgError::GenericError(
            "Invalid commitment-value relationship".to_string(),
        ));
    }

    // Compute [z]*G2
    // This encrypts the evaluation point as a point in G2
    let z_g2 = (G2Affine::generator() * z_fr).into_affine();

    // Compute [τ - z]*G2
    // This represents (X - z) in the polynomial equation
    // τ is the secret from the trusted setup representing the variable X
    let x_minus_z = (g2_tau - z_g2).into_affine();

    if x_minus_z == G2Affine::identity() {
        return Err(KzgError::GenericError(
            "Evaluation point equals trusted setup secret".to_string(),
        ));
    }

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
    commitment: &G1Affine,
    proof: &G1Affine,
) -> Result<bool, KzgError> {
    // This checks: not identity, on curve, correct subgroup, not generator
    helpers::validate_g1_point(commitment)?;

    // This checks: not identity, on curve, correct subgroup, not generator
    helpers::validate_g1_point(proof)?;

    // Convert blob to polynomial
    let polynomial = blob.to_polynomial_eval_form()?;

    // Compute the evaluation challenge for the blob and commitment
    let evaluation_challenge = helpers::compute_challenge(blob, commitment)?;

    // Evaluate the polynomial in evaluation form
    let y = helpers::evaluate_polynomial_in_evaluation_form(&polynomial, &evaluation_challenge)?;

    // Verify the KZG proof
    self::verify_proof(*commitment, *proof, y, evaluation_challenge)
}
