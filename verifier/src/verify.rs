use ark_bn254::{Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use rust_kzg_bn254_primitives::{
    blob::Blob,
    consts::{BYTES_PER_FIELD_ELEMENT, G2_TAU, SIZE_OF_G1_AFFINE_COMPRESSED},
    errors::KzgError,
    helpers,
    traits::{ReadFrFromBytes, ReadPointFromBytes},
};

extern crate alloc;
use alloc::string::ToString;

/// This function performs verification of a KZG proof where the commitment, proof,
/// evaluation value, and evaluation point are provided as deserialized curve points
/// and field elements. It implements the core KZG proof verification algorithm
/// using bilinear pairings.
///
/// # Arguments
///
/// * `commitment` - A `G1Affine` point representing the KZG commitment to a polynomial
/// * `proof` - A `G1Affine` point representing the KZG proof for the evaluation
/// * `value_fr` - A field element representing the claimed polynomial value at the evaluation point
/// * `z_fr` - A field element representing the evaluation point
///
/// # Returns
///
/// * `Ok(true)` - If the proof is valid and verification succeeds
/// * `Ok(false)` - If the proof is invalid but no errors occurred during verification
/// * `Err(KzgError)` - If an error occurs during verification (e.g., invalid curve points)
///
/// # Examples
///
/// ```rust,no_run
/// use rust_kzg_bn254_verifier::verify::verify_proof_impl;
/// use ark_bn254::{G1Affine, Fr};
/// use ark_ff::One;
/// use ark_ec::AffineRepr;
///
/// let commitment = G1Affine::generator(); // Example commitment
/// let proof = G1Affine::generator();      // Example proof
/// let value = Fr::one();                  // Claimed polynomial value
/// let z = Fr::one();                      // Evaluation point
///
/// match verify_proof_impl(commitment, proof, value, z) {
///     Ok(true) => println!("Proof is valid!"),
///     Ok(false) => println!("Proof is invalid"),
///     Err(e) => println!("Verification error: {}", e),
/// }
/// ```
///
pub fn verify_proof_impl(
    commitment: G1Affine,
    proof: G1Affine,
    value_fr: Fr,
    z_fr: Fr,
) -> Result<bool, KzgError> {
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

/// This function performs verification of a KZG proof where the commitment, proof,
/// evaluation value, and evaluation point are provided as compressed byte arrays
/// in big-endian format. It deserializes the inputs and delegates to the core
/// verification implementation.
///
/// # Arguments
///
/// * `commitment` - A 32-byte array containing a compressed G1 point representing 
///   the KZG commitment in big-endian format
/// * `proof` - A 32-byte array containing a compressed G1 point representing 
///   the KZG proof in big-endian format  
/// * `value_fr` - A 32-byte array containing a field element representing the
///   claimed polynomial value at the evaluation point in big-endian format
/// * `z_fr` - A 32-byte array containing a field element representing the
///   evaluation point in big-endian format
///
/// # Returns
///
/// * `Ok(true)` - If the proof is valid and verification succeeds
/// * `Ok(false)` - If the proof is invalid but no errors occurred during verification
/// * `Err(KzgError)` - If an error occurs during verification
///
/// # Examples
///
/// ```rust,no_run
/// use rust_kzg_bn254_verifier::verify::verify_proof;
/// use rust_kzg_bn254_primitives::consts::{SIZE_OF_G1_AFFINE_COMPRESSED, BYTES_PER_FIELD_ELEMENT};
///
/// let commitment = [0u8; SIZE_OF_G1_AFFINE_COMPRESSED]; // Compressed commitment
/// let proof = [0u8; SIZE_OF_G1_AFFINE_COMPRESSED];      // Compressed proof
/// let value = [0u8; BYTES_PER_FIELD_ELEMENT];           // Polynomial value
/// let z = [0u8; BYTES_PER_FIELD_ELEMENT];               // Evaluation point
///
/// match verify_proof(&commitment, &proof, &value, &z) {
///     Ok(true) => println!("Proof is valid!"),
///     Ok(false) => println!("Proof is invalid"),
///     Err(e) => println!("Verification error: {}", e),
/// }
/// ```
///     
/// # References
///
/// * [Ethereum Consensus Specs - KZG Proof Verification](https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_kzg_proof)   
pub fn verify_proof(
    commitment: &[u8; SIZE_OF_G1_AFFINE_COMPRESSED],
    proof: &[u8; SIZE_OF_G1_AFFINE_COMPRESSED],
    value_fr: &[u8; BYTES_PER_FIELD_ELEMENT],
    z_fr: &[u8; BYTES_PER_FIELD_ELEMENT],
) -> Result<bool, KzgError> {
    let commitment =
        G1Affine::read_point_from_bytes_native_compressed_be(commitment).map_err(|_| {
            KzgError::SerializationError("Failed to deserialize commitment".to_string())
        })?;
    let proof = G1Affine::read_point_from_bytes_native_compressed_be(proof)
        .map_err(|_| KzgError::SerializationError("Failed to deserialize proof".to_string()))?;
    let value_fr = Fr::deserialize_from_bytes_be(value_fr)
        .map_err(|_| KzgError::SerializationError("Failed to deserialize value_fr".to_string()))?;
    let z_fr = Fr::deserialize_from_bytes_be(z_fr)
        .map_err(|_| KzgError::SerializationError("Failed to deserialize z_fr".to_string()))?;
    verify_proof_impl(commitment, proof, value_fr, z_fr)
}

/// This function performs verification of a KZG proof for a blob where the blob data,
/// commitment, and proof are provided as byte arrays. It deserializes the compressed
/// inputs, validates the blob data, and delegates to the core verification implementation.
///
/// # Arguments
///
/// * `blob` - A byte slice containing the blob data to verify
/// * `commitment` - A 32-byte array containing a compressed G1 point representing 
///   the KZG commitment in big-endian format
/// * `proof` - A 32-byte array containing a compressed G1 point representing 
///   the KZG proof in big-endian format
///
/// # Returns
///
/// * `Ok(true)` - If the proof is valid and verification succeeds
/// * `Ok(false)` - If the proof is invalid but no errors occurred during verification
/// * `Err(KzgError)` - If an error occurs during verification
///
/// # Examples
///
/// ```rust,no_run
/// use rust_kzg_bn254_verifier::verify::verify_blob_kzg_proof;
/// use rust_kzg_bn254_primitives::consts::SIZE_OF_G1_AFFINE_COMPRESSED;
///
/// let blob_data = b"example blob data to verify";
/// let commitment = [0u8; SIZE_OF_G1_AFFINE_COMPRESSED]; // Compressed commitment
/// let proof = [0u8; SIZE_OF_G1_AFFINE_COMPRESSED];      // Compressed proof
///
/// match verify_blob_kzg_proof(blob_data, &commitment, &proof) {
///     Ok(true) => println!("Blob proof is valid!"),
///     Ok(false) => println!("Blob proof is invalid"),
///     Err(e) => println!("Verification error: {}", e),
/// }
/// ```
///
/// # References
///
/// * [Ethereum Consensus Specs - Blob KZG Proof Verification](https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#verify_blob_kzg_proof)
pub fn verify_blob_kzg_proof(
    blob: &[u8],
    commitment: &[u8; SIZE_OF_G1_AFFINE_COMPRESSED],
    proof: &[u8; SIZE_OF_G1_AFFINE_COMPRESSED],
) -> Result<bool, KzgError> {
    let blob = Blob::new(blob)?;
    let commitment =
        G1Affine::read_point_from_bytes_native_compressed_be(commitment).map_err(|_| {
            KzgError::SerializationError("Failed to deserialize commitment".to_string())
        })?;
    let proof = G1Affine::read_point_from_bytes_native_compressed_be(proof)
        .map_err(|_| KzgError::SerializationError("Failed to deserialize proof".to_string()))?;
    verify_blob_kzg_proof_impl(&blob, &commitment, &proof)
}

/// This function performs verification of a KZG proof for a blob where the blob,
/// commitment, and proof are provided as deserialized objects. It implements the
/// blob-specific KZG proof verification algorithm that includes challenge generation
/// using the Fiat-Shamir transform and polynomial evaluation.
///
/// # Arguments
///
/// * `blob` - A `Blob` object containing the data that was committed to.
/// * `commitment` - A `G1Affine` point representing the KZG commitment to the blob's polynomial
/// * `proof` - A `G1Affine` point representing the KZG proof for the blob evaluation
///
/// # Returns
///
/// * `Ok(true)` - If the proof is valid and verification succeeds
/// * `Ok(false)` - If the proof is invalid but no errors occurred during verification
/// * `Err(KzgError)` - If an error occurs during verification
///
/// # Examples
///
/// ```rust,no_run
/// use rust_kzg_bn254_verifier::verify::verify_blob_kzg_proof_impl;
/// use rust_kzg_bn254_primitives::blob::Blob;
/// use ark_bn254::G1Affine;
/// use ark_ec::AffineRepr;
///
/// // Note: This is a simplified example. In practice, you would have
/// // valid blob data, commitment, and proof from a KZG setup
/// let blob_data = vec![0u8; 32]; // Example: 32 bytes of zero data
/// let blob = Blob::new(&blob_data).expect("Valid blob");
/// let commitment = G1Affine::generator(); // Example commitment
/// let proof = G1Affine::generator();      // Example proof
///
/// match verify_blob_kzg_proof_impl(&blob, &commitment, &proof) {
///     Ok(true) => println!("Blob proof is valid!"),
///     Ok(false) => println!("Blob proof is invalid"),
///     Err(e) => println!("Verification error: {}", e),
/// }
/// ```
pub fn verify_blob_kzg_proof_impl(
    blob: &Blob,
    commitment: &G1Affine,
    proof: &G1Affine,
) -> Result<bool, KzgError> {
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
    let evaluation_challenge = helpers::compute_challenge(blob, commitment)?;

    // Evaluate the polynomial in evaluation form
    let y = helpers::evaluate_polynomial_in_evaluation_form(&polynomial, &evaluation_challenge)?;

    // Verify the KZG proof
    verify_proof_impl(*commitment, *proof, y, evaluation_challenge)
}
