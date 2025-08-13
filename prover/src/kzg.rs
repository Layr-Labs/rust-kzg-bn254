use ark_bn254::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::{ops::Div, Zero};
use num_traits::ToPrimitive;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rust_kzg_bn254_primitives::{
    blob::Blob,
    errors::KzgError,
    helpers,
    polynomial::{PolynomialCoeffForm, PolynomialEvalForm},
};

use crate::srs::SRS;

/// Main interesting struct of the rust-kzg-bn254 crate.
/// [Kzg] is a struct that holds the SRS points in monomial form, and
/// provides methods for committing to a blob, (either via a [Blob] itself,
/// or a [PolynomialCoeffForm] or [PolynomialEvalForm]), and generating and
/// verifying proofs.
///
/// The [Blob] and [PolynomialCoeffForm]/[PolynomialEvalForm] structs are mostly
/// <https://en.wikipedia.org/wiki/Passive_data_structure> with
/// constructor and few helper methods.
#[derive(Debug, PartialEq, Clone)]
pub struct KZG {
    expanded_roots_of_unity: Vec<Fr>,
}

impl Default for KZG {
    fn default() -> Self {
        Self::new()
    }
}

impl KZG {
    pub fn new() -> Self {
        Self {
            expanded_roots_of_unity: vec![],
        }
    }

    /// Calculates the roots of unities and assigns it to the struct
    ///
    /// # Arguments
    /// * `length_of_data_after_padding` - Length of the blob data after padding in bytes.
    ///
    /// # Returns
    /// * `Result<(), KzgError>`
    ///
    /// # Details
    /// - Generates roots of unity needed for FFT operations
    ///
    /// # Example
    /// ```
    /// use rust_kzg_bn254_prover::kzg::KZG;
    /// use rust_kzg_bn254_primitives::blob::Blob;
    /// use ark_std::One;
    /// use ark_bn254::Fr;
    ///
    /// let mut kzg = KZG::new();
    /// let input_blob = Blob::from_raw_data(b"test blob data");
    /// kzg.calculate_and_store_roots_of_unity(input_blob.len().try_into().unwrap()).unwrap();
    /// ```
    pub fn calculate_and_store_roots_of_unity(
        &mut self,
        length_of_data_after_padding: u64,
    ) -> Result<(), KzgError> {
        let roots_of_unity = helpers::calculate_roots_of_unity(length_of_data_after_padding)?;
        self.expanded_roots_of_unity = roots_of_unity;
        Ok(())
    }

    pub fn get_roots_of_unities(&self) -> Vec<Fr> {
        self.expanded_roots_of_unity.clone()
    }

    /// helper function to get the
    pub fn get_nth_root_of_unity(&self, i: usize) -> Option<&Fr> {
        self.expanded_roots_of_unity.get(i)
    }

    /// Commit the polynomial with the srs values loaded into [Kzg].
    pub fn commit_eval_form(
        &self,
        polynomial: &PolynomialEvalForm,
        srs: &SRS,
    ) -> Result<G1Affine, KzgError> {
        if polynomial.len() > srs.g1.len() {
            return Err(KzgError::SrsCapacityExceeded {
                polynomial_len: polynomial.len(),
                srs_len: srs.g1.len(),
            });
        }

        // When the polynomial is in evaluation form, use IFFT to transform monomial srs
        // points to lagrange form.
        let bases = self.g1_ifft(polynomial.len(), srs)?;

        match G1Projective::msm(&bases, polynomial.evaluations()) {
            Ok(res) => Ok(res.into_affine()),
            Err(err) => Err(KzgError::CommitError(err.to_string())),
        }
    }

    /// Commit the polynomial with the srs values loaded into [Kzg].
    pub fn commit_coeff_form(
        &self,
        polynomial: &PolynomialCoeffForm,
        srs: &SRS,
    ) -> Result<G1Affine, KzgError> {
        if polynomial.len() > srs.g1.len() {
            return Err(KzgError::SerializationError(
                "polynomial length is not correct".to_string(),
            ));
        }
        // When the polynomial is in coefficient form, use the original srs points (in
        // monomial form).
        let bases = srs.g1[..polynomial.len()].to_vec();

        match G1Projective::msm(&bases, polynomial.coeffs()) {
            Ok(res) => Ok(res.into_affine()),
            Err(err) => Err(KzgError::CommitError(err.to_string())),
        }
    }

    /// Helper function for `compute_kzg_proof()` and `compute_blob_kzg_proof()`
    fn compute_proof_impl(
        &self,
        polynomial: &PolynomialEvalForm,
        z_fr: &Fr,
        srs: &SRS,
    ) -> Result<G1Affine, KzgError> {
        // Verify polynomial length matches that of the roots of unity
        if polynomial.len() != self.expanded_roots_of_unity.len() {
            return Err(KzgError::GenericError(
                "inconsistent length between blob and root of unities".to_string(),
            ));
        }

        let eval_fr = polynomial.evaluations();
        // Pre-allocate vector for shifted polynomial p(x) - y
        let mut poly_shift: Vec<Fr> = Vec::with_capacity(eval_fr.len());

        // Evaluate polynomial at the point z
        // This gives us y = p(z)
        let y_fr = helpers::evaluate_polynomial_in_evaluation_form(polynomial, z_fr)?;

        // Compute p(x) - y for each evaluation point
        // This is the numerator of the quotient polynomial
        for fr in eval_fr {
            poly_shift.push(*fr - y_fr);
        }

        // Compute denominator polynomial (x - z) at each root of unity
        let mut denom_poly = Vec::<Fr>::with_capacity(self.expanded_roots_of_unity.len());
        for root_of_unity in self.expanded_roots_of_unity.iter().take(eval_fr.len()) {
            denom_poly.push(*root_of_unity - z_fr);
        }

        // Pre-allocate vector for quotient polynomial evaluations
        let mut quotient_poly = Vec::<Fr>::with_capacity(self.expanded_roots_of_unity.len());

        // Compute quotient polynomial q(x) = (p(x) - y)/(x - z) at each root of unity
        for i in 0..self.expanded_roots_of_unity.len() {
            if denom_poly[i].is_zero() {
                // Special case: when x = z, use L'Hôpital's rule
                // Compute the derivative evaluation instead
                quotient_poly.push(self.compute_quotient_eval_on_domain(z_fr, eval_fr, &y_fr));
            } else {
                // Normal case: direct polynomial division
                quotient_poly.push(poly_shift[i].div(denom_poly[i]));
            }
        }

        let quotient_poly_eval_form = PolynomialEvalForm::new(quotient_poly)?;
        self.commit_eval_form(&quotient_poly_eval_form, srs)
    }

    /// commit to a [Blob], by transforming it into a [PolynomialEvalForm] and
    /// then calling [Kzg::commit_eval_form].
    pub fn commit_blob(&self, blob: &Blob, srs: &SRS) -> Result<G1Affine, KzgError> {
        let polynomial = blob.to_polynomial_eval_form()?;
        self.commit_eval_form(&polynomial, srs)
    }

    pub fn compute_proof_with_known_z_fr_index(
        &self,
        polynomial: &PolynomialEvalForm,
        index: u64,
        srs: &SRS,
    ) -> Result<G1Affine, KzgError> {
        // Convert u64 index to usize for array indexing
        let usized_index = index.to_usize().ok_or(KzgError::GenericError(
            "Index conversion to usize failed".to_string(),
        ))?;

        // Get the root of unity at the specified index
        let z_fr = self
            .get_nth_root_of_unity(usized_index)
            .ok_or_else(|| KzgError::GenericError("Root of unity not found".to_string()))?;

        // Compute the KZG proof at the selected root of unity
        // This delegates to the main proof computation function
        // using our selected evaluation point
        self.compute_proof(polynomial, z_fr, srs)
    }

    /// Compute a kzg proof from a polynomial in evaluation form.
    /// We don't currently support proofs for polynomials in coefficient form,
    /// but one can take the FFT of the polynomial in coefficient form to
    /// get the polynomial in evaluation form. This is available via the
    /// method [PolynomialCoeffForm::to_eval_form].
    /// TODO(anupsv): Accept bytes instead of Fr element. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/29
    pub fn compute_proof(
        &self,
        polynomial: &PolynomialEvalForm,
        z_fr: &Fr,
        srs: &SRS,
    ) -> Result<G1Affine, KzgError> {
        // Verify that polynomial length matches roots of unity length
        if polynomial.len() != self.expanded_roots_of_unity.len() {
            return Err(KzgError::GenericError(
                "inconsistent length between blob and root of unities".to_string(),
            ));
        }

        // Call the implementation to compute the actual proof
        // This will:
        // 1. Evaluate polynomial at z
        // 2. Compute quotient polynomial q(x) = (p(x) - p(z)) / (x - z)
        // 3. Generate KZG proof as commitment to q(x)
        self.compute_proof_impl(polynomial, z_fr, srs)
    }

    /// refer to DA for more context
    pub fn compute_quotient_eval_on_domain(&self, z_fr: &Fr, eval_fr: &[Fr], value_fr: &Fr) -> Fr {
        let mut quotient = Fr::zero();
        let mut fi: Fr = Fr::zero();
        let mut numerator: Fr = Fr::zero();
        let mut denominator: Fr = Fr::zero();
        let mut temp: Fr = Fr::zero();

        self.expanded_roots_of_unity
            .iter()
            .enumerate()
            .for_each(|(i, omega_i)| {
                if *omega_i == *z_fr {
                    return;
                }
                fi = eval_fr[i] - value_fr;
                numerator = fi * omega_i;
                denominator = z_fr - omega_i;
                denominator *= z_fr;
                if denominator.is_zero() {
                    return;
                }
                temp = numerator.div(denominator);
                quotient += temp;
            });

        quotient
    }

    /// function to compute the inverse FFT
    pub fn g1_ifft(&self, length: usize, srs: &SRS) -> Result<Vec<G1Affine>, KzgError> {
        // is not power of 2
        if !length.is_power_of_two() {
            return Err(KzgError::FFTError(
                "length provided is not a power of 2".to_string(),
            ));
        }

        let points_projective: Vec<G1Projective> = srs.g1[..length]
            .par_iter()
            .map(|&p| G1Projective::from(p))
            .collect();
        let ifft_result: Vec<_> = GeneralEvaluationDomain::<Fr>::new(length)
            .ok_or(KzgError::FFTError(
                "Could not perform IFFT due to domain consturction error".to_string(),
            ))?
            .ifft(&points_projective)
            .par_iter()
            .map(|p| p.into_affine())
            .collect();

        Ok(ifft_result)
    }

    /// TODO(anupsv): Match 4844 specs w.r.t to the inputs. Ref: https://github.com/Layr-Labs/rust-kzg-bn254/issues/30
    pub fn compute_blob_proof(
        &self,
        blob: &Blob,
        commitment: &G1Affine,
        srs: &SRS,
    ) -> Result<G1Affine, KzgError> {
        // This checks: not identity point, on curve, and in correct subgroup, is not generator point
        helpers::validate_g1_point(commitment)?;

        // Convert the blob to a polynomial in evaluation form
        // This is necessary because KZG proofs work with polynomials
        let blob_poly = blob.to_polynomial_eval_form()?;

        // Compute the evaluation challenge using Fiat-Shamir heuristic
        // This challenge determines the point at which we evaluate the polynomial
        let evaluation_challenge = helpers::compute_challenge(blob, commitment)?;

        // Compute the actual KZG proof using the polynomial and evaluation point
        // This creates a proof that the polynomial evaluates to a specific value at the challenge point
        // The proof is a single G1 point that can be used to verify the evaluation
        self.compute_proof_impl(&blob_poly, &evaluation_challenge, srs)
    }
}
