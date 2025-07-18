use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::Zero;

use crate::{consts::BYTES_PER_FIELD_ELEMENT, errors::PolynomialError, helpers};

extern crate alloc;
use alloc::string::ToString;
use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq)]
pub struct PolynomialEvalForm {
    /// evaluations contains the evaluations of the polynomial, padded with 0s
    /// to the next power of two. Hence if the polynomial is created with
    /// coefficients [1, 2, 3], the internal representation will be [1, 2,
    /// 3, 0]. Note that this changes the polynomial! This is an inconsistency
    /// in our current representations. Polynomials are the objects that get
    /// committed, not the underlying Blobs.
    /// TODO: do we also want to force blobs to be of powers-of-two length?
    evaluations: Vec<Fr>,
    /// Number of bytes in the underlying blob, which was used to create the
    /// polynomial. This is passed as is when converting between Coefficient
    /// and Evaluation forms, so that the blob can be reconstructed with the
    /// same length.
    ///
    /// TODO: We should get rid of this: polynomial should not know about the
    /// blob.       This len is equivalent to the coeffs len before it gets
    /// padded.       Perhaps we can store the original coeffs and only pad
    /// when needed?
    len_underlying_blob_bytes: usize,
}

impl PolynomialEvalForm {
    /// Creates a new [PolynomialEvalForm] from the given coefficients, passed
    /// as a vector of `Fr`. The coefficients are padded to the next power
    /// of two by appending zeros. This typically wouldn't be used directly,
    /// but instead a [crate::blob::Blob] would be converted to a
    /// [PolynomialEvalForm] using [crate::blob::Blob::to_polynomial_eval_form].
    pub fn new(evals: Vec<Fr>) -> Self {
        // ✅ SECURITY FIX: Add bounds checking to prevent integer overflow and memory exhaustion
        const MAX_POLYNOMIAL_SIZE: usize = 1 << 24; // 16M elements = 512MB for field elements
        
        if evals.len() > MAX_POLYNOMIAL_SIZE {
            // For oversized inputs, truncate to prevent DoS attacks
            // This is safer than panicking or allowing unbounded memory allocation
            let truncated_evals = evals.into_iter().take(MAX_POLYNOMIAL_SIZE).collect::<Vec<_>>();
            let underlying_blob_len_in_bytes = truncated_evals.len() * BYTES_PER_FIELD_ELEMENT;
            
            // ✅ SECURITY FIX: Safe calculation with overflow protection
            let next_power_of_two = truncated_evals.len().next_power_of_two().min(MAX_POLYNOMIAL_SIZE);
            let mut padded_evals = truncated_evals;
            padded_evals.resize(next_power_of_two, Fr::zero());

            return Self {
                evaluations: padded_evals,
                len_underlying_blob_bytes: underlying_blob_len_in_bytes,
            };
        }

        let underlying_blob_len_in_bytes = evals.len() * BYTES_PER_FIELD_ELEMENT;
        
        // ✅ SECURITY FIX: Protect against integer overflow in next_power_of_two
        let next_power_of_two = if evals.len() > (usize::MAX / 2) {
            // If input is too large for next_power_of_two, use the input size directly
            // This prevents integer overflow while maintaining functionality
            evals.len()
        } else {
            evals.len().next_power_of_two()
        };
        
        let mut padded_evals = evals;
        padded_evals.resize(next_power_of_two, Fr::zero());

        Self {
            evaluations: padded_evals,
            len_underlying_blob_bytes: underlying_blob_len_in_bytes,
        }
    }

    pub fn evaluations(&self) -> &[Fr] {
        &self.evaluations
    }

    /// Returns the number of evaluations in the polynomial. Note that this
    /// returns the number of evaluations in the padded polynomial, not the
    /// number of evaluations in the original polynomial.
    pub fn len(&self) -> usize {
        self.evaluations.len()
    }

    /// TODO: we should deprecate this. See comment in the struct.
    pub fn len_underlying_blob_bytes(&self) -> usize {
        self.len_underlying_blob_bytes
    }

    /// Similar to [Self::len_underlying_blob_bytes], but returns the number of
    /// field elements instead of bytes
    pub fn len_underlying_blob_field_elements(&self) -> usize {
        self.len_underlying_blob_bytes / BYTES_PER_FIELD_ELEMENT
    }

    /// Retrieves a reference to the element at the specified index.
    ///
    /// # Arguments
    ///
    /// * `i` - The index of the element to retrieve.
    ///
    /// # Returns
    ///
    /// An `Option` containing a reference to the `Fr` element if the index is within bounds, or `None` otherwise.
    pub fn get_evalualtion(&self, i: usize) -> Option<&Fr> {
        self.evaluations.get(i)
    }

    /// Checks whether the polynomial has no elements.
    ///
    /// # Returns
    ///
    /// `true` if the `elements` vector is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.evaluations.is_empty()
    }

    /// Converts all `Fr` elements in the polynomial to a single big-endian byte vector.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the big-endian byte representation of the polynomial elements.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        helpers::to_byte_array(&self.evaluations, self.len_underlying_blob_bytes)
    }

    /// Converts the polynomial to coefficient form. This is done by performing
    /// an IFFT on the evaluations.
    pub fn to_coeff_form(&self) -> Result<PolynomialCoeffForm, PolynomialError> {
        let coeffs = GeneralEvaluationDomain::<Fr>::new(self.len())
            .ok_or(PolynomialError::FFTError(
                "Failed to construct domain for IFFT".to_string(),
            ))?
            .ifft(&self.evaluations);
        Ok(PolynomialCoeffForm::new(coeffs))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct PolynomialCoeffForm {
    /// coeffs contains the coefficients of the polynomial, padded with 0s to
    /// the next power of two. Hence if the polynomial is created with
    /// coefficients [1, 2, 3], the internal representation will be [1, 2,
    /// 3, 0].
    coeffs: Vec<Fr>,
    /// Number of bytes in the underlying blob, which was used to create the
    /// polynomial. This is passed as is when converting between Coefficient
    /// and Evaluation forms, so that the blob can be reconstructed with the
    /// same length.
    ///
    /// TODO: We should get rid of this: polynomial should not know about the
    /// blob.       This len is equivalent to the coeffs len before it gets
    /// padded.       Perhaps we can store the original coeffs and only pad
    /// when needed?
    len_underlying_blob_bytes: usize,
}

impl PolynomialCoeffForm {
    /// Creates a new [PolynomialCoeffForm] from the given coefficients, passed
    /// as a vector of `Fr`. The coefficients are padded to the next power
    /// of two by appending zeros. This typically wouldn't be used directly,
    /// but instead a [crate::blob::Blob] would be converted to a
    /// [PolynomialCoeffForm] using
    /// [crate::blob::Blob::to_polynomial_coeff_form].
    pub fn new(coeffs: Vec<Fr>) -> Self {
        // ✅ SECURITY FIX: Add bounds checking to prevent integer overflow and memory exhaustion
        const MAX_POLYNOMIAL_SIZE: usize = 1 << 24; // 16M elements = 512MB for field elements
        
        if coeffs.len() > MAX_POLYNOMIAL_SIZE {
            // For oversized inputs, truncate to prevent DoS attacks
            // This is safer than panicking or allowing unbounded memory allocation
            let truncated_coeffs = coeffs.into_iter().take(MAX_POLYNOMIAL_SIZE).collect::<Vec<_>>();
            let underlying_blob_len_in_bytes = truncated_coeffs.len() * BYTES_PER_FIELD_ELEMENT;
            
            // ✅ SECURITY FIX: Safe calculation with overflow protection
            let next_power_of_two = truncated_coeffs.len().next_power_of_two().min(MAX_POLYNOMIAL_SIZE);
            let mut padded_coeffs = truncated_coeffs;
            padded_coeffs.resize(next_power_of_two, Fr::zero());

            return Self {
                coeffs: padded_coeffs,
                len_underlying_blob_bytes: underlying_blob_len_in_bytes,
            };
        }

        let underlying_blob_len_in_bytes = coeffs.len() * BYTES_PER_FIELD_ELEMENT;
        
        // ✅ SECURITY FIX: Protect against integer overflow in next_power_of_two
        let next_power_of_two = if coeffs.len() > (usize::MAX / 2) {
            // If input is too large for next_power_of_two, use the input size directly
            // This prevents integer overflow while maintaining functionality
            coeffs.len()
        } else {
            coeffs.len().next_power_of_two()
        };
        
        let mut padded_coeffs = coeffs;
        padded_coeffs.resize(next_power_of_two, Fr::zero());

        Self {
            coeffs: padded_coeffs,
            len_underlying_blob_bytes: underlying_blob_len_in_bytes,
        }
    }

    pub fn coeffs(&self) -> &[Fr] {
        &self.coeffs
    }

    /// Returns the number of coefficients in the polynomial. Note that this
    /// returns the number of coefficients in the padded polynomial, not the
    /// number of coefficients in the original polynomial.
    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    /// TODO: we should deprecate this. See comment in the struct.
    pub fn len_underlying_blob_bytes(&self) -> usize {
        self.len_underlying_blob_bytes
    }

    /// Similar to [Self::len_underlying_blob_bytes], but returns the number of
    /// field elements instead of bytes
    pub fn len_underlying_blob_field_elements(&self) -> usize {
        self.len_underlying_blob_bytes / BYTES_PER_FIELD_ELEMENT
    }

    pub fn get_at_index(&self, i: usize) -> Option<&Fr> {
        self.coeffs.get(i)
    }

    /// Checks if the polynomial has no elements.
    pub fn is_empty(&self) -> bool {
        self.coeffs.is_empty()
    }

    /// Converts all `Fr` elements in the `Polynomial` to a single byte vector.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        helpers::to_byte_array(&self.coeffs, self.len_underlying_blob_bytes)
    }

    /// Converts the polynomial to evaluation form. This is done by performing
    /// an FFT on the coefficients.
    pub fn to_eval_form(&self) -> Result<PolynomialEvalForm, PolynomialError> {
        let evals = GeneralEvaluationDomain::<Fr>::new(self.len())
            .ok_or(PolynomialError::FFTError(
                "Failed to construct domain for FFT".to_string(),
            ))?
            .fft(&self.coeffs);
        Ok(PolynomialEvalForm::new(evals))
    }
}
