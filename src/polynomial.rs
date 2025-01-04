use crate::{errors::PolynomialError, helpers};
use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::Zero;

/// Represents the format in which a polynomial is stored.
#[derive(Clone, Debug, PartialEq, Copy)]
pub enum PolynomialFormat {
    /// Polynomial is in coefficient form.
    InCoefficientForm,
    /// Polynomial is in evaluation form.
    InEvaluationForm,
}

/// A polynomial over the BN254 field.
#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial {
    /// The elements of the polynomial, either in coefficient or evaluation form.
    elements: Vec<Fr>,
    /// The size of the blob after padding with zeros to match BN254 field element sizes.
    length_of_padded_blob: usize,
    /// The current format of the polynomial.
    form: PolynomialFormat,
}

impl Polynomial {
    /// Constructs a new `Polynomial` with the provided elements.
    ///
    /// This function pads the input elements with zeros to the next power of two to
    /// facilitate FFT operations. The `length_of_padded_blob` specifies the size
    /// of the blob after padding.
    ///
    /// # Arguments
    ///
    /// * `elements` - A slice of `Fr` elements representing the polynomial.
    /// * `length_of_padded_blob` - The length of the padded blob.
    /// * `form` - The format of the polynomial (`InCoefficientForm` or `InEvaluationForm`).
    ///
    /// # Errors
    ///
    /// Returns a `PolynomialError::GenericError` if the `elements` slice is empty.
    pub fn new(
        elements: &[Fr],
        length_of_padded_blob: usize,
        form: PolynomialFormat,
    ) -> Result<Self, PolynomialError> {
        if elements.is_empty() {
            return Err(PolynomialError::GenericError(
                "elements are empty".to_string(),
            ));
        }

        // Optimize padding by resizing the vector with zeros up to the next power of two.
        let next_pow = elements.len().next_power_of_two();
        let mut padded_input_fr = elements.to_vec();
        padded_input_fr.resize(next_pow, Fr::zero());

        Ok(Polynomial {
            elements: padded_input_fr,
            length_of_padded_blob,
            form,
        })
    }

    /// Returns the length of the padded blob.
    ///
    /// # Returns
    ///
    /// The size of the padded blob as a `usize`.
    pub fn get_length_of_padded_blob(&self) -> usize {
        self.length_of_padded_blob
    }

    /// Returns the current format of the polynomial.
    ///
    /// # Returns
    ///
    /// A `PolynomialFormat` indicating whether the polynomial is in coefficient or evaluation form.
    pub fn get_form(&self) -> PolynomialFormat {
        self.form
    }

    /// Returns the number of elements in the polynomial.
    ///
    /// # Returns
    ///
    /// The length of the `elements` vector as a `usize`.
    pub fn len(&self) -> usize {
        self.elements.len()
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
    pub fn get_at_index(&self, i: usize) -> Option<&Fr> {
        self.elements.get(i)
    }

    /// Checks whether the polynomial has no elements.
    ///
    /// # Returns
    ///
    /// `true` if the `elements` vector is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Converts all `Fr` elements in the polynomial to a single big-endian byte vector.
    ///
    /// This method delegates the conversion to the `helpers::to_byte_array` function,
    /// passing the elements and the length of the padded blob.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the big-endian byte representation of the polynomial elements.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        helpers::to_byte_array(&self.elements, self.length_of_padded_blob)
    }

    /// Returns a clone of the elements as a `Vec<Fr>`.
    ///
    /// # Returns
    ///
    /// A `Vec<Fr>` containing the elements of the polynomial.
    pub fn to_vec(&self) -> Vec<Fr> {
        self.elements.clone()
    }

    /// Transforms the polynomial to the specified format.
    ///
    /// If the polynomial is already in the desired format, an error is returned.
    /// Otherwise, it performs an FFT or inverse FFT to convert between coefficient and evaluation forms.
    ///
    /// # Arguments
    ///
    /// * `form` - The target `PolynomialFormat` to transform the polynomial into.
    ///
    /// # Errors
    ///
    /// Returns a `PolynomialError::IncorrectFormError` if the polynomial is already in the desired form.
    /// Propagates errors from FFT operations.
    pub fn transform_to_form(&mut self, form: PolynomialFormat) -> Result<(), PolynomialError> {
        if self.form == form {
            return Err(PolynomialError::IncorrectFormError(
                "Polynomial is already in the given form".to_string(),
            ));
        }

        match form {
            PolynomialFormat::InCoefficientForm => {
                // Transform from evaluation form to coefficient form using inverse FFT
                self.fft_on_elements(false)?;
            },
            PolynomialFormat::InEvaluationForm => {
                // Transform from coefficient form to evaluation form using FFT
                self.fft_on_elements(true)?;
            },
        }

        self.form = form;
        Ok(())
    }

    /// Performs an FFT or inverse FFT on the polynomial's elements.
    ///
    /// This method modifies the `elements` vector in place by applying the FFT or inverse FFT.
    ///
    /// # Arguments
    ///
    /// * `inverse` - If `true`, performs an inverse FFT; otherwise, performs a forward FFT.
    ///
    /// # Errors
    ///
    /// Returns a `PolynomialError` if the FFT operation fails.
    pub fn fft_on_elements(&mut self, inverse: bool) -> Result<(), PolynomialError> {
        let fft_result = Self::fft(&self.elements, inverse);
        self.elements = fft_result?;
        Ok(())
    }

    /// Performs an FFT or inverse FFT on a vector of `Fr` elements.
    ///
    /// This is a helper function that utilizes the `ark-poly` crate to perform the FFT operations.
    ///
    /// # Arguments
    ///
    /// * `vals` - A reference to the vector of `Fr` elements to transform.
    /// * `inverse` - If `true`, performs an inverse FFT; otherwise, performs a forward FFT.
    ///
    /// # Returns
    ///
    /// A `Result` containing the transformed vector of `Fr` elements or a `PolynomialError` if the operation fails.
    pub fn fft(vals: &Vec<Fr>, inverse: bool) -> Result<Vec<Fr>, PolynomialError> {
        let length = vals.len();

        let domain = GeneralEvaluationDomain::<Fr>::new(length).ok_or_else(|| {
            PolynomialError::FFTError("Failed to construct domain for FFT".to_string())
        })?;

        let result = if inverse {
            domain.ifft(vals)
        } else {
            domain.fft(vals)
        };

        Ok(result)
    }
}
