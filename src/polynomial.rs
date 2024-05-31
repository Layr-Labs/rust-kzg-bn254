use crate::{errors::PolynomialError, helpers};
use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::Zero;

#[derive(Clone, Debug, PartialEq, Copy)]
pub enum PolynomialFormat {
    InCoefficientForm,
    InEvaluationForm,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial {
    elements: Vec<Fr>,
    length_of_padded_blob: usize,
    length_of_padded_blob_as_fr_vector: usize,
    form: PolynomialFormat,
}

impl Polynomial {
    /// Constructs a new `Polynomial` with a given vector of `Fr` elements.
    pub fn new(
        elements: &Vec<Fr>,
        length_of_padded_blob: usize,
        form: PolynomialFormat,
    ) -> Result<Self, PolynomialError> {
        if elements.is_empty() {
            return Err(PolynomialError::GenericError(
                "elements are empty".to_string(),
            ));
        }
        let mut padded_input_fr = vec![];
        for i in 0..elements.len().next_power_of_two() {
            if i < elements.len() {
                padded_input_fr.push(elements[i]);
            } else {
                padded_input_fr.push(Fr::zero());
            }
        }
        Ok(Polynomial {
            elements: padded_input_fr,
            length_of_padded_blob,
            length_of_padded_blob_as_fr_vector: elements.len(),
            form,
        })
    }

    pub fn get_length_of_padded_blob_as_fr_vector(&self) -> usize {
        self.length_of_padded_blob_as_fr_vector
    }

    /// Returns the form of the polynomial.
    pub fn get_form(&self) -> PolynomialFormat {
        self.form
    }

    /// Returns the number of elements in the polynomial.
    pub fn len(&self) -> usize {
        self.elements.len()
    }

    pub fn get_at_index(&self, i: usize) -> Option<&Fr> {
        self.elements.get(i)
    }

    /// Checks if the polynomial has no elements.
    pub fn is_empty(&self) -> bool {
        self.elements.is_empty()
    }

    /// Converts all `Fr` elements in the `Polynomial` to a single byte vector.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        helpers::to_byte_array(&self.elements, self.length_of_padded_blob)
    }

    /// Returns a clone of the elements as a `Vec<Fr>`.
    pub fn to_vec(&self) -> Vec<Fr> {
        self.elements.clone()
    }

    /// Helper function to transform the polynomial to the given form.
    pub fn transform_to_form(&mut self, form: PolynomialFormat) -> Result<(), PolynomialError> {
        if self.form == form {
            return Err(PolynomialError::IncorrectFormError(
                "Polynomial is already in the given form".to_string(),
            ));
        }

        match form {
            PolynomialFormat::InCoefficientForm => {
                // Transform from evaluation form to coefficient form using IFFT
                self.fft_on_elements(true)
            },
            PolynomialFormat::InEvaluationForm => {
                // Transform from coefficient form to evaluation form using FFT
                self.fft_on_elements(false)
            },
        }
    }

    /// Performs an fft or ifft on the polynomial's elements
    pub fn fft_on_elements(&mut self, inverse: bool) -> Result<(), PolynomialError> {
        let fft_result = Self::fft(&self.to_vec(), inverse);
        match fft_result {
            Ok(fft_result) => {
                self.elements = fft_result;
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    /// helper function to perform fft or ifft on a vector of Fr
    pub fn fft(vals: &Vec<Fr>, inverse: bool) -> Result<Vec<Fr>, PolynomialError> {
        let length = vals.len();

        match GeneralEvaluationDomain::<Fr>::new(length) {
            Some(domain) => {
                if inverse {
                    let result = domain.ifft(vals);
                    Ok(result)
                } else {
                    let result = domain.fft(vals);
                    Ok(result)
                }
            },
            None => Err(PolynomialError::FFTError(
                "Failed to construct domain for FFT".to_string(),
            )),
        }
    }
}
