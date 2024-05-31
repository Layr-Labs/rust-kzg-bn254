use crate::{errors::PolynomialError, helpers};
use ark_bn254::Fr;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::Zero;

#[derive(Clone, Debug, PartialEq)]
pub struct Polynomial {
    elements: Vec<Fr>,
    length_of_padded_blob: usize,
    length_of_padded_blob_as_fr_vector: usize,
}

impl Polynomial {
    /// Constructs a new `Polynomial` with a given vector of `Fr` elements.
    pub fn new(elements: &Vec<Fr>, length_of_padded_blob: usize) -> Result<Self, PolynomialError> {
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
        })
    }

    pub fn get_length_of_padded_blob_as_fr_vector(&self) -> usize {
        self.length_of_padded_blob_as_fr_vector
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
    pub fn ifft_on_elements(&mut self) -> Result<(), PolynomialError> {
        let ifft_result = Self::ifft(&self.to_vec());
        match ifft_result {
            Ok(ifft_result) => {
                self.elements = ifft_result;
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    pub fn fft_on_elements(&mut self) -> Result<(), PolynomialError> {
        let fft_result = Self::fft(&self.to_vec());
        match fft_result {
            Ok(fft_result) => {
                self.elements = fft_result;
                Ok(())
            },
            Err(e) => Err(e),
        }
    }

    pub fn ifft(vals: &Vec<Fr>) -> Result<Vec<Fr>, PolynomialError> {
        let length = vals.len();

        if !length.is_power_of_two() {
            return Err(PolynomialError::FFTError(format!(
                "Length of fr vec provided is not a power of 2: {}",
                vals.len()
            )));
        }

        match GeneralEvaluationDomain::<Fr>::new(length) {
            Some(domain) => {
                let result = domain.ifft(vals);
                Ok(result)
            },
            None => Err(PolynomialError::FFTError(
                "Failed to construct domain for IFFT".to_string(),
            )),
        }
    }

    pub fn fft(vals: &Vec<Fr>) -> Result<Vec<Fr>, PolynomialError> {
        let length = vals.len();

        if !length.is_power_of_two() {
            return Err(PolynomialError::FFTError(format!(
                "Length of fr vec provided is not a power of 2: {}",
                vals.len()
            )));
        }

        match GeneralEvaluationDomain::<Fr>::new(length) {
            Some(domain) => {
                let result = domain.fft(vals);
                Ok(result)
            },
            None => Err(PolynomialError::FFTError(
                "Failed to construct domain for FFT".to_string(),
            )),
        }
    }
}
