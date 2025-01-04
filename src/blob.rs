use crate::{
    errors::BlobError,
    helpers,
    polynomial::{Polynomial, PolynomialFormat},
};

/// A blob aligned with the Eigen DA specification.
///
/// The `Blob` struct encapsulates binary data and manages padding according to
/// DA specifications. It provides functionality to pad, remove padding, and
/// convert the blob data into a `Polynomial`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob {
    /// The binary data contained within the blob.
    blob_data: Vec<u8>,
    /// Indicates whether the blob data has been padded.
    is_padded: bool,
    /// The length of the blob data after padding.
    length_after_padding: usize,
}

impl Blob {
    /// Creates a new `Blob` from the given data without padding.
    ///
    /// # Arguments
    ///
    /// * `blob_data` - A `Vec<u8>` representing the initial binary data of the blob.
    pub fn new(blob_data: Vec<u8>) -> Self {
        Blob {
            blob_data,
            is_padded: false,
            length_after_padding: 0,
        }
    }

    /// Returns the length of the blob data after padding.
    ///
    /// If the blob is not padded, this will return `0`.
    ///
    /// # Returns
    ///
    /// The length of the blob after padding as a `usize`.
    pub fn get_length_after_padding(&self) -> usize {
        self.length_after_padding
    }

    /// Checks whether the blob data is padded.
    ///
    /// # Returns
    ///
    /// `true` if the blob data is padded, `false` otherwise.
    pub fn is_padded(&self) -> bool {
        self.is_padded
    }

    /// Creates a new `Blob` from the provided byte slice and pads it according to DA specifications.
    ///
    /// This function applies padding to the input data to align with DA specs, typically by adding
    /// zero bytes until the data meets the required size constraints.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice (`&[u8]`) representing the initial data to be padded.
    ///
    /// # Returns
    ///
    /// A new padded `Blob`.
    pub fn from_bytes_and_pad(input: &[u8]) -> Self {
        let padded_input = helpers::convert_by_padding_empty_byte(input);
        let length_after_padding = padded_input.len();
        Blob {
            blob_data: padded_input,
            is_padded: true,
            length_after_padding,
        }
    }

    /// Creates a new `Blob` from the provided byte slice, assuming it's already padded according to DA specifications.
    ///
    /// **WARNING**: This function does not verify whether the bytes conform to the BN254 field modulo. If the data contains
    /// 32-byte segments that exceed the field's modulo, the bytes will be reduced modulo the field's order, potentially
    /// corrupting the data.
    ///
    /// # Arguments
    ///
    /// * `input` - A byte slice (`&[u8]`) representing the pre-padded data.
    ///
    /// # Returns
    ///
    /// A new `Blob` marked as padded.
    pub fn from_padded_bytes_unchecked(input: &[u8]) -> Self {
        let length_after_padding = input.len();

        Blob {
            blob_data: input.to_vec(),
            is_padded: true,
            length_after_padding,
        }
    }

    /// Returns a reference to the blob data.
    ///
    /// This method avoids cloning by returning a reference to the internal `blob_data`.
    ///
    /// # Returns
    ///
    /// A reference to the blob's data as `&[u8]`.
    pub fn get_blob_data_ref(&self) -> &[u8] {
        &self.blob_data
    }

    /// Returns a clone of the blob data.
    ///
    /// If you need ownership of the data, use this method to obtain a cloned `Vec<u8>`.
    ///
    /// # Returns
    ///
    /// A `Vec<u8>` containing the blob's data.
    pub fn get_blob_data(&self) -> Vec<u8> {
        self.blob_data.clone()
    }

    /// Returns the length of the blob data.
    ///
    /// This length reflects the size of the data, including any padding if applied.
    ///
    /// # Returns
    ///
    /// The length of the blob data as a `usize`.
    pub fn len(&self) -> usize {
        self.blob_data.len()
    }

    /// Checks whether the blob data is empty.
    ///
    /// # Returns
    ///
    /// `true` if the blob data is empty, `false` otherwise.
    pub fn is_empty(&self) -> bool {
        self.blob_data.is_empty()
    }

    /// Pads the blob data in-place according to DA specifications if it is not already padded.
    ///
    /// This method modifies the `Blob` by applying padding to the `blob_data`. If the blob is already padded,
    /// it returns an error.
    ///
    /// # Errors
    ///
    /// Returns `BlobError::AlreadyPaddedError` if the blob is already padded.
    pub fn pad_data(&mut self) -> Result<(), BlobError> {
        if self.is_padded {
            Err(BlobError::AlreadyPaddedError)
        } else {
            self.blob_data = helpers::convert_by_padding_empty_byte(&self.blob_data);
            self.is_padded = true;
            self.length_after_padding = self.blob_data.len();
            Ok(())
        }
    }

    /// Removes padding from the blob data if it is padded.
    ///
    /// This method modifies the `Blob` by removing padding from the `blob_data`. If the blob is not padded,
    /// it returns an error.
    ///
    /// # Errors
    ///
    /// Returns `BlobError::NotPaddedError` if the blob is not padded.
    pub fn remove_padding(&mut self) -> Result<(), BlobError> {
        if !self.is_padded {
            Err(BlobError::NotPaddedError)
        } else {
            self.blob_data =
                helpers::remove_empty_byte_from_padded_bytes_unchecked(&self.blob_data);
            self.is_padded = false;
            self.length_after_padding = 0;
            Ok(())
        }
    }

    /// Converts the blob data to a `Polynomial` in the specified format if the data is padded.
    ///
    /// This method transforms the binary blob data into a polynomial representation, which can be
    /// in either coefficient form or evaluation form, depending on the provided `PolynomialFormat`.
    ///
    /// # Arguments
    ///
    /// * `form` - The desired `PolynomialFormat` (`InCoefficientForm` or `InEvaluationForm`).
    ///
    /// # Errors
    ///
    /// - Returns `BlobError::NotPaddedError` if the blob data is not padded.
    /// - Propagates `PolynomialError` as `BlobError::GenericError` if polynomial construction fails.
    ///
    /// # Returns
    ///
    /// A `Result` containing the constructed `Polynomial` or a `BlobError`.
    pub fn to_polynomial(&self, form: PolynomialFormat) -> Result<Polynomial, BlobError> {
        if !self.is_padded {
            return Err(BlobError::NotPaddedError);
        }

        let fr_vec = helpers::to_fr_array(&self.blob_data);
        let poly = Polynomial::new(&fr_vec, self.length_after_padding, form)
            .map_err(|err| BlobError::GenericError(err.to_string()))?;
        Ok(poly)
    }
}
