use crate::{
    helpers,
    polynomial::{PolynomialCoeffForm, PolynomialEvalForm},
};

// Need to explicitly import alloc because we are in a no-std environment.
extern crate alloc;
use alloc::vec::Vec;
use serde::{Serialize, Deserialize};

/// A blob aligned with the Eigen DA specification.
/// TODO: we should probably move to a transparent repr like
///       <https://docs.rs/alloy-primitives/latest/alloy_primitives/struct.FixedBytes.html>
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blob {
    /// The binary data contained within the blob.
    blob_data: Vec<u8>,
}

impl Blob {
    /// Creates a new `Blob` from the given blob_data.
    /// blob_data should already be padded according to DA specs, meaning
    /// that it contains bn254 field elements. Otherwise, use
    /// [`Blob::from_raw_data`].
    ///
    /// WARNING: This function does not check if the bytes are modulo bn254.
    /// If the data has 32 byte segments exceeding the modulo of the field
    /// then the bytes will be modded by the order of the field and the data
    /// will be transformed incorrectly.
    /// TODO: we should check that the bytes are correct and return an error
    /// instead of relying on the users reading this documentation.
    pub fn new(blob_data: &[u8]) -> Self {
        Blob {
            blob_data: blob_data.to_vec(),
        }
    }

    /// Creates a new `Blob` from the provided raw_data byte slice and pads it
    /// according to DA specs. If the data is already padded, use
    /// [`Blob::new`] instead.
    pub fn from_raw_data(raw_data: &[u8]) -> Self {
        let blob_data = helpers::convert_by_padding_empty_byte(raw_data);
        Blob { blob_data }
    }

    /// Returns the raw data of the blob, removing any padding added by
    /// [`Blob::from_raw_data`].
    pub fn to_raw_data(&self) -> Vec<u8> {
        helpers::remove_empty_byte_from_padded_bytes_unchecked(&self.blob_data)
    }

    /// Returns the blob data
    pub fn data(&self) -> &[u8] {
        &self.blob_data
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

    /// Convert the blob data to a [PolynomialEvalForm].
    pub fn to_polynomial_eval_form(&self) -> PolynomialEvalForm {
        let fr_vec = helpers::to_fr_array(&self.blob_data);
        PolynomialEvalForm::new(fr_vec)
    }

    /// Convert the blob data to a [PolynomialCoeffForm].
    pub fn to_polynomial_coeff_form(&self) -> PolynomialCoeffForm {
        let fr_vec = helpers::to_fr_array(&self.blob_data);
        PolynomialCoeffForm::new(fr_vec)
    }
}

impl From<Vec<u8>> for Blob {
    fn from(blob_data: Vec<u8>) -> Self {
        Blob { blob_data }
    }
}

impl From<Blob> for Vec<u8> {
    fn from(blob: Blob) -> Self {
        blob.blob_data
    }
}
