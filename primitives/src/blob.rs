use crate::{
    errors::KzgError,
    helpers,
    polynomial::{PolynomialCoeffForm, PolynomialEvalForm},
};

// Need to explicitly import alloc because we are in a no-std environment.
extern crate alloc;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

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
    /// that it contains bn254 field elements.
    ///
    /// This function validates that the input is a multiple of 32 and each
    /// 32-byte chunks in the data represents canonical bn254 field elements
    /// (i.e., they are less than the field modulus).
    /// Returns an error if any chunk contains bytes that exceed the field modulus.
    pub fn new(blob_data: &[u8]) -> Result<Self, KzgError> {
        helpers::validate_blob_data_as_canonical_field_elements(blob_data)?;
        Ok(Blob {
            blob_data: blob_data.to_vec(),
        })
    }

    /// Creates a new `Blob` from the provided raw_data byte slice and pads it
    /// according to DA specs. If the data is already padded, use
    /// [`Blob::new`] instead.
    /// Ref: https://layr-labs.github.io/eigenda/integration/spec/3-data-structs.html#encodedpayload
    pub fn from_raw_data(raw_data: &[u8]) -> Self {
        let blob_data = helpers::pad_payload(raw_data);
        Blob { blob_data }
    }

    /// Returns the raw data of the blob, removing any padding added by
    /// [`Blob::from_raw_data`].
    pub fn to_raw_data(&self) -> Result<Vec<u8>, KzgError> {
        helpers::remove_internal_padding(&self.blob_data)
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
    pub fn to_polynomial_eval_form(&self) -> Result<PolynomialEvalForm, KzgError> {
        let fr_vec = helpers::to_fr_array(&self.blob_data);
        PolynomialEvalForm::new(fr_vec)
    }

    /// Convert the blob data to a [PolynomialCoeffForm].
    pub fn to_polynomial_coeff_form(&self) -> Result<PolynomialCoeffForm, KzgError> {
        let fr_vec = helpers::to_fr_array(&self.blob_data);
        PolynomialCoeffForm::new(fr_vec)
    }
}

impl From<Vec<u8>> for Blob {
    fn from(blob_data: Vec<u8>) -> Blob {
        // Data is properly formatted - construct blob
        // Note: Downstream field element construction will apply modulo reduction as expected
        Blob { blob_data }
    }
}

impl From<Blob> for Vec<u8> {
    fn from(blob: Blob) -> Self {
        blob.blob_data
    }
}
