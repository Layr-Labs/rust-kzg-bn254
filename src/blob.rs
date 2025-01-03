use crate::{
    errors::BlobError,
    helpers,
    polynomial::{Polynomial, PolynomialFormat},
};

/// A blob which is Eigen DA spec aligned.
/// TODO: we should probably move to a transparent repr like
///       https://docs.rs/alloy-primitives/latest/alloy_primitives/struct.FixedBytes.html
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob {
    blob_data: Vec<u8>,
}

impl Blob {
    /// Creates a new `Blob` from the given blob_data.
    /// blob_data should already be padded according to DA specs, meaning
    /// that it contains bn254 field elements. Otherwise, use [`Blob::from_raw_data`].
    ///
    /// WARNING: This function does not check if the bytes are modulo bn254
    /// if the data has 32 byte segments exceeding the modulo of the field
    /// then the bytes will be modded by the order of the field and the data
    /// will be transformed incorrectly.
    /// TODO: we should check that the bytes are correct and return an error instead of
    ///       relying on the users reading this documentation.
    pub fn new(blob_data: &[u8]) -> Self {
        Blob {
            blob_data: blob_data.to_vec(),
        }
    }

    /// Creates a new `Blob` from the provided raw_data byte slice and pads it according
    /// to DA specs. If the data is already padded, use [`Blob::new`] instead.
    pub fn from_raw_data(raw_data: &[u8]) -> Self {
        let blob_data = helpers::convert_by_padding_empty_byte(raw_data);
        Blob { blob_data }
    }

    /// Returns the raw data of the blob, removing any padding added by [`Blob::from_raw_data`].
    pub fn to_raw_data(&self) -> Vec<u8> {
        helpers::remove_empty_byte_from_padded_bytes_unchecked(&self.blob_data)
    }

    /// Returns the blob data
    pub fn data(&self) -> &[u8] {
        &self.blob_data
    }

    /// Returns the length of the data in the blob.
    pub fn len(&self) -> usize {
        self.blob_data.len()
    }

    /// Checks if the blob data is empty.
    pub fn is_empty(&self) -> bool {
        self.blob_data.is_empty()
    }

    /// Converts the blob data to a `Polynomial` if the data is padded.
    pub fn to_polynomial(&self, form: PolynomialFormat) -> Result<Polynomial, BlobError> {
        let fr_vec = helpers::to_fr_array(&self.blob_data);
        let poly = Polynomial::new(&fr_vec, self.len(), form)
            .map_err(|err| BlobError::GenericError(err.to_string()))?;
        Ok(poly)
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
