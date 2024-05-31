use crate::{errors::BlobError, helpers, polynomial::Polynomial};

/// A blob which is Eigen DA spec aligned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob {
    blob_data: Vec<u8>,
    is_padded: bool,
    length_after_padding: usize,
}

impl Blob {
    /// Creates a new `Blob` from the given data.
    pub fn new(blob_data: Vec<u8>) -> Self {
        Blob {
            blob_data,
            is_padded: false,
            length_after_padding: 0,
        }
    }

    pub fn get_length_after_padding(&self) -> usize {
        self.length_after_padding
    }

    /// Creates a new `Blob` from the given data.
    pub fn is_padded(&self) -> bool {
        self.is_padded
    }

    /// Creates a new `Blob` from the provided byte slice and pads it according
    /// to DA specs.
    pub fn from_bytes_and_pad(input: &[u8]) -> Self {
        let padded_input = helpers::convert_by_padding_empty_byte(input);
        let length_after_padding = padded_input.len();
        Blob {
            blob_data: padded_input,
            is_padded: true,
            length_after_padding,
        }
    }

    /// Returns the blob data
    pub fn get_blob_data(&self) -> Vec<u8> {
        self.blob_data.clone()
    }

    /// Returns the length of the data in the blob.
    pub fn len(&self) -> usize {
        self.blob_data.len()
    }

    /// Returns true if the blob is empty.
    pub fn is_empty(&self) -> bool {
        self.blob_data.is_empty()
    }

    /// Pads the blob data in-place if it is not already padded.
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
    pub fn remove_padding(&mut self) -> Result<(), BlobError> {
        if !self.is_padded {
            Err(BlobError::NotPaddedError)
        } else {
            self.blob_data = helpers::remove_empty_byte_from_padded_bytes(&self.blob_data);
            self.is_padded = false;
            self.length_after_padding = 0;
            Ok(())
        }
    }

    /// Converts the blob data to a `Polynomial` if the data is padded.
    pub fn to_polynomial(&self) -> Result<Polynomial, BlobError> {
        if !self.is_padded {
            Err(BlobError::NotPaddedError)
        } else {
            let fr_vec = helpers::to_fr_array(&self.blob_data);
            let poly = Polynomial::new(&fr_vec, self.length_after_padding)
                .map_err(|err| BlobError::GenericError(err.to_string()))?;
            Ok(poly)
        }
    }
}
