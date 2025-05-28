use ark_bn254::g1::G1Affine;
use ark_bn254::Fr;
use ark_ec::AffineRepr;
use ark_ff::Field;
use ark_serialize::CanonicalDeserialize;

extern crate alloc;
use alloc::format;
use alloc::string::String;

use crate::consts::{BYTES_PER_FIELD_ELEMENT, SIZE_OF_G1_AFFINE_COMPRESSED};

// We define our own error instead of using io::ErrorKind::InvalidData
// because we want this to compile in no-std environments.
#[derive(Debug, thiserror::Error)]
pub enum PointReadError {
    #[error("Invalid point data: {0}")]
    InvalidData(String),

    #[error("Deserialization failed")]
    DeserializationError,
}

pub type Result<T> = core::result::Result<T, PointReadError>;

pub trait ReadPointFromBytes: AffineRepr {
    fn read_point_from_bytes_be(bytes: &[u8]) -> Result<Self>;
    fn read_point_from_bytes_native_compressed_be(bytes: &[u8]) -> Result<Self>;
}

// Implement this trait for G1Affine
impl ReadPointFromBytes for G1Affine {
    fn read_point_from_bytes_be(bytes: &[u8]) -> Result<G1Affine> {
        crate::helpers::read_g1_point_from_bytes_be(bytes)
            .map_err(|e| PointReadError::InvalidData(format!("{:?}", e)))
    }

    fn read_point_from_bytes_native_compressed_be(bytes_be: &[u8]) -> Result<G1Affine> {
        let mut bytes_le = [0u8; SIZE_OF_G1_AFFINE_COMPRESSED];
        bytes_le.copy_from_slice(bytes_be);
        bytes_le.reverse();
        G1Affine::deserialize_compressed(&bytes_le[..])
            .map_err(|_| PointReadError::DeserializationError)
    }
}

// A new trait for Fr for reading from bytes in big endian format
pub trait ReadFrFromBytes: Field {
    fn deserialize_from_bytes_be(bytes: &[u8]) -> Result<Self>;
}

// Implement ReadFrFromBytes trait for Fr
impl ReadFrFromBytes for Fr {
    fn deserialize_from_bytes_be(bytes: &[u8]) -> Result<Fr> {
        let mut bytes_le = [0u8; BYTES_PER_FIELD_ELEMENT];
        bytes_le.copy_from_slice(bytes);
        bytes_le.reverse();
        Fr::deserialize_uncompressed(&bytes_le[..])
            .map_err(|_| PointReadError::DeserializationError)
    }
}
