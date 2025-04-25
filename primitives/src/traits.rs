use ark_bn254::g1::G1Affine;
use ark_ec::AffineRepr;
use ark_serialize::CanonicalDeserialize;

extern crate alloc;
use alloc::format;
use alloc::string::String;

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
    fn read_point_from_bytes_native_compressed(bytes: &[u8]) -> Result<Self>;
}

// Implement this trait for G1Affine and G2Affine
impl ReadPointFromBytes for G1Affine {
    fn read_point_from_bytes_be(bytes: &[u8]) -> Result<G1Affine> {
        crate::helpers::read_g1_point_from_bytes_be(bytes)
            .map_err(|e| PointReadError::InvalidData(format!("{:?}", e)))
    }

    fn read_point_from_bytes_native_compressed(bytes: &[u8]) -> Result<G1Affine> {
        G1Affine::deserialize_compressed(bytes).map_err(|_| PointReadError::DeserializationError)
    }
}
