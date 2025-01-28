use crate::{consts::SIZE_OF_G1_AFFINE_COMPRESSED, errors::KzgError, helpers};
use ark_bn254::G1Affine;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io;

// Define a new trait with your custom method
pub trait G1AffineExt {
    fn deserialize_compressed_be(bytes: &[u8; 32]) -> Result<G1Affine, KzgError>;
    fn serialize_compressed_be(g1_point: &G1Affine) -> Result<[u8; 32], KzgError>;
}

// Implement the trait for G1Affine
impl G1AffineExt for G1Affine {
    fn deserialize_compressed_be(bytes: &[u8; 32]) -> Result<G1Affine, KzgError> {
        G1Affine::deserialize_compressed(&bytes[..])
            .map_err(|e| KzgError::DeserializationError(e.to_string()))   
    }

    fn serialize_compressed_be(g1_point: &G1Affine) -> Result<[u8; 32], KzgError> {
        let mut commitment_bytes = Vec::with_capacity(SIZE_OF_G1_AFFINE_COMPRESSED);
        g1_point
        .serialize_compressed(&mut commitment_bytes)
        .map_err(|_| KzgError::SerializationError("Failed to serialize commitment".to_string()))?;
        commitment_bytes.as_slice().try_into().map_err(|e: std::array::TryFromSliceError| KzgError::SerializationError(e.to_string()))
    }
}

pub trait ReadPointFromBytes: AffineRepr {
    fn read_point_from_bytes_be(bytes: &[u8]) -> io::Result<Self>;
    fn read_point_from_bytes_native_compressed(bytes: &[u8]) -> io::Result<Self>;
}

// Implement this trait for G1Affine and G2Affine
impl ReadPointFromBytes for G1Affine {
    fn read_point_from_bytes_be(bytes: &[u8]) -> io::Result<G1Affine> {
        helpers::read_g1_point_from_bytes_be(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    fn read_point_from_bytes_native_compressed(bytes: &[u8]) -> io::Result<G1Affine> {
        G1Affine::deserialize_compressed(bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}
