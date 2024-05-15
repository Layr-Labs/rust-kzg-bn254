use ark_bn254::{g1::G1Affine, g2::G2Affine, Fq, Fq2};
use ark_ec::AffineRepr;
use std::io;

use crate::new_helpers as helpers;

pub trait ReadPointFromBytes: AffineRepr {
    fn read_point_from_bytes_be(bytes: &[u8]) -> io::Result<Self>;
}

// Implement this trait for G1Affine and G2Affine
impl ReadPointFromBytes for G1Affine {
    fn read_point_from_bytes_be(bytes: &[u8]) -> io::Result<G1Affine> {
        helpers::read_g1_point_from_bytes_be(&bytes.to_vec()) .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}

impl ReadPointFromBytes for G2Affine {
    fn read_point_from_bytes_be(bytes: &[u8]) -> io::Result<G2Affine> {
        helpers::read_g2_point_from_bytes_be(&bytes.to_vec()) .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
}
