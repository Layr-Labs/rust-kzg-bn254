use ark_serialize::CanonicalSerialize;
use rust_kzg_bn254::kzg::Kzg;
use std::fs;

pub fn main() {
    let setup = Kzg::setup(true).unwrap();
    let mut compressed_g1 = Vec::new();
    let mut compressed_g2 = Vec::new();

    setup.g1.serialize_compressed(&mut compressed_g1).unwrap();
    setup.g2.serialize_compressed(&mut compressed_g2).unwrap();

    fs::write("src/test-files/g1_serialized_test", compressed_g1).expect("Unable to write g1 file");
    fs::write("src/test-files/g2_serialized_test", compressed_g2).expect("Unable to write g2 file");
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::{G1Affine, G2Affine};
    use ark_serialize::CanonicalDeserialize;

    #[test]
    fn test_deserialize() {
        let setup = Kzg::setup(true).unwrap();

        let mut compressed_g1 =
            fs::read("src/test-files/g1_serialized_test").expect("Unable to read g1 file");
        let mut compressed_g2 =
            fs::read("src/test-files/g2_serialized_test").expect("Unable to read g2 file");

        let g1: Vec<G1Affine> =
            CanonicalDeserialize::deserialize_compressed(&*compressed_g1).unwrap();
        let g2: Vec<G2Affine> =
            CanonicalDeserialize::deserialize_compressed(&*compressed_g2).unwrap();

        println!("{:?}", g1);
        println!("{:?}", g2);
        assert_eq!(g1, setup.g1);
        assert_eq!(g2, setup.g2);
    }
}
