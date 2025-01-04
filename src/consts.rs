pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const SIZE_OF_G1_AFFINE_COMPRESSED: usize = 32; // in bytes
pub const SIZE_OF_G2_AFFINE_COMPRESSED: usize = 64; // in bytes
pub const REQUIRED_FREE_SPACE: u64 = 100 * 1024 * 1024; // 100 MB in bytes

pub const FIAT_SHAMIR_PROTOCOL_DOMAIN: &[u8] = b"EIGENDA_FSBLOBVERIFY_V1_"; // Adapted from 4844
pub const FIELD_ELEMENTS_PER_BLOB: u64 = 131072; // 32MB max blob size
pub const KZG_ENDIANNESS: Endianness = Endianness::Big; // Choose between Big or Little.

pub const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: &[u8] = b"EIGENDA_RCKZGBATCH___V1_"; // Adapted from 4844
#[derive(Debug, Clone, Copy)]
pub enum Endianness {
    Big,
    Little,
}
