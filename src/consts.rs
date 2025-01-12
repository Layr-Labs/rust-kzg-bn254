pub const BYTES_PER_FIELD_ELEMENT: usize = 32;
pub const SIZE_OF_G1_AFFINE_COMPRESSED: usize = 32; // in bytes

/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#blob
pub const FIAT_SHAMIR_PROTOCOL_DOMAIN: &[u8] = b"EIGENDA_FSBLOBVERIFY_V1_"; // Adapted from 4844

/// Ref: https://github.com/ethereum/consensus-specs/blob/master/specs/deneb/polynomial-commitments.md#blob
pub const RANDOM_CHALLENGE_KZG_BATCH_DOMAIN: &[u8] = b"EIGENDA_RCKZGBATCH___V1_"; // Adapted from 4844

pub const KZG_ENDIANNESS: Endianness = Endianness::Big; // Choose between Big or Little.

#[derive(Debug, Clone, Copy)]
pub enum Endianness {
    Big,
    Little,
}

// This is the G2 Tau for the SRS of size 3000. These is only meant for testing purposes.
pub const G2_TAU_FOR_TEST_SRS_3000: [[u64; 4]; 4] = [
    [
        6210180350256028851,
        1155870131248430255,
        5195628682048044774,
        1260504166784820003,
    ], // x_c0
    [
        5796639583410086988,
        1670781852330703136,
        9975496901009692568,
        3351822507251002947,
    ], // x_c1
    [
        11145494475421916991,
        4671284253524040022,
        18315320503610857882,
        2978668873662892197,
    ], // y_c0
    [
        6336249489527546243,
        1821275851175057403,
        15993261854023940214,
        1208597503336813826,
    ], // y_c1
];

// This is the G2 Tau for the MAINNET SRS points.
pub const G2_TAU_FOR_MAINNET_SRS: [[u64; 4]; 4] = [
    [
        6210180350256028851,
        1155870131248430255,
        5195628682048044774,
        1260504166784820003,
    ], // x_c0
    [
        5796639583410086988,
        1670781852330703136,
        9975496901009692568,
        3351822507251002947,
    ], // x_c1
    [
        11145494475421916991,
        4671284253524040022,
        18315320503610857882,
        2978668873662892197,
    ], // y_c0
    [
        6336249489527546243,
        1821275851175057403,
        15993261854023940214,
        1208597503336813826,
    ], // y_c1
];

pub const MAINNET_SRS_G1_SIZE: usize = 131072;
