//! ## Library Design / Architecture
//!
//! The main purpose of this library is to allow taking a piece of data,
//! committing to it, and then generating and verifying proofs against that
//! commitment.
//!
//! ### Data Types
//!
//! The main data pipeline goes:
//! > user data -> [blob::Blob] ->
//! > [polynomial::PolynomialEvalForm]/[polynomial::PolynomialCoeffForm] -> KZG
//! > Commitment / Proof
//!
//! - User Data: bytes array
//! - meaningful to users (typically will be a rollup batch)
//! - Blob: bn254 field elements array
//! - meaningful to EigenDA network
//! - Obtained from User Data by inserting zeroes every 31 bytes to make every
//!   32 byte an element of bn254.
//! - Polynomial: bn254 field elements array, interpreted as coefficients or
//!   evaluations of a polynomial
//! - meaningful when committing and generating/verifying proofs
//! - Obtained from Blob by appending zeroes to make the length a power of 2,
//!   and then interpreting the array as coefficients or evaluations of a
//!   polynomial.
//! - KZG: struct storing the SRS points used to generate commitments and proofs
//! - SRS points: bn254 group elements
//! - inner producted with the polynomial to generate commitments
//!
//! The Blob and Polynomial structs are mostly
//! [Plain Old Data](https://en.wikipedia.org/wiki/Passive_data_structure) with constructor and few helper methods.
//! The interesting stuff happens in the [kzg::KZG] struct,
//! which has methods for committing to a blob, polynomial in coeff or eval
//! form, and generating and verifying proofs.
//!
//! Our current codebase has the types PolynomialEvalForm and
//! PolynomialCoeffForm to represent the polynomial in evaluation and
//! coefficient form respectively. However, we do not have types to represent
//! the two forms of srs points. They are implicitly assumed to be in monomial
//! form when loaded, and an IFFT is performed before taking the inner product
//! with the polynomial in evaluation form.
//!
//! ### KZG Commitments
//!
//! A KZG commitment can be taken by an inner product between (poly_coeff,
//! srs_monomial) or (poly_eval, srs_lagrange). FFT and IFFT operations can be
//! performed to convert between these forms.
//!
//! ![KZG](../kzg_commitment_diagram.png)
//!
//! ### KZG Proofs
//!
//! TODO
//!
//! ## Examples
//!
//! ### Commit to a some user data
//! ```rust
//! use rust_kzg_bn254::{blob::Blob, kzg::KZG};
//!
//! let kzg = KZG::setup(
//! "tests/test-files/mainnet-data/g1.131072.point",
//! "",
//! "tests/test-files/mainnet-data/g2.point.powerOf2",
//! 268435456,
//! 131072,
//! ).unwrap();
//!
//! let rollup_data: &[u8] = "some rollup batcher data".as_bytes();
//! let blob = Blob::from_raw_data(rollup_data);
//! let poly = blob.to_polynomial_eval_form();
//! let commitment = kzg.commit_eval_form(&poly).unwrap();
//! ```
//!
//! ### Generate a proof for a piece of data
//! ```rust
//! // TODO:
//! ```
//!

mod arith;
pub mod blob;
pub mod consts;
pub mod errors;
pub mod helpers;
pub mod kzg;
pub mod polynomial;
mod traits;
