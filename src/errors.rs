use std::{error::Error, fmt};

#[derive(Clone, Debug, PartialEq)]
pub enum BlobError {
    NotPaddedError,
    AlreadyPaddedError,
    GenericError(String),
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            BlobError::NotPaddedError => write!(f, "tried to execute on non padded blob"),
            BlobError::AlreadyPaddedError => write!(f, "tried to execute on already padded blob"),
            BlobError::GenericError(ref msg) => write!(f, "generic error: {}", msg),
        }
    }
}

impl Error for BlobError {}

#[derive(Clone, Debug, PartialEq)]
pub enum PolynomialError {
    SerializationFromStringError,
    CommitError(String),
    GenericError(String),
}

impl fmt::Display for PolynomialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PolynomialError::SerializationFromStringError => write!(f, "couldn't load string to fr vector"),
            PolynomialError::CommitError(ref msg) => write!(f, "Commitment error: {}", msg),
            PolynomialError::GenericError(ref msg) => write!(f, "generic error: {}", msg),
        }
    }
}

impl Error for PolynomialError {}

#[derive(Clone, Debug, PartialEq)]
pub enum KzgError {
    CommitError(String),
    SerializationError(String),
    FftError(String),
    GenericError(String)
}

impl fmt::Display for KzgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            KzgError::CommitError(ref msg) => write!(f, "Commitment error: {}", msg),
            KzgError::SerializationError(ref msg) => write!(f, "Serialization error: {}", msg),
            KzgError::FftError(ref msg) => write!(f, "FFT error: {}", msg),
            KzgError::GenericError(ref msg) => write!(f, "Generic error: {}", msg),
        }
    }
}

impl Error for KzgError {}
