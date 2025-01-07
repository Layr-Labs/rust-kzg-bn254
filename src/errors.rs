use thiserror::Error;

/// Errors related to Blob operations.
///
/// The `BlobError` enum encapsulates all possible errors that can occur during
/// operations on the `Blob` struct, such as padding and conversion errors.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum BlobError {
    /// A generic error with a descriptive message.
    #[error("generic error: {0}")]
    GenericError(String),
}

/// Errors related to Polynomial operations.
///
/// The `PolynomialError` enum encapsulates all possible errors that can occur
/// during operations on the `Polynomial` struct, such as FFT transformations
/// and serialization errors.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum PolynomialError {
    /// Error during serialization from string to a vector of `Fr` elements.
    #[error("serialization from string to Fr vector failed")]
    SerializationFromStringError,

    /// Error related to commitment operations with a descriptive message.
    #[error("commitment error: {0}")]
    CommitError(String),

    /// Error related to Fast Fourier Transform (FFT) operations with a descriptive message.
    #[error("FFT error: {0}")]
    FFTError(String),

    /// A generic error with a descriptive message.
    #[error("generic error: {0}")]
    GenericError(String),

    /// Error indicating that the polynomial is already in the desired form.
    #[error("incorrect form error: {0}")]
    IncorrectFormError(String),
}

/// Errors related to KZG operations.
///
/// The `KzgError` enum encapsulates all possible errors that can occur during
/// KZG-related operations, including those from `PolynomialError` and `BlobError`.
/// It also includes additional errors specific to KZG operations.
#[derive(Clone, Debug, PartialEq, Error)]
pub enum KzgError {
    /// Wraps errors originating from Polynomial operations.
    #[error("polynomial error: {0}")]
    PolynomialError(#[from] PolynomialError),

    #[error("MSM error: {0}")]
    MsmError(String),

    /// Wraps errors originating from Blob operations.
    #[error("blob error: {0}")]
    BlobError(#[from] BlobError),

    /// Error related to serialization with a descriptive message.
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Error related to commitment processes with a descriptive message.
    #[error("commitment error: {0}")]
    CommitmentError(String),

    /// Error related to commitment processes with a descriptive message.
    #[error("not on curve error: {0}")]
    NotOnCurveError(String),

    /// Error indicating an invalid commit operation with a descriptive message.
    #[error("commit error: {0}")]
    CommitError(String),

    /// Error related to Fast Fourier Transform (FFT) operations with a descriptive message.
    #[error("FFT error: {0}")]
    FFTError(String),

    /// A generic error with a descriptive message.
    #[error("generic error: {0}")]
    GenericError(String),

    /// Error indicating an invalid denominator scenario, typically in mathematical operations.
    #[error("invalid denominator")]
    InvalidDenominator,

    /// Error indicating an invalid input length scenario, typically in data processing.
    #[error("invalid input length")]
    InvalidInputLength,
}
