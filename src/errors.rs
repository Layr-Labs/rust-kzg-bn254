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
            PolynomialError::SerializationFromStringError => {
                write!(f, "couldn't load string to fr vector")
            }
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
    GenericError(String),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_error_serialization_from_string() {
        let error = PolynomialError::SerializationFromStringError;
        assert_eq!(format!("{}", error), "couldn't load string to fr vector");
    }

    #[test]
    fn test_polynomial_error_commit() {
        let msg = String::from("test commit error");
        let error = PolynomialError::CommitError(msg.clone());
        assert_eq!(format!("{}", error), format!("Commitment error: {}", msg));
    }

    #[test]
    fn test_polynomial_error_generic() {
        let msg = String::from("test generic error");
        let error = PolynomialError::GenericError(msg.clone());
        assert_eq!(format!("{}", error), format!("generic error: {}", msg));
    }

    #[test]
    fn test_polynomial_error_equality() {
        let error1 = PolynomialError::SerializationFromStringError;
        let error2 = PolynomialError::SerializationFromStringError;
        let error3 = PolynomialError::CommitError(String::from("error"));
        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    // KzgError tests
    #[test]
    fn test_kzg_error_commit() {
        let msg = String::from("test commit error");
        let error = KzgError::CommitError(msg.clone());
        assert_eq!(format!("{}", error), format!("Commitment error: {}", msg));
    }

    #[test]
    fn test_kzg_error_serialization() {
        let msg = String::from("test serialization error");
        let error = KzgError::SerializationError(msg.clone());
        assert_eq!(
            format!("{}", error),
            format!("Serialization error: {}", msg)
        );
    }

    #[test]
    fn test_kzg_error_fft() {
        let msg = String::from("test fft error");
        let error = KzgError::FftError(msg.clone());
        assert_eq!(format!("{}", error), format!("FFT error: {}", msg));
    }

    #[test]
    fn test_kzg_error_generic() {
        let msg = String::from("test generic error");
        let error = KzgError::GenericError(msg.clone());
        assert_eq!(format!("{}", error), format!("Generic error: {}", msg));
    }

    #[test]
    fn test_kzg_error_equality() {
        let error1 = KzgError::CommitError(String::from("error"));
        let error2 = KzgError::CommitError(String::from("error"));
        let error3 = KzgError::SerializationError(String::from("different error"));
        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_not_padded_error_display() {
        let error = BlobError::NotPaddedError;
        assert_eq!(format!("{}", error), "tried to execute on non padded blob");
    }

    #[test]
    fn test_already_padded_error_display() {
        let error = BlobError::AlreadyPaddedError;
        assert_eq!(
            format!("{}", error),
            "tried to execute on already padded blob"
        );
    }

    #[test]
    fn test_blob_error_equality() {
        let error1 = BlobError::NotPaddedError;
        let error2 = BlobError::NotPaddedError;
        let error3 = BlobError::AlreadyPaddedError;

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
    }

    #[test]
    fn test_blob_generic_error() {
        let error1 = BlobError::GenericError(String::from("error"));
        let error3 = BlobError::GenericError(String::from("error"));
        let error2 = BlobError::NotPaddedError;
        assert_eq!(error1, error3);
        assert_ne!(error1, error2);
    }
}
