#[cfg(test)]
mod tests {
    use rust_kzg_bn254::errors::{BlobError, KzgError, PolynomialError};

    #[test]
    fn test_polynomial_error_serialization_from_string() {
        let error = PolynomialError::SerializationFromStringError;
        assert_eq!(
            format!("{}", error),
            "serialization from string to Fr vector failed"
        );
    }

    #[test]
    fn test_polynomial_error_commit() {
        let msg = String::from("test commit error");
        let error = PolynomialError::CommitError(msg.clone());
        assert_eq!(format!("{}", error), format!("commitment error: {}", msg));
    }

    #[test]
    fn test_polynomial_error_generic() {
        let msg = String::from("test generic error");
        let error = PolynomialError::GenericError(msg.clone());
        assert_eq!(format!("{}", error), format!("generic error: {}", msg));
    }

    #[test]
    fn test_polynomial_error_fft() {
        let msg = String::from("test fft error");
        let error = PolynomialError::FFTError(msg.clone());
        assert_eq!(format!("{}", error), format!("FFT error: {}", msg));
    }
    #[test]
    fn test_polynomial_error_incorrect_form() {
        let msg = String::from("test incorrect form error");
        let error = PolynomialError::IncorrectFormError(msg.clone());
        assert_eq!(
            format!("{}", error),
            format!("incorrect form error: {}", msg)
        );
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
        assert_eq!(format!("{}", error), format!("commit error: {}", msg));
    }

    #[test]
    fn test_kzg_error_serialization() {
        let msg = String::from("test serialization error");
        let error = KzgError::SerializationError(msg.clone());
        assert_eq!(
            format!("{}", error),
            format!("serialization error: {}", msg)
        );
    }

    #[test]
    fn test_kzg_error_fft() {
        let msg = String::from("test fft error");
        let error = KzgError::FFTError(msg.clone());
        assert_eq!(format!("{}", error), format!("FFT error: {}", msg));
    }

    #[test]
    fn test_kzg_error_generic() {
        let msg = String::from("test generic error");
        let error = KzgError::GenericError(msg.clone());
        assert_eq!(format!("{}", error), format!("generic error: {}", msg));
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
        assert_eq!(
            format!("{}", error),
            "tried to execute on a non-padded blob"
        );
    }

    #[test]
    fn test_already_padded_error_display() {
        let error = BlobError::AlreadyPaddedError;
        assert_eq!(
            format!("{}", error),
            "tried to execute on an already padded blob"
        );
    }

    #[test]
    fn test_blob_error_equality() {
        let error1 = BlobError::NotPaddedError;
        let error2 = BlobError::NotPaddedError;
        let error3 = BlobError::AlreadyPaddedError;
        let error4 = BlobError::GenericError("test".to_string());

        assert_eq!(error1, error2);
        assert_ne!(error1, error3);
        assert_ne!(error1, error4);
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
