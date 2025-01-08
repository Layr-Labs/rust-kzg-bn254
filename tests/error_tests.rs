#[cfg(test)]
mod tests {
    use rust_kzg_bn254::errors::{KzgError, PolynomialError};

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
}
