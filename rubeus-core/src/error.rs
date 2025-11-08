// Error types for the Rubeus Rust port
// Replaces C# exception-based error handling with Result<T, E>

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RubeusError {
    #[error("ASN.1 parsing error: {0}")]
    AsnError(String),

    #[error("Kerberos protocol error: {0}")]
    KrbError(String),

    #[error("Cryptography error: {0}")]
    CryptoError(String),

    #[cfg(windows)]
    #[error("LSA/Windows API error: {0}")]
    LsaError(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Command execution error: {0}")]
    CommandError(String),

    #[error("LDAP error: {0}")]
    LdapError(String),

    #[error("Platform not supported: {0}")]
    PlatformUnsupported(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Encoding error: {0}")]
    EncodingError(String),
}

pub type Result<T> = std::result::Result<T, RubeusError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = RubeusError::AsnError("test error".to_string());
        assert_eq!(err.to_string(), "ASN.1 parsing error: test error");
    }

    #[test]
    fn test_error_from_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let rubeus_err: RubeusError = io_err.into();
        assert!(matches!(rubeus_err, RubeusError::IoError(_)));
    }

    #[test]
    fn test_result_type() {
        fn returns_result() -> Result<i32> {
            Ok(42)
        }
        assert_eq!(returns_result().unwrap(), 42);
    }
}
