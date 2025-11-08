//! ASN.1-specific error types
//! Ported from Rubeus/Asn1/AsnException.cs

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq)]
pub enum AsnError {
    #[error("Invalid DER encoding: {0}")]
    InvalidEncoding(String),

    #[error("Unexpected tag: expected {expected:#04x}, got {actual:#04x}")]
    UnexpectedTag { expected: u8, actual: u8 },

    #[error("Invalid length encoding")]
    InvalidLength,

    #[error("Truncated data: needed {needed} bytes, got {available}")]
    TruncatedData { needed: usize, available: usize },

    #[error("Integer overflow in ASN.1 value")]
    IntegerOverflow,

    #[error("Invalid UTF-8 in string: {0}")]
    InvalidUtf8(String),

    #[error("Invalid OID encoding")]
    InvalidOid,

    #[error("Constructed encoding not allowed for this type")]
    ConstructedNotAllowed,

    #[error("Primitive encoding required but got constructed")]
    PrimitiveRequired,

    #[error("Index out of bounds: {index} >= {length}")]
    IndexOutOfBounds { index: usize, length: usize },

    #[error("Empty sequence")]
    EmptySequence,
}

pub type Result<T> = std::result::Result<T, AsnError>;

impl AsnError {
    /// Create a truncated data error
    pub fn truncated(needed: usize, available: usize) -> Self {
        AsnError::TruncatedData { needed, available }
    }

    /// Create an unexpected tag error
    pub fn unexpected_tag(expected: u8, actual: u8) -> Self {
        AsnError::UnexpectedTag { expected, actual }
    }

    /// Create an index out of bounds error
    pub fn index_out_of_bounds(index: usize, length: usize) -> Self {
        AsnError::IndexOutOfBounds { index, length }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncated_error() {
        let err = AsnError::truncated(10, 5);
        assert!(matches!(err, AsnError::TruncatedData { needed: 10, available: 5 }));
        assert_eq!(err.to_string(), "Truncated data: needed 10 bytes, got 5");
    }

    #[test]
    fn test_unexpected_tag_error() {
        let err = AsnError::unexpected_tag(0x02, 0x04);
        assert!(matches!(err, AsnError::UnexpectedTag { expected: 0x02, actual: 0x04 }));
    }

    #[test]
    fn test_error_equality() {
        let err1 = AsnError::InvalidLength;
        let err2 = AsnError::InvalidLength;
        assert_eq!(err1, err2);
    }

    #[test]
    fn test_error_clone() {
        let err = AsnError::InvalidOid;
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
}
