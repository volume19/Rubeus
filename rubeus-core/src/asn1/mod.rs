//! ASN.1 DER encoding/decoding module
//!
//! Provides core ASN.1 functionality adapted from Thomas Pornin's DDer library.
//! This is the foundation for all Kerberos protocol structures.

pub mod error;
pub mod element;

pub use error::{AsnError, Result};
pub use element::{AsnElt, AsnValue, TagClass, tags};
