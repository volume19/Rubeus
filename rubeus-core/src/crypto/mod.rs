//! Kerberos cryptography module
//! Implements encryption types: RC4-HMAC, AES128/256-CTS-HMAC-SHA1, DES-CBC-MD5

pub mod kerberos;

pub use kerberos::{EType, password_hash, password_hash_bytes, compute_salt};
