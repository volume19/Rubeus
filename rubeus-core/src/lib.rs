//! # Rubeus Core Library
//!
//! Rust port of the Rubeus Kerberos exploitation toolkit.
//! This library provides cross-platform Kerberos protocol implementation
//! with Windows-specific features behind conditional compilation.
//!
//! ## Authorization Context
//! This port is intended for authorized security testing, CTF competitions,
//! educational/training purposes, and defensive security research ONLY.
//!
//! ## Features
//! - `windows-lsa`: Enable Windows LSA/SSPI ticket extraction (Windows-only)
//!
//! ## Security Considerations
//! - Never logs passwords, hashes, or encryption keys
//! - Clears sensitive key material from memory using zeroize
//! - Runs with minimal privileges (except LSA extraction on Windows)
//! - No network listening, client-only operation

// Re-export error types at crate root
pub mod error;
pub use error::{Result, RubeusError};

// Core modules (to be populated)
pub mod asn1;
pub mod kerberos;
pub mod crypto;
pub mod platform;
pub mod commands;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crate_compiles() {
        // Basic smoke test
        let _result: Result<()> = Ok(());
    }
}
