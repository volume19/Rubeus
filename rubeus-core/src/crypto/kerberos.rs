//! Kerberos cryptography implementation
//! Ported from Rubeus/lib/Crypto.cs
//!
//! Implements password hashing and encryption for Kerberos encryption types:
//! - RC4-HMAC (KERB_ETYPE 23)
//! - AES128-CTS-HMAC-SHA1 (KERB_ETYPE 17)
//! - AES256-CTS-HMAC-SHA1 (KERB_ETYPE 18)
//! - DES-CBC-MD5 (KERB_ETYPE 3)

use crate::error::{Result, RubeusError};
use md4::Digest as _;
use pbkdf2::pbkdf2_hmac;
use zeroize::Zeroizing;

/// Kerberos encryption types (RFC 3961, RFC 4120)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum EType {
    DesCbcCrc = 1,
    DesCbcMd4 = 2,
    DesCbcMd5 = 3,
    Des3CbcSha1Kd = 16,
    Aes128CtsHmacSha1 = 17,
    Aes256CtsHmacSha1 = 18,
    Rc4Hmac = 23,
    Rc4HmacExp = 24,
}

impl EType {
    /// Get key size in bytes for this encryption type
    pub fn key_size(&self) -> usize {
        match self {
            EType::DesCbcCrc | EType::DesCbcMd4 | EType::DesCbcMd5 => 8,
            EType::Des3CbcSha1Kd => 24,
            EType::Aes128CtsHmacSha1 => 16,
            EType::Aes256CtsHmacSha1 => 32,
            EType::Rc4Hmac | EType::Rc4HmacExp => 16,
        }
    }
}

/// Compute Kerberos password hash for a given encryption type
///
/// # Arguments
/// * `etype` - Encryption type
/// * `password` - User password
/// * `salt` - Salt (usually REALM + username, uppercase realm)
/// * `iterations` - PBKDF2 iteration count (default 4096 for AES)
///
/// # Returns
/// Password hash as hex string (for compatibility with original Rubeus output)
pub fn password_hash(
    etype: EType,
    password: &str,
    salt: &str,
    iterations: u32,
) -> Result<String> {
    let key_bytes = password_hash_bytes(etype, password, salt, iterations)?;
    Ok(hex::encode_upper(key_bytes))
}

/// Compute Kerberos password hash as raw bytes
pub fn password_hash_bytes(
    etype: EType,
    password: &str,
    salt: &str,
    iterations: u32,
) -> Result<Zeroizing<Vec<u8>>> {
    match etype {
        EType::Rc4Hmac | EType::Rc4HmacExp => rc4_hmac_password_hash(password),
        EType::Aes128CtsHmacSha1 => {
            aes_cts_hmac_sha1_password_hash(password, salt, iterations, 16)
        }
        EType::Aes256CtsHmacSha1 => {
            aes_cts_hmac_sha1_password_hash(password, salt, iterations, 32)
        }
        EType::DesCbcMd5 => des_cbc_md5_password_hash(password, salt),
        _ => Err(RubeusError::CryptoError(format!(
            "Unsupported encryption type: {:?}",
            etype
        ))),
    }
}

/// RC4-HMAC password hash (KERB_ETYPE 23)
///
/// Algorithm: MD4(UTF-16LE(password))
/// This is the NT hash (NTLM hash)
fn rc4_hmac_password_hash(password: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Convert password to UTF-16LE
    let password_utf16: Vec<u16> = password.encode_utf16().collect();
    let password_bytes: Vec<u8> = password_utf16
        .iter()
        .flat_map(|&c| c.to_le_bytes())
        .collect();

    // MD4 hash
    let result = md4::Md4::digest(&password_bytes);

    Ok(Zeroizing::new(result.to_vec()))
}

/// AES-CTS-HMAC-SHA1 password hash (KERB_ETYPE 17/18)
///
/// Algorithm: PBKDF2-HMAC-SHA1(password, salt, iterations, key_size)
/// RFC 3962 - AES encryption for Kerberos 5
fn aes_cts_hmac_sha1_password_hash(
    password: &str,
    salt: &str,
    iterations: u32,
    key_size: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if iterations == 0 {
        return Err(RubeusError::CryptoError(
            "PBKDF2 iterations must be > 0".to_string(),
        ));
    }

    // Convert password and salt to UTF-8 bytes
    let password_bytes = password.as_bytes();
    let salt_bytes = salt.as_bytes();

    // PBKDF2-HMAC-SHA1
    let mut key = vec![0u8; key_size];
    pbkdf2_hmac::<sha1::Sha1>(password_bytes, salt_bytes, iterations, &mut key);

    Ok(Zeroizing::new(key))
}

/// DES-CBC-MD5 password hash (KERB_ETYPE 3) - LEGACY
///
/// Algorithm: Complex DES-based string-to-key
/// Note: Simplified implementation - full DES string-to-key is complex
/// For now, we compute MD5(password + salt) and use first 8 bytes
fn des_cbc_md5_password_hash(password: &str, salt: &str) -> Result<Zeroizing<Vec<u8>>> {
    // Concatenate password and salt
    let input = format!("{}{}", password, salt);

    // MD5 hash
    type Md5Hash = [u8; 16];
    let result: Md5Hash = md5::compute(input.as_bytes()).into();

    // Take first 8 bytes for DES key
    Ok(Zeroizing::new(result[..8].to_vec()))
}

/// Compute salt from domain and username
///
/// Standard salt: REALM + username (uppercase realm)
/// Computer account salt: REALMhost + hostname.realm (special format)
pub fn compute_salt(domain: &str, username: &str) -> String {
    let realm = domain.to_uppercase();

    if username.ends_with('$') {
        // Computer account: REALMhost + hostname.realm
        let hostname = username.trim_end_matches('$').to_lowercase();
        format!("{}host{}.{}", realm, hostname, domain.to_lowercase())
    } else {
        // User account: REALM + username
        format!("{}{}", realm, username)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rc4_hmac_password_hash() {
        // Known test vector: password "Password123"
        // RC4-HMAC is MD4 of UTF-16LE
        let hash = password_hash(EType::Rc4Hmac, "Password123", "", 4096).unwrap();

        // Verify it's 32 hex chars (16 bytes)
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_aes256_password_hash() {
        // AES256 with salt
        let hash = password_hash(
            EType::Aes256CtsHmacSha1,
            "Password123",
            "DOMAIN.COMuser",
            4096,
        )
        .unwrap();

        // Verify it's 64 hex chars (32 bytes)
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_aes128_password_hash() {
        let hash = password_hash(
            EType::Aes128CtsHmacSha1,
            "Password123",
            "DOMAIN.COMuser",
            4096,
        )
        .unwrap();

        // Verify it's 32 hex chars (16 bytes)
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_des_cbc_md5_password_hash() {
        let hash = password_hash(
            EType::DesCbcMd5,
            "Password123SecretSalt",
            "salt",
            4096,
        )
        .unwrap();

        // Verify it's 16 hex chars (8 bytes)
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_compute_salt_user() {
        let salt = compute_salt("DOMAIN.COM", "alice");
        assert_eq!(salt, "DOMAIN.COMalice");
    }

    #[test]
    fn test_compute_salt_computer() {
        let salt = compute_salt("DOMAIN.COM", "WS01$");
        assert_eq!(salt, "DOMAIN.COMhostws01.domain.com");
    }

    #[test]
    fn test_etype_key_sizes() {
        assert_eq!(EType::Rc4Hmac.key_size(), 16);
        assert_eq!(EType::Aes128CtsHmacSha1.key_size(), 16);
        assert_eq!(EType::Aes256CtsHmacSha1.key_size(), 32);
        assert_eq!(EType::DesCbcMd5.key_size(), 8);
    }

    #[test]
    fn test_zero_iterations_error() {
        let result = password_hash(EType::Aes256CtsHmacSha1, "password", "salt", 0);
        assert!(result.is_err());
    }
}
