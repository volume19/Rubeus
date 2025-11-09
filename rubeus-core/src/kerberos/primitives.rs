//! Kerberos primitive data structures
//! Ported from Rubeus/lib/krb_structures/*.cs
//!
//! Core types used in Kerberos protocol messages (RFC 4120).

use crate::asn1::{AsnElt, TagClass, tags};
use crate::asn1::error::{Result as AsnResult, AsnError};

/// Kerberos principal name types (RFC 4120 Section 6.2)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PrincipalType {
    /// Name type not known
    NtUnknown = 0,
    /// Just the name of the principal as in DCE, or for users
    NtPrincipal = 1,
    /// Service and other unique instance (krbtgt)
    NtSrvInst = 2,
    /// Service with host name as instance (telnet, rcommands)
    NtSrvHst = 3,
    /// Service with host as remaining components
    NtSrvXhst = 4,
    /// Unique ID
    NtUid = 5,
    /// Encoded X.509 Distinguished name
    NtX500Principal = 6,
    /// Name in form of SMTP email name
    NtSmtpName = 7,
    /// Enterprise name - may be mapped to principal name
    NtEnterprise = 10,
}

impl PrincipalType {
    /// Convert from i32 value
    pub fn from_i32(value: i32) -> Option<Self> {
        match value {
            0 => Some(PrincipalType::NtUnknown),
            1 => Some(PrincipalType::NtPrincipal),
            2 => Some(PrincipalType::NtSrvInst),
            3 => Some(PrincipalType::NtSrvHst),
            4 => Some(PrincipalType::NtSrvXhst),
            5 => Some(PrincipalType::NtUid),
            6 => Some(PrincipalType::NtX500Principal),
            7 => Some(PrincipalType::NtSmtpName),
            10 => Some(PrincipalType::NtEnterprise),
            _ => None,
        }
    }
}

/// PrincipalName structure (RFC 4120)
///
/// ```asn1
/// PrincipalName ::= SEQUENCE {
///     name-type   [0] Int32,
///     name-string [1] SEQUENCE OF KerberosString
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PrincipalName {
    /// Type of principal name
    pub name_type: PrincipalType,
    /// Components of the principal name (e.g., ["user"] or ["krbtgt", "REALM.COM"])
    pub name_string: Vec<String>,
}

impl PrincipalName {
    /// Create a new principal name
    pub fn new(name_type: PrincipalType, name_string: Vec<String>) -> Self {
        PrincipalName {
            name_type,
            name_string,
        }
    }

    /// Parse from ASN.1 element
    ///
    /// Expects structure:
    /// SEQUENCE {
    ///   [0] SEQUENCE { INTEGER }      -- name-type
    ///   [1] SEQUENCE { SEQUENCE OF GeneralString }  -- name-string
    /// }
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        asn.check_constructed()?;

        let subs = asn.get_subs()?;
        if subs.len() < 2 {
            return Err(AsnError::InvalidEncoding(
                "PrincipalName requires at least 2 fields".to_string()
            ));
        }

        // Parse name-type [0]
        subs[0].check_tag(TagClass::Context, 0)?;
        let name_type_int = get_integer_i32(subs[0].get_sub(0)?)?;
        let name_type = PrincipalType::from_i32(name_type_int)
            .ok_or_else(|| AsnError::InvalidEncoding(format!("invalid principal type: {}", name_type_int)))?;

        // Parse name-string [1] SEQUENCE OF GeneralString
        subs[1].check_tag(TagClass::Context, 1)?;
        let name_seq = subs[1].get_sub(0)?;
        name_seq.check_constructed()?;

        let mut name_string = Vec::new();
        for name_elt in name_seq.get_subs()? {
            // Each element is a GeneralString (OCTET STRING in DER)
            let bytes = name_elt.get_primitive_bytes()?;
            let s = String::from_utf8(bytes.to_vec())
                .map_err(|e| AsnError::InvalidEncoding(format!("invalid UTF-8 in name string: {}", e)))?;
            name_string.push(s);
        }

        Ok(PrincipalName {
            name_type,
            name_string,
        })
    }

    /// Get principal name as string (join components with '/')
    pub fn to_string(&self) -> String {
        self.name_string.join("/")
    }
}

/// EncryptionKey structure (RFC 4120)
///
/// ```asn1
/// EncryptionKey ::= SEQUENCE {
///     keytype  [0] Int32 -- actually encryption type --,
///     keyvalue [1] OCTET STRING
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptionKey {
    /// Encryption type (EType value)
    pub keytype: i32,
    /// Key material
    pub keyvalue: Vec<u8>,
}

impl EncryptionKey {
    /// Create a new encryption key
    pub fn new(keytype: i32, keyvalue: Vec<u8>) -> Self {
        EncryptionKey { keytype, keyvalue }
    }

    /// Parse from ASN.1 element
    ///
    /// Expects structure:
    /// SEQUENCE {
    ///   SEQUENCE {
    ///     [0] SEQUENCE { INTEGER }      -- keytype
    ///     [1] SEQUENCE { OCTET STRING } -- keyvalue
    ///   }
    /// }
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        asn.check_constructed()?;

        let outer_seq = asn.get_sub(0)?;
        outer_seq.check_constructed()?;

        let mut keytype = None;
        let mut keyvalue = None;

        // Parse context-tagged fields
        for field in outer_seq.get_subs()? {
            match field.tag_value {
                0 => {
                    // keytype [0] Int32
                    keytype = Some(get_integer_i32(field.get_sub(0)?)?);
                }
                1 | 2 => {
                    // keyvalue [1] or [2] OCTET STRING
                    // Note: C# code checks both [1] and [2] tags
                    keyvalue = Some(field.get_sub(0)?.get_primitive_bytes()?.to_vec());
                }
                _ => {
                    // Ignore unknown fields
                }
            }
        }

        let keytype = keytype.ok_or_else(|| AsnError::InvalidEncoding("missing keytype".to_string()))?;
        let keyvalue = keyvalue.ok_or_else(|| AsnError::InvalidEncoding("missing keyvalue".to_string()))?;

        Ok(EncryptionKey { keytype, keyvalue })
    }
}

/// EncryptedData structure (RFC 4120)
///
/// ```asn1
/// EncryptedData ::= SEQUENCE {
///     etype  [0] Int32 -- EncryptionType --,
///     kvno   [1] UInt32 OPTIONAL,
///     cipher [2] OCTET STRING -- ciphertext
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedData {
    /// Encryption type
    pub etype: i32,
    /// Key version number (optional)
    pub kvno: Option<u32>,
    /// Ciphertext
    pub cipher: Vec<u8>,
}

impl EncryptedData {
    /// Create a new EncryptedData
    pub fn new(etype: i32, cipher: Vec<u8>) -> Self {
        EncryptedData {
            etype,
            kvno: None,
            cipher,
        }
    }

    /// Create a new EncryptedData with key version number
    pub fn new_with_kvno(etype: i32, kvno: u32, cipher: Vec<u8>) -> Self {
        EncryptedData {
            etype,
            kvno: Some(kvno),
            cipher,
        }
    }

    /// Parse from ASN.1 element
    ///
    /// Expects structure:
    /// SEQUENCE {
    ///   [0] SEQUENCE { INTEGER }      -- etype
    ///   [1] SEQUENCE { INTEGER }      -- kvno (optional)
    ///   [2] SEQUENCE { OCTET STRING } -- cipher
    /// }
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        asn.check_constructed()?;

        let mut etype = None;
        let mut kvno = None;
        let mut cipher = None;

        // Parse context-tagged fields
        for field in asn.get_subs()? {
            match field.tag_value {
                0 => {
                    // etype [0] Int32
                    etype = Some(get_integer_i32(field.get_sub(0)?)?);
                }
                1 => {
                    // kvno [1] UInt32
                    let kvno_i64 = get_integer_i64(field.get_sub(0)?)?;
                    // Mask to 32 bits (C# code: Convert.ToUInt32(tmpLong & 0x00000000ffffffff))
                    kvno = Some((kvno_i64 & 0xFFFF_FFFF) as u32);
                }
                2 => {
                    // cipher [2] OCTET STRING
                    cipher = Some(field.get_sub(0)?.get_primitive_bytes()?.to_vec());
                }
                _ => {
                    // Ignore unknown fields
                }
            }
        }

        let etype = etype.ok_or_else(|| AsnError::InvalidEncoding("missing etype".to_string()))?;
        let cipher = cipher.ok_or_else(|| AsnError::InvalidEncoding("missing cipher".to_string()))?;

        Ok(EncryptedData { etype, kvno, cipher })
    }
}

// Helper functions for ASN.1 INTEGER parsing

/// Get INTEGER value as i32
fn get_integer_i32(asn: &AsnElt) -> AsnResult<i32> {
    asn.check_universal_tag(tags::INTEGER as u32)?;
    let bytes = asn.get_primitive_bytes()?;

    if bytes.is_empty() {
        return Err(AsnError::InvalidEncoding("empty INTEGER".to_string()));
    }

    // DER INTEGER is big-endian, two's complement
    let is_negative = (bytes[0] & 0x80) != 0;

    if bytes.len() > 4 {
        return Err(AsnError::IntegerOverflow);
    }

    let mut value = if is_negative { -1i32 } else { 0i32 };
    for &byte in bytes {
        value = value.checked_shl(8)
            .ok_or(AsnError::IntegerOverflow)?;
        value |= byte as i32;
    }

    Ok(value)
}

/// Get INTEGER value as i64
fn get_integer_i64(asn: &AsnElt) -> AsnResult<i64> {
    asn.check_universal_tag(tags::INTEGER as u32)?;
    let bytes = asn.get_primitive_bytes()?;

    if bytes.is_empty() {
        return Err(AsnError::InvalidEncoding("empty INTEGER".to_string()));
    }

    let is_negative = (bytes[0] & 0x80) != 0;

    if bytes.len() > 8 {
        return Err(AsnError::IntegerOverflow);
    }

    let mut value = if is_negative { -1i64 } else { 0i64 };
    for &byte in bytes {
        value = value.checked_shl(8)
            .ok_or(AsnError::IntegerOverflow)?;
        value |= byte as i64;
    }

    Ok(value)
}

/// Helper to check if element is constructed
trait AsnEltExt {
    fn check_constructed(&self) -> AsnResult<()>;
}

impl AsnEltExt for AsnElt {
    fn check_constructed(&self) -> AsnResult<()> {
        if !self.is_constructed() {
            return Err(AsnError::ConstructedNotAllowed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_principal_type_from_i32() {
        assert_eq!(PrincipalType::from_i32(1), Some(PrincipalType::NtPrincipal));
        assert_eq!(PrincipalType::from_i32(2), Some(PrincipalType::NtSrvInst));
        assert_eq!(PrincipalType::from_i32(10), Some(PrincipalType::NtEnterprise));
        assert_eq!(PrincipalType::from_i32(99), None);
    }

    #[test]
    fn test_principal_name_new() {
        let name = PrincipalName::new(
            PrincipalType::NtPrincipal,
            vec!["alice".to_string()]
        );
        assert_eq!(name.name_type, PrincipalType::NtPrincipal);
        assert_eq!(name.name_string, vec!["alice"]);
        assert_eq!(name.to_string(), "alice");
    }

    #[test]
    fn test_principal_name_to_string() {
        let name = PrincipalName::new(
            PrincipalType::NtSrvInst,
            vec!["krbtgt".to_string(), "REALM.COM".to_string()]
        );
        assert_eq!(name.to_string(), "krbtgt/REALM.COM");
    }

    #[test]
    fn test_encryption_key_new() {
        let key = EncryptionKey::new(23, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(key.keytype, 23);
        assert_eq!(key.keyvalue, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_encrypted_data_new() {
        let data = EncryptedData::new(18, vec![0xAA, 0xBB]);
        assert_eq!(data.etype, 18);
        assert_eq!(data.kvno, None);
        assert_eq!(data.cipher, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_encrypted_data_new_with_kvno() {
        let data = EncryptedData::new_with_kvno(18, 5, vec![0xAA, 0xBB]);
        assert_eq!(data.etype, 18);
        assert_eq!(data.kvno, Some(5));
        assert_eq!(data.cipher, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_get_integer_i32() {
        // INTEGER 42 = 02 01 2A
        let asn = AsnElt::new_primitive(TagClass::Universal, tags::INTEGER as u32, vec![0x2A]);
        assert_eq!(get_integer_i32(&asn).unwrap(), 42);

        // INTEGER 256 = 02 02 01 00
        let asn = AsnElt::new_primitive(TagClass::Universal, tags::INTEGER as u32, vec![0x01, 0x00]);
        assert_eq!(get_integer_i32(&asn).unwrap(), 256);

        // INTEGER -1 = 02 01 FF
        let asn = AsnElt::new_primitive(TagClass::Universal, tags::INTEGER as u32, vec![0xFF]);
        assert_eq!(get_integer_i32(&asn).unwrap(), -1);
    }

    #[test]
    fn test_get_integer_i64() {
        // INTEGER 0x123456789ABCDEF = big endian
        let asn = AsnElt::new_primitive(
            TagClass::Universal,
            tags::INTEGER as u32,
            vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        );
        assert_eq!(get_integer_i64(&asn).unwrap(), 0x0123_4567_89AB_CDEF);
    }
}
