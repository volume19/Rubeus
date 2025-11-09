//! Kerberos primitive data structures
//! Ported from Rubeus/lib/krb_structures/*.cs
//!
//! Core types used in Kerberos protocol messages (RFC 4120).

use crate::asn1::{AsnElt, TagClass, tags};
use crate::asn1::error::{Result as AsnResult, AsnError};
use chrono::{DateTime, Utc, TimeZone};
use bitflags::bitflags;

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

// =============================================================================
// Realm, Time, and Ticket Structures
// =============================================================================

/// Realm is a KerberosString (GeneralString in ASN.1)
/// Represents a Kerberos realm (domain name)
pub type Realm = String;

/// KerberosTime - timestamp used in Kerberos protocol (RFC 4120 Section 5.2.3)
///
/// Represented as GeneralizedTime in ASN.1: YYYYMMDDHHmmssZ
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KerberosTime(pub DateTime<Utc>);

impl KerberosTime {
    /// Create a new KerberosTime from DateTime
    pub fn new(dt: DateTime<Utc>) -> Self {
        KerberosTime(dt)
    }

    /// Create from Unix timestamp
    pub fn from_timestamp(secs: i64) -> Option<Self> {
        Utc.timestamp_opt(secs, 0).single().map(KerberosTime)
    }

    /// Parse from ASN.1 GeneralizedTime string
    ///
    /// Format: YYYYMMDDHHmmssZ
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        let bytes = asn.get_primitive_bytes()?;
        let time_str = std::str::from_utf8(bytes)
            .map_err(|e| AsnError::InvalidEncoding(format!("invalid UTF-8 in time: {}", e)))?;

        // Parse GeneralizedTime format: YYYYMMDDHHmmssZ
        if time_str.len() < 15 || !time_str.ends_with('Z') {
            return Err(AsnError::InvalidEncoding(format!("invalid KerberosTime format: {}", time_str)));
        }

        let year: i32 = time_str[0..4].parse()
            .map_err(|_| AsnError::InvalidEncoding("invalid year".to_string()))?;
        let month: u32 = time_str[4..6].parse()
            .map_err(|_| AsnError::InvalidEncoding("invalid month".to_string()))?;
        let day: u32 = time_str[6..8].parse()
            .map_err(|_| AsnError::InvalidEncoding("invalid day".to_string()))?;
        let hour: u32 = time_str[8..10].parse()
            .map_err(|_| AsnError::InvalidEncoding("invalid hour".to_string()))?;
        let min: u32 = time_str[10..12].parse()
            .map_err(|_| AsnError::InvalidEncoding("invalid minute".to_string()))?;
        let sec: u32 = time_str[12..14].parse()
            .map_err(|_| AsnError::InvalidEncoding("invalid second".to_string()))?;

        let dt = Utc.with_ymd_and_hms(year, month, day, hour, min, sec)
            .single()
            .ok_or_else(|| AsnError::InvalidEncoding("invalid datetime".to_string()))?;

        Ok(KerberosTime(dt))
    }

    /// Get as Unix timestamp
    pub fn timestamp(&self) -> i64 {
        self.0.timestamp()
    }
}

bitflags! {
    /// Ticket flags (RFC 4120 Section 5.3)
    ///
    /// Flags indicating various properties of a Kerberos ticket.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct TicketFlags: u32 {
        const RESERVED        = 0x8000_0000;
        const FORWARDABLE     = 0x4000_0000;
        const FORWARDED       = 0x2000_0000;
        const PROXIABLE       = 0x1000_0000;
        const PROXY           = 0x0800_0000;
        const MAY_POSTDATE    = 0x0400_0000;
        const POSTDATED       = 0x0200_0000;
        const INVALID         = 0x0100_0000;
        const RENEWABLE       = 0x0080_0000;
        const INITIAL         = 0x0040_0000;
        const PRE_AUTHENT     = 0x0020_0000;
        const HW_AUTHENT      = 0x0010_0000;
        const OK_AS_DELEGATE  = 0x0004_0000;
        const ANONYMOUS       = 0x0002_0000;
        const NAME_CANONICALIZE = 0x0001_0000;
        const ENC_PA_REP      = 0x0001_0000;  // Same as NAME_CANONICALIZE
    }
}

impl TicketFlags {
    /// Parse from ASN.1 BIT STRING or INTEGER
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        // C# code: Convert.ToUInt32(s.Sub[0].GetInteger())
        let value = get_integer_i32(asn)? as u32;
        Ok(TicketFlags::from_bits_truncate(value))
    }
}

/// Ticket structure (RFC 4120 Section 5.3)
///
/// ```asn1
/// Ticket ::= [APPLICATION 1] SEQUENCE {
///     tkt-vno     [0] INTEGER (5),
///     realm       [1] Realm,
///     sname       [2] PrincipalName,
///     enc-part    [3] EncryptedData -- EncTicketPart
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct Ticket {
    /// Ticket version number (always 5 for Kerberos v5)
    pub tkt_vno: i32,
    /// Service realm
    pub realm: Realm,
    /// Service principal name
    pub sname: PrincipalName,
    /// Encrypted ticket part
    pub enc_part: EncryptedData,
}

impl Ticket {
    /// Create a new ticket
    pub fn new(realm: String, sname: PrincipalName, enc_part: EncryptedData) -> Self {
        Ticket {
            tkt_vno: 5,
            realm,
            sname,
            enc_part,
        }
    }

    /// Parse from ASN.1 element
    ///
    /// Expects [APPLICATION 1] SEQUENCE structure
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        // Check for APPLICATION 1 tag
        asn.check_tag(TagClass::Application, 1)?;

        let outer_seq = asn.get_sub(0)?;
        outer_seq.check_constructed()?;

        let mut tkt_vno = None;
        let mut realm = None;
        let mut sname = None;
        let mut enc_part = None;

        // Parse context-tagged fields
        for field in outer_seq.get_subs()? {
            match field.tag_value {
                0 => {
                    // tkt-vno [0] INTEGER (5)
                    tkt_vno = Some(get_integer_i32(field.get_sub(0)?)?);
                }
                1 => {
                    // realm [1] Realm (GeneralString)
                    let bytes = field.get_sub(0)?.get_primitive_bytes()?;
                    realm = Some(String::from_utf8(bytes.to_vec())
                        .map_err(|e| AsnError::InvalidEncoding(format!("invalid UTF-8 in realm: {}", e)))?);
                }
                2 => {
                    // sname [2] PrincipalName
                    sname = Some(PrincipalName::from_asn(field.get_sub(0)?)?);
                }
                3 => {
                    // enc-part [3] EncryptedData
                    enc_part = Some(EncryptedData::from_asn(field.get_sub(0)?)?);
                }
                _ => {
                    // Ignore unknown fields
                }
            }
        }

        let tkt_vno = tkt_vno.ok_or_else(|| AsnError::InvalidEncoding("missing tkt_vno".to_string()))?;
        let realm = realm.ok_or_else(|| AsnError::InvalidEncoding("missing realm".to_string()))?;
        let sname = sname.ok_or_else(|| AsnError::InvalidEncoding("missing sname".to_string()))?;
        let enc_part = enc_part.ok_or_else(|| AsnError::InvalidEncoding("missing enc_part".to_string()))?;

        Ok(Ticket {
            tkt_vno,
            realm,
            sname,
            enc_part,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, Timelike};

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

    #[test]
    fn test_kerberos_time_from_timestamp() {
        let kt = KerberosTime::from_timestamp(1234567890).unwrap();
        assert_eq!(kt.timestamp(), 1234567890);
    }

    #[test]
    fn test_kerberos_time_from_asn() {
        // 20250101120000Z = Jan 1, 2025 12:00:00 UTC
        let time_bytes = b"20250101120000Z";
        let asn = AsnElt::new_primitive(TagClass::Universal, tags::GENERALIZED_TIME as u32, time_bytes.to_vec());

        let kt = KerberosTime::from_asn(&asn).unwrap();
        let dt = kt.0;
        assert_eq!(dt.year(), 2025);
        assert_eq!(dt.month(), 1);
        assert_eq!(dt.day(), 1);
        assert_eq!(dt.hour(), 12);
        assert_eq!(dt.minute(), 0);
        assert_eq!(dt.second(), 0);
    }

    #[test]
    fn test_ticket_flags_bitflags() {
        let flags = TicketFlags::FORWARDABLE | TicketFlags::RENEWABLE;
        assert!(flags.contains(TicketFlags::FORWARDABLE));
        assert!(flags.contains(TicketFlags::RENEWABLE));
        assert!(!flags.contains(TicketFlags::PROXIABLE));
    }

    #[test]
    fn test_ticket_flags_from_bits() {
        let flags = TicketFlags::from_bits_truncate(0x4000_0000);
        assert_eq!(flags, TicketFlags::FORWARDABLE);
    }

    #[test]
    fn test_ticket_new() {
        let sname = PrincipalName::new(
            PrincipalType::NtSrvInst,
            vec!["krbtgt".to_string(), "REALM.COM".to_string()]
        );
        let enc_part = EncryptedData::new(18, vec![0xAA, 0xBB]);

        let ticket = Ticket::new("REALM.COM".to_string(), sname.clone(), enc_part.clone());
        assert_eq!(ticket.tkt_vno, 5);
        assert_eq!(ticket.realm, "REALM.COM");
        assert_eq!(ticket.sname, sname);
        assert_eq!(ticket.enc_part, enc_part);
    }
}
