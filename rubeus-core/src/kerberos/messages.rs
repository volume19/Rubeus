//! Kerberos protocol messages (AS-REQ, AS-REP, TGS-REQ, TGS-REP)
//! Ported from Rubeus/lib/krb_structures/*.cs
//!
//! Implements RFC 4120 message structures for Kerberos authentication.

use crate::asn1::{AsnElt, TagClass};
use crate::asn1::error::{Result as AsnResult, AsnError};
use crate::kerberos::primitives::{
    PrincipalName, EncryptedData, KerberosTime, Ticket, Realm
};
use bitflags::bitflags;

bitflags! {
    /// KDC Options flags (RFC 4120 Section 5.4.1)
    ///
    /// Flags used in KDC-REQ-BODY to specify options for ticket requests.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct KdcOptions: u32 {
        const VALIDATE                 = 0x00000001;
        const RENEW                    = 0x00000002;
        const UNUSED29                 = 0x00000004;
        const ENC_TKT_IN_SKEY          = 0x00000008;
        const RENEWABLE_OK             = 0x00000010;
        const DISABLE_TRANSITED_CHECK  = 0x00000020;
        const UNUSED16                 = 0x0000_FFC0;
        const CONSTRAINED_DELEGATION   = 0x0002_0000;
        const CANONICALIZE             = 0x0001_0000;
        const CNAME_IN_ADDL_TKT        = 0x0000_4000;
        const OK_AS_DELEGATE           = 0x0004_0000;
        const REQUEST_ANONYMOUS        = 0x0000_8000;
        const UNUSED12                 = 0x0008_0000;
        const OPT_HARDWARE_AUTH        = 0x0010_0000;
        const PREAUTHENT               = 0x0020_0000;
        const INITIAL                  = 0x0040_0000;
        const RENEWABLE                = 0x0080_0000;
        const UNUSED7                  = 0x0100_0000;
        const POSTDATED                = 0x0200_0000;
        const ALLOW_POSTDATE           = 0x0400_0000;
        const PROXY                    = 0x0800_0000;
        const PROXIABLE                = 0x1000_0000;
        const FORWARDED                = 0x2000_0000;
        const FORWARDABLE              = 0x4000_0000;
        const RESERVED                 = 0x8000_0000;
    }
}

/// PA-DATA type identifiers (RFC 4120)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PaDataType {
    TgsReq = 1,
    EncTimestamp = 2,
    PwSalt = 3,
    EncUnixTime = 5,
    Sandia = 6,
    Sesame = 7,
    OsfDce = 8,
    Cybersafe = 9,
    AfsFs = 10,
    EtypeInfo2 = 19,
    SvrReferralInfo = 20,
    SamChallenge = 24,
    SamResponse = 25,
    PkAsReq19 = 14,
    PkAsRep19 = 15,
    PkAsReq = 16,
    PkAsRep = 17,
    EtypeInfo = 11,
    SamChallenge2 = 30,
    SamResponse2 = 31,
    PaPacRequest = 128,
    ForUser = 129,
    S4uX509User = 130,
    PaPacOptions = 167,
}

/// Pre-authentication data (RFC 4120 Section 5.2.7)
///
/// ```asn1
/// PA-DATA ::= SEQUENCE {
///     padata-type  [1] Int32,
///     padata-value [2] OCTET STRING
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct PaData {
    /// Pre-authentication data type
    pub pa_type: i32,
    /// Pre-authentication data value (type-specific)
    pub pa_value: Vec<u8>,
}

impl PaData {
    /// Create new PA-DATA
    pub fn new(pa_type: i32, pa_value: Vec<u8>) -> Self {
        PaData { pa_type, pa_value }
    }

    /// Parse from ASN.1 element
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        asn.check_constructed()?;

        let subs = asn.get_subs()?;
        if subs.len() < 2 {
            return Err(AsnError::InvalidEncoding("PA-DATA requires at least 2 fields".to_string()));
        }

        let mut pa_type = None;
        let mut pa_value = None;

        for field in subs {
            match field.tag_value {
                1 => {
                    // padata-type [1] Int32
                    pa_type = Some(super::primitives::get_integer_i32(field.get_sub(0)?)?);
                }
                2 => {
                    // padata-value [2] OCTET STRING
                    pa_value = Some(field.get_sub(0)?.get_primitive_bytes()?.to_vec());
                }
                _ => {
                    // Ignore unknown fields
                }
            }
        }

        let pa_type = pa_type.ok_or_else(|| AsnError::InvalidEncoding("missing pa_type".to_string()))?;
        let pa_value = pa_value.ok_or_else(|| AsnError::InvalidEncoding("missing pa_value".to_string()))?;

        Ok(PaData { pa_type, pa_value })
    }
}

/// KDC-REQ-BODY structure (RFC 4120 Section 5.4.1)
///
/// Common body for AS-REQ and TGS-REQ messages.
///
/// ```asn1
/// KDC-REQ-BODY ::= SEQUENCE {
///     kdc-options             [0] KDCOptions,
///     cname                   [1] PrincipalName OPTIONAL,
///     realm                   [2] Realm,
///     sname                   [3] PrincipalName OPTIONAL,
///     from                    [4] KerberosTime OPTIONAL,
///     till                    [5] KerberosTime,
///     rtime                   [6] KerberosTime OPTIONAL,
///     nonce                   [7] UInt32,
///     etype                   [8] SEQUENCE OF Int32,
///     addresses               [9] HostAddresses OPTIONAL,
///     enc-authorization-data  [10] EncryptedData OPTIONAL,
///     additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct KdcReqBody {
    /// KDC options flags
    pub kdc_options: KdcOptions,
    /// Client principal name (used in AS-REQ)
    pub cname: Option<PrincipalName>,
    /// Realm (server's realm, also client's in AS-REQ)
    pub realm: Realm,
    /// Service principal name
    pub sname: Option<PrincipalName>,
    /// Start time (optional)
    pub from: Option<KerberosTime>,
    /// End time
    pub till: KerberosTime,
    /// Renewable till time (optional)
    pub rtime: Option<KerberosTime>,
    /// Random nonce
    pub nonce: u32,
    /// Requested encryption types (in preference order)
    pub etypes: Vec<i32>,
    // Note: addresses, enc_authorization_data, additional_tickets omitted for now
}

impl KdcReqBody {
    /// Create new KDC-REQ-BODY with default values
    pub fn new(realm: String) -> Self {
        // Default: 2037-09-13 02:48:05 UTC (from kekeo)
        let till = KerberosTime::from_timestamp(2133478085).unwrap();

        KdcReqBody {
            kdc_options: KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE | KdcOptions::RENEWABLE_OK,
            cname: None,
            realm,
            sname: None,
            from: None,
            till,
            rtime: None,
            nonce: 0,
            etypes: Vec::new(),
        }
    }

    /// Parse from ASN.1 element
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        asn.check_constructed()?;

        let mut kdc_options = None;
        let mut cname = None;
        let mut realm = None;
        let mut sname = None;
        let mut from = None;
        let mut till = None;
        let mut rtime = None;
        let mut nonce = None;
        let mut etypes = Vec::new();

        for field in asn.get_subs()? {
            match field.tag_value {
                0 => {
                    // kdc-options [0] KDCOptions (BIT STRING)
                    let opts_i32 = super::primitives::get_integer_i32(field.get_sub(0)?)? as u32;
                    kdc_options = Some(KdcOptions::from_bits_truncate(opts_i32));
                }
                1 => {
                    // cname [1] PrincipalName OPTIONAL
                    cname = Some(PrincipalName::from_asn(field.get_sub(0)?)?);
                }
                2 => {
                    // realm [2] Realm
                    let bytes = field.get_sub(0)?.get_primitive_bytes()?;
                    realm = Some(String::from_utf8(bytes.to_vec())
                        .map_err(|e| AsnError::InvalidEncoding(format!("invalid UTF-8 in realm: {}", e)))?);
                }
                3 => {
                    // sname [3] PrincipalName OPTIONAL
                    sname = Some(PrincipalName::from_asn(field.get_sub(0)?)?);
                }
                4 => {
                    // from [4] KerberosTime OPTIONAL
                    from = Some(KerberosTime::from_asn(field.get_sub(0)?)?);
                }
                5 => {
                    // till [5] KerberosTime
                    till = Some(KerberosTime::from_asn(field.get_sub(0)?)?);
                }
                6 => {
                    // rtime [6] KerberosTime OPTIONAL
                    rtime = Some(KerberosTime::from_asn(field.get_sub(0)?)?);
                }
                7 => {
                    // nonce [7] UInt32
                    let nonce_i64 = super::primitives::get_integer_i64(field.get_sub(0)?)?;
                    nonce = Some((nonce_i64 & 0xFFFF_FFFF) as u32);
                }
                8 => {
                    // etype [8] SEQUENCE OF Int32
                    let etype_seq = field.get_sub(0)?;
                    etype_seq.check_constructed()?;
                    for etype_elt in etype_seq.get_subs()? {
                        let etype = super::primitives::get_integer_i32(etype_elt)?;
                        etypes.push(etype);
                    }
                }
                _ => {
                    // Ignore optional fields 9, 10, 11 for now
                }
            }
        }

        let kdc_options = kdc_options.ok_or_else(|| AsnError::InvalidEncoding("missing kdc_options".to_string()))?;
        let realm = realm.ok_or_else(|| AsnError::InvalidEncoding("missing realm".to_string()))?;
        let till = till.ok_or_else(|| AsnError::InvalidEncoding("missing till".to_string()))?;
        let nonce = nonce.ok_or_else(|| AsnError::InvalidEncoding("missing nonce".to_string()))?;

        Ok(KdcReqBody {
            kdc_options,
            cname,
            realm,
            sname,
            from,
            till,
            rtime,
            nonce,
            etypes,
        })
    }
}

/// AS-REQ structure (RFC 4120 Section 5.4.1)
///
/// ```asn1
/// AS-REQ ::= [APPLICATION 10] KDC-REQ
///
/// KDC-REQ ::= SEQUENCE {
///     pvno            [1] INTEGER (5),
///     msg-type        [2] INTEGER (10 -- AS),
///     padata          [3] SEQUENCE OF PA-DATA OPTIONAL,
///     req-body        [4] KDC-REQ-BODY
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AsReq {
    /// Protocol version number (always 5)
    pub pvno: i32,
    /// Message type (10 for AS-REQ)
    pub msg_type: i32,
    /// Pre-authentication data
    pub padata: Vec<PaData>,
    /// Request body
    pub req_body: KdcReqBody,
}

impl AsReq {
    /// Create new AS-REQ with default values
    pub fn new(realm: String) -> Self {
        AsReq {
            pvno: 5,
            msg_type: 10,
            padata: Vec::new(),
            req_body: KdcReqBody::new(realm),
        }
    }

    /// Parse from ASN.1 element
    ///
    /// Expects [APPLICATION 10] SEQUENCE structure
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        // Check for APPLICATION 10 tag
        asn.check_tag(TagClass::Application, 10)?;

        let outer_seq = asn.get_sub(0)?;
        outer_seq.check_constructed()?;

        let mut pvno = None;
        let mut msg_type = None;
        let mut padata = Vec::new();
        let mut req_body = None;

        // Parse context-tagged fields (note: starts at [1] not [0])
        for field in outer_seq.get_subs()? {
            match field.tag_value {
                1 => {
                    // pvno [1] INTEGER (5)
                    pvno = Some(super::primitives::get_integer_i32(field.get_sub(0)?)?);
                }
                2 => {
                    // msg-type [2] INTEGER (10 -- AS)
                    msg_type = Some(super::primitives::get_integer_i32(field.get_sub(0)?)?);
                }
                3 => {
                    // padata [3] SEQUENCE OF PA-DATA OPTIONAL
                    let padata_seq = field.get_sub(0)?;
                    padata_seq.check_constructed()?;
                    for pa_elt in padata_seq.get_subs()? {
                        padata.push(PaData::from_asn(pa_elt)?);
                    }
                }
                4 => {
                    // req-body [4] KDC-REQ-BODY
                    req_body = Some(KdcReqBody::from_asn(field.get_sub(0)?)?);
                }
                _ => {
                    // Ignore unknown fields
                }
            }
        }

        let pvno = pvno.ok_or_else(|| AsnError::InvalidEncoding("missing pvno".to_string()))?;
        let msg_type = msg_type.ok_or_else(|| AsnError::InvalidEncoding("missing msg_type".to_string()))?;
        let req_body = req_body.ok_or_else(|| AsnError::InvalidEncoding("missing req_body".to_string()))?;

        Ok(AsReq {
            pvno,
            msg_type,
            padata,
            req_body,
        })
    }
}

/// AS-REP structure (RFC 4120 Section 5.4.2)
///
/// ```asn1
/// AS-REP ::= [APPLICATION 11] KDC-REP
///
/// KDC-REP ::= SEQUENCE {
///     pvno         [0] INTEGER (5),
///     msg-type     [1] INTEGER (11 -- AS),
///     padata       [2] SEQUENCE OF PA-DATA OPTIONAL,
///     crealm       [3] Realm,
///     cname        [4] PrincipalName,
///     ticket       [5] Ticket,
///     enc-part     [6] EncryptedData
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct AsRep {
    /// Protocol version number (always 5)
    pub pvno: i32,
    /// Message type (11 for AS-REP)
    pub msg_type: i32,
    /// Pre-authentication data (optional)
    pub padata: Vec<PaData>,
    /// Client realm
    pub crealm: Realm,
    /// Client principal name
    pub cname: PrincipalName,
    /// Ticket
    pub ticket: Ticket,
    /// Encrypted part (EncASRepPart)
    pub enc_part: EncryptedData,
}

impl AsRep {
    /// Parse from ASN.1 element
    ///
    /// Expects [APPLICATION 11] SEQUENCE structure
    pub fn from_asn(asn: &AsnElt) -> AsnResult<Self> {
        // Check for APPLICATION 11 tag
        asn.check_tag(TagClass::Application, 11)?;

        let outer_seq = asn.get_sub(0)?;
        outer_seq.check_constructed()?;

        let mut pvno = None;
        let mut msg_type = None;
        let mut padata = Vec::new();
        let mut crealm = None;
        let mut cname = None;
        let mut ticket = None;
        let mut enc_part = None;

        // Parse context-tagged fields (starts at [0] for KDC-REP)
        for field in outer_seq.get_subs()? {
            match field.tag_value {
                0 => {
                    // pvno [0] INTEGER (5)
                    pvno = Some(super::primitives::get_integer_i32(field.get_sub(0)?)?);
                }
                1 => {
                    // msg-type [1] INTEGER (11 -- AS)
                    msg_type = Some(super::primitives::get_integer_i32(field.get_sub(0)?)?);
                }
                2 => {
                    // padata [2] SEQUENCE OF PA-DATA OPTIONAL
                    let padata_seq = field.get_sub(0)?;
                    padata_seq.check_constructed()?;
                    for pa_elt in padata_seq.get_subs()? {
                        padata.push(PaData::from_asn(pa_elt)?);
                    }
                }
                3 => {
                    // crealm [3] Realm
                    let bytes = field.get_sub(0)?.get_primitive_bytes()?;
                    crealm = Some(String::from_utf8(bytes.to_vec())
                        .map_err(|e| AsnError::InvalidEncoding(format!("invalid UTF-8 in crealm: {}", e)))?);
                }
                4 => {
                    // cname [4] PrincipalName
                    cname = Some(PrincipalName::from_asn(field.get_sub(0)?)?);
                }
                5 => {
                    // ticket [5] Ticket
                    // Note: C# code has s.Sub[0].Sub[0], suggesting extra wrapping
                    let ticket_asn = field.get_sub(0)?;
                    ticket = Some(Ticket::from_asn(ticket_asn)?);
                }
                6 => {
                    // enc-part [6] EncryptedData
                    enc_part = Some(EncryptedData::from_asn(field.get_sub(0)?)?);
                }
                _ => {
                    // Ignore unknown fields
                }
            }
        }

        let pvno = pvno.ok_or_else(|| AsnError::InvalidEncoding("missing pvno".to_string()))?;
        let msg_type = msg_type.ok_or_else(|| AsnError::InvalidEncoding("missing msg_type".to_string()))?;
        let crealm = crealm.ok_or_else(|| AsnError::InvalidEncoding("missing crealm".to_string()))?;
        let cname = cname.ok_or_else(|| AsnError::InvalidEncoding("missing cname".to_string()))?;
        let ticket = ticket.ok_or_else(|| AsnError::InvalidEncoding("missing ticket".to_string()))?;
        let enc_part = enc_part.ok_or_else(|| AsnError::InvalidEncoding("missing enc_part".to_string()))?;

        Ok(AsRep {
            pvno,
            msg_type,
            padata,
            crealm,
            cname,
            ticket,
            enc_part,
        })
    }
}

// Helper trait extension for check_constructed
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
    fn test_kdc_options_bitflags() {
        let opts = KdcOptions::FORWARDABLE | KdcOptions::RENEWABLE;
        assert!(opts.contains(KdcOptions::FORWARDABLE));
        assert!(opts.contains(KdcOptions::RENEWABLE));
        assert!(!opts.contains(KdcOptions::PROXIABLE));
    }

    #[test]
    fn test_kdc_options_from_bits() {
        let opts = KdcOptions::from_bits_truncate(0x4000_0000);
        assert_eq!(opts, KdcOptions::FORWARDABLE);
    }

    #[test]
    fn test_pa_data_new() {
        let pa = PaData::new(2, vec![0x01, 0x02, 0x03]);
        assert_eq!(pa.pa_type, 2);
        assert_eq!(pa.pa_value, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_kdc_req_body_new() {
        let body = KdcReqBody::new("REALM.COM".to_string());
        assert_eq!(body.realm, "REALM.COM");
        assert!(body.kdc_options.contains(KdcOptions::FORWARDABLE));
        assert!(body.kdc_options.contains(KdcOptions::RENEWABLE));
    }

    #[test]
    fn test_as_req_new() {
        let req = AsReq::new("REALM.COM".to_string());
        assert_eq!(req.pvno, 5);
        assert_eq!(req.msg_type, 10);
        assert_eq!(req.req_body.realm, "REALM.COM");
    }
}
