//! ASN.1 element representation and operations
//! Ported from Rubeus/Asn1/AsnElt.cs
//!
//! Provides DER encoding/decoding for Kerberos protocol structures.

use super::error::{AsnError, Result};

/// Universal tag values from ITU-T X.680
#[allow(non_camel_case_types)]
pub mod tags {
    pub const BOOLEAN: u8 = 1;
    pub const INTEGER: u8 = 2;
    pub const BIT_STRING: u8 = 3;
    pub const OCTET_STRING: u8 = 4;
    pub const NULL: u8 = 5;
    pub const OBJECT_IDENTIFIER: u8 = 6;
    pub const OBJECT_DESCRIPTOR: u8 = 7;
    pub const EXTERNAL: u8 = 8;
    pub const REAL: u8 = 9;
    pub const ENUMERATED: u8 = 10;
    pub const EMBEDDED_PDV: u8 = 11;
    pub const UTF8_STRING: u8 = 12;
    pub const RELATIVE_OID: u8 = 13;
    pub const SEQUENCE: u8 = 16;
    pub const SET: u8 = 17;
    pub const NUMERIC_STRING: u8 = 18;
    pub const PRINTABLE_STRING: u8 = 19;
    pub const T61_STRING: u8 = 20;
    pub const TELETEX_STRING: u8 = 20;
    pub const VIDEOTEX_STRING: u8 = 21;
    pub const IA5_STRING: u8 = 22;
    pub const UTC_TIME: u8 = 23;
    pub const GENERALIZED_TIME: u8 = 24;
    pub const GRAPHIC_STRING: u8 = 25;
    pub const VISIBLE_STRING: u8 = 26;
    pub const GENERAL_STRING: u8 = 27;
    pub const UNIVERSAL_STRING: u8 = 28;
    pub const CHARACTER_STRING: u8 = 29;
    pub const BMP_STRING: u8 = 30;
}

/// ASN.1 tag class
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TagClass {
    Universal = 0,
    Application = 1,
    Context = 2,
    Private = 3,
}

impl TagClass {
    pub fn from_u8(value: u8) -> Result<Self> {
        match value {
            0 => Ok(TagClass::Universal),
            1 => Ok(TagClass::Application),
            2 => Ok(TagClass::Context),
            3 => Ok(TagClass::Private),
            _ => Err(AsnError::InvalidEncoding(format!("invalid tag class: {}", value))),
        }
    }

    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

/// ASN.1 element value (either primitive bytes or constructed sub-elements)
#[derive(Debug, Clone, PartialEq)]
pub enum AsnValue {
    /// Primitive value (raw bytes)
    Primitive(Vec<u8>),
    /// Constructed value (sub-elements)
    Constructed(Vec<AsnElt>),
}

/// An ASN.1 DER element (immutable)
///
/// Represents a decoded ASN.1 object with tag, class, and value.
/// Ported from Thomas Pornin's DDer library used in Rubeus.
#[derive(Debug, Clone, PartialEq)]
pub struct AsnElt {
    /// Tag class (UNIVERSAL, APPLICATION, CONTEXT, PRIVATE)
    pub tag_class: TagClass,
    /// Tag value
    pub tag_value: u32,
    /// Element value (primitive bytes or constructed sub-elements)
    pub value: AsnValue,
}

impl AsnElt {
    /// Create a new primitive ASN.1 element
    pub fn new_primitive(tag_class: TagClass, tag_value: u32, data: Vec<u8>) -> Self {
        AsnElt {
            tag_class,
            tag_value,
            value: AsnValue::Primitive(data),
        }
    }

    /// Create a new constructed ASN.1 element
    pub fn new_constructed(tag_class: TagClass, tag_value: u32, subs: Vec<AsnElt>) -> Self {
        AsnElt {
            tag_class,
            tag_value,
            value: AsnValue::Constructed(subs),
        }
    }

    /// Check if this element is constructed
    pub fn is_constructed(&self) -> bool {
        matches!(self.value, AsnValue::Constructed(_))
    }

    /// Check if this element is primitive
    pub fn is_primitive(&self) -> bool {
        matches!(self.value, AsnValue::Primitive(_))
    }

    /// Get sub-elements (returns error if not constructed)
    pub fn get_subs(&self) -> Result<&[AsnElt]> {
        match &self.value {
            AsnValue::Constructed(subs) => Ok(subs),
            AsnValue::Primitive(_) => Err(AsnError::ConstructedNotAllowed),
        }
    }

    /// Get sub-element by index
    pub fn get_sub(&self, index: usize) -> Result<&AsnElt> {
        let subs = self.get_subs()?;
        subs.get(index)
            .ok_or_else(|| AsnError::index_out_of_bounds(index, subs.len()))
    }

    /// Get primitive value bytes (returns error if constructed)
    pub fn get_primitive_bytes(&self) -> Result<&[u8]> {
        match &self.value {
            AsnValue::Primitive(bytes) => Ok(bytes),
            AsnValue::Constructed(_) => Err(AsnError::PrimitiveRequired),
        }
    }

    /// Check that tag matches expected class and value
    pub fn check_tag(&self, tag_class: TagClass, tag_value: u32) -> Result<()> {
        if self.tag_class != tag_class || self.tag_value != tag_value {
            Err(AsnError::InvalidEncoding(format!(
                "unexpected tag: expected {:?}:{}, got {:?}:{}",
                tag_class, tag_value, self.tag_class, self.tag_value
            )))
        } else {
            Ok(())
        }
    }

    /// Check that tag is UNIVERSAL with given value
    pub fn check_universal_tag(&self, tag_value: u32) -> Result<()> {
        self.check_tag(TagClass::Universal, tag_value)
    }

    /// Get number of sub-elements (0 if primitive)
    pub fn sub_count(&self) -> usize {
        match &self.value {
            AsnValue::Constructed(subs) => subs.len(),
            AsnValue::Primitive(_) => 0,
        }
    }

    /// Decode an ASN.1 DER object from bytes
    ///
    /// # Arguments
    /// * `buf` - The DER-encoded bytes
    /// * `exact_length` - If true, reject trailing garbage
    ///
    /// # Returns
    /// Decoded AsnElt or error
    pub fn decode(buf: &[u8], exact_length: bool) -> Result<Self> {
        let (element, consumed) = Self::decode_internal(buf)?;

        if exact_length && consumed != buf.len() {
            return Err(AsnError::InvalidEncoding(
                format!("trailing garbage: {} bytes decoded, {} total", consumed, buf.len())
            ));
        }

        Ok(element)
    }

    /// Internal decode that returns element and bytes consumed
    fn decode_internal(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.is_empty() {
            return Err(AsnError::truncated(1, 0));
        }

        let mut pos = 0;

        // Decode tag
        let first_byte = buf[pos];
        pos += 1;

        let constructed = (first_byte & 0x20) != 0;
        let tag_class = TagClass::from_u8(first_byte >> 6)?;
        let mut tag_value = (first_byte & 0x1F) as u32;

        // Multi-byte tag value (tag >= 31)
        if tag_value == 0x1F {
            tag_value = 0;
            loop {
                if pos >= buf.len() {
                    return Err(AsnError::truncated(pos + 1, buf.len()));
                }
                let byte = buf[pos];
                pos += 1;

                if tag_value > 0x00FF_FFFF {
                    return Err(AsnError::IntegerOverflow);
                }

                tag_value = (tag_value << 7) | ((byte & 0x7F) as u32);

                if (byte & 0x80) == 0 {
                    break;
                }
            }
        }

        // Decode length
        if pos >= buf.len() {
            return Err(AsnError::truncated(pos + 1, buf.len()));
        }

        let length_byte = buf[pos];
        pos += 1;

        let value_len = if length_byte == 0x80 {
            // Indefinite length - not strict DER, but we tolerate it
            if !constructed {
                return Err(AsnError::InvalidEncoding(
                    "indefinite length but not constructed".to_string()
                ));
            }
            return Err(AsnError::InvalidLength); // Simplified: we don't support indefinite length in this initial version
        } else if length_byte > 0x80 {
            // Long form length
            let len_len = (length_byte & 0x7F) as usize;
            if pos + len_len > buf.len() {
                return Err(AsnError::truncated(pos + len_len, buf.len()));
            }

            let mut length = 0usize;
            for _ in 0..len_len {
                if length > 0x007F_FFFF {
                    return Err(AsnError::IntegerOverflow);
                }
                length = (length << 8) | (buf[pos] as usize);
                pos += 1;
            }
            length
        } else {
            // Short form length
            length_byte as usize
        };

        // Check we have enough bytes for the value
        let value_start = pos;
        if value_start + value_len > buf.len() {
            return Err(AsnError::truncated(value_start + value_len, buf.len()));
        }

        let value = if constructed {
            // Decode sub-elements
            let mut subs = Vec::new();
            let mut sub_pos = value_start;
            let value_end = value_start + value_len;

            while sub_pos < value_end {
                let remaining = &buf[sub_pos..value_end];
                let (sub_element, sub_consumed) = Self::decode_internal(remaining)?;
                subs.push(sub_element);
                sub_pos += sub_consumed;
            }

            AsnValue::Constructed(subs)
        } else {
            // Primitive value
            AsnValue::Primitive(buf[value_start..value_start + value_len].to_vec())
        };

        let element = AsnElt {
            tag_class,
            tag_value,
            value,
        };

        Ok((element, value_start + value_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tag_class_conversion() {
        assert_eq!(TagClass::from_u8(0).unwrap(), TagClass::Universal);
        assert_eq!(TagClass::from_u8(1).unwrap(), TagClass::Application);
        assert_eq!(TagClass::from_u8(2).unwrap(), TagClass::Context);
        assert_eq!(TagClass::from_u8(3).unwrap(), TagClass::Private);
        assert!(TagClass::from_u8(4).is_err());
    }

    #[test]
    fn test_decode_simple_integer() {
        // DER encoding of INTEGER 5: 02 01 05
        let der = vec![0x02, 0x01, 0x05];
        let elt = AsnElt::decode(&der, true).unwrap();

        assert_eq!(elt.tag_class, TagClass::Universal);
        assert_eq!(elt.tag_value, tags::INTEGER as u32);
        assert!(elt.is_primitive());

        let bytes = elt.get_primitive_bytes().unwrap();
        assert_eq!(bytes, &[0x05]);
    }

    #[test]
    fn test_decode_sequence() {
        // DER encoding of SEQUENCE { INTEGER 1, INTEGER 2 }
        // 30 06 02 01 01 02 01 02
        let der = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02];
        let elt = AsnElt::decode(&der, true).unwrap();

        assert_eq!(elt.tag_class, TagClass::Universal);
        assert_eq!(elt.tag_value, tags::SEQUENCE as u32);
        assert!(elt.is_constructed());

        let subs = elt.get_subs().unwrap();
        assert_eq!(subs.len(), 2);

        assert_eq!(subs[0].tag_value, tags::INTEGER as u32);
        assert_eq!(subs[0].get_primitive_bytes().unwrap(), &[0x01]);

        assert_eq!(subs[1].tag_value, tags::INTEGER as u32);
        assert_eq!(subs[1].get_primitive_bytes().unwrap(), &[0x02]);
    }

    #[test]
    fn test_decode_context_tag() {
        // [0] INTEGER 42  ->  A0 03 02 01 2A
        let der = vec![0xA0, 0x03, 0x02, 0x01, 0x2A];
        let elt = AsnElt::decode(&der, true).unwrap();

        assert_eq!(elt.tag_class, TagClass::Context);
        assert_eq!(elt.tag_value, 0);
        assert!(elt.is_constructed());
    }

    #[test]
    fn test_decode_trailing_garbage() {
        let der = vec![0x02, 0x01, 0x05, 0xFF, 0xFF]; // INTEGER 5 + garbage

        // Should fail with exact_length = true
        assert!(AsnElt::decode(&der, true).is_err());

        // Should succeed with exact_length = false
        assert!(AsnElt::decode(&der, false).is_ok());
    }

    #[test]
    fn test_check_tag() {
        let elt = AsnElt::new_primitive(TagClass::Universal, tags::INTEGER as u32, vec![0x05]);

        assert!(elt.check_universal_tag(tags::INTEGER as u32).is_ok());
        assert!(elt.check_universal_tag(tags::OCTET_STRING as u32).is_err());
    }

    #[test]
    fn test_truncated_data() {
        // Incomplete DER: tag says 5 bytes but only 2 provided
        let der = vec![0x02, 0x05, 0x01, 0x02];
        assert!(matches!(
            AsnElt::decode(&der, true),
            Err(AsnError::TruncatedData { .. })
        ));
    }
}
