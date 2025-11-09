//! Kerberos protocol data structures
//! Implements RFC 4120 message types

// Re-export primitives for convenience
pub use super::primitives::{
    PrincipalType, PrincipalName, EncryptionKey, EncryptedData,
    Realm, KerberosTime, TicketFlags, Ticket,
};
