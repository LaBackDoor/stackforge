// DNS protocol constants and type definitions.
//
// Comprehensive DNS constants matching Scapy's dns.py reference implementation.
// Covers record types, classes, opcodes, response codes, DNSSEC algorithms,
// DNSSEC digest types, and EDNS0 option codes.

// ---------------------------------------------------------------------------
// DNS Record Types (QTYPE/RRTYPE)
// Reference: IANA DNS Parameters, RFC 1035, RFC 3596, RFC 6895, and others.
// ---------------------------------------------------------------------------

pub mod record_type {
    /// Host address (IPv4)
    pub const A: u16 = 1;
    /// Authoritative name server
    pub const NS: u16 = 2;
    /// Mail destination (obsolete, use MX)
    pub const MD: u16 = 3;
    /// Mail forwarder (obsolete, use MX)
    pub const MF: u16 = 4;
    /// Canonical name for an alias
    pub const CNAME: u16 = 5;
    /// Start of a zone of authority
    pub const SOA: u16 = 6;
    /// Mailbox domain name (experimental)
    pub const MB: u16 = 7;
    /// Mail group member (experimental)
    pub const MG: u16 = 8;
    /// Mail rename domain name (experimental)
    pub const MR: u16 = 9;
    /// Null resource record (experimental)
    pub const NULL: u16 = 10;
    /// Well known service description
    pub const WKS: u16 = 11;
    /// Domain name pointer
    pub const PTR: u16 = 12;
    /// Host information
    pub const HINFO: u16 = 13;
    /// Mailbox or mail list information
    pub const MINFO: u16 = 14;
    /// Mail exchange
    pub const MX: u16 = 15;
    /// Text strings
    pub const TXT: u16 = 16;
    /// Responsible person
    pub const RP: u16 = 17;
    /// AFS database location
    pub const AFSDB: u16 = 18;
    /// X.25 PSDN address
    pub const X25: u16 = 19;
    /// ISDN address
    pub const ISDN: u16 = 20;
    /// Route through
    pub const RT: u16 = 21;
    /// NSAP address
    pub const NSAP: u16 = 22;
    /// NSAP domain name pointer (deprecated)
    pub const NSAP_PTR: u16 = 23;
    /// Security signature (obsoleted by RRSIG)
    pub const SIG: u16 = 24;
    /// Security key (obsoleted by DNSKEY)
    pub const KEY: u16 = 25;
    /// X.400 mail mapping information
    pub const PX: u16 = 26;
    /// Geographical position
    pub const GPOS: u16 = 27;
    /// IPv6 address
    pub const AAAA: u16 = 28;
    /// Location information
    pub const LOC: u16 = 29;
    /// Next domain (obsoleted by NSEC)
    pub const NXT: u16 = 30;
    /// Server selection
    pub const SRV: u16 = 33;
    /// Naming authority pointer
    pub const NAPTR: u16 = 35;
    /// Key exchanger
    pub const KX: u16 = 36;
    /// Certificate record
    pub const CERT: u16 = 37;
    /// IPv6 address (experimental, deprecated)
    pub const A6: u16 = 38;
    /// Delegation name
    pub const DNAME: u16 = 39;
    /// EDNS0 option (pseudo-RR)
    pub const OPT: u16 = 41;
    /// Address prefix list
    pub const APL: u16 = 42;
    /// Delegation signer
    pub const DS: u16 = 43;
    /// SSH key fingerprint
    pub const SSHFP: u16 = 44;
    /// IPsec key
    pub const IPSECKEY: u16 = 45;
    /// DNSSEC signature
    pub const RRSIG: u16 = 46;
    /// Next secure record
    pub const NSEC: u16 = 47;
    /// DNS key record
    pub const DNSKEY: u16 = 48;
    /// DHCP identifier
    pub const DHCID: u16 = 49;
    /// Next secure record version 3
    pub const NSEC3: u16 = 50;
    /// NSEC3 parameters
    pub const NSEC3PARAM: u16 = 51;
    /// TLSA certificate association
    pub const TLSA: u16 = 52;
    /// S/MIME certificate association
    pub const SMIMEA: u16 = 53;
    /// Host identity protocol
    pub const HIP: u16 = 55;
    /// Child DS
    pub const CDS: u16 = 59;
    /// Child DNSKEY
    pub const CDNSKEY: u16 = 60;
    /// OpenPGP public key record
    pub const OPENPGPKEY: u16 = 61;
    /// Child-to-parent synchronization
    pub const CSYNC: u16 = 62;
    /// Message digest for DNS zone
    pub const ZONEMD: u16 = 63;
    /// Service binding
    pub const SVCB: u16 = 64;
    /// HTTPS service binding
    pub const HTTPS: u16 = 65;
    /// Sender policy framework (obsolete, use TXT)
    pub const SPF: u16 = 99;
    /// Node identifier
    pub const NID: u16 = 104;
    /// 32-bit locator for ILNPv4
    pub const L32: u16 = 105;
    /// 64-bit locator for ILNPv6
    pub const L64: u16 = 106;
    /// Name of an ILNP subnetwork
    pub const LP: u16 = 107;
    /// EUI-48 address
    pub const EUI48: u16 = 108;
    /// EUI-64 address
    pub const EUI64: u16 = 109;
    /// Transaction key
    pub const TKEY: u16 = 249;
    /// Transaction signature
    pub const TSIG: u16 = 250;
    /// Incremental zone transfer
    pub const IXFR: u16 = 251;
    /// Full zone transfer
    pub const AXFR: u16 = 252;
    /// Mailbox-related records (MB, MG, MR)
    pub const MAILB: u16 = 253;
    /// Mail agent records (obsolete, use MX)
    pub const MAILA: u16 = 254;
    /// All cached records (wildcard)
    pub const ANY: u16 = 255;
    /// Uniform resource identifier
    pub const URI: u16 = 256;
    /// Certification authority authorization
    pub const CAA: u16 = 257;
    /// DNSSEC trust authorities
    pub const TA: u16 = 32768;
    /// DNSSEC lookaside validation
    pub const DLV: u16 = 32769;
}

/// Backward-compatible alias for `record_type`.
pub use record_type as rr_type;

/// Returns a human-readable name for the given DNS record type value.
pub fn dns_type_name(t: u16) -> &'static str {
    match t {
        record_type::A => "A",
        record_type::NS => "NS",
        record_type::MD => "MD",
        record_type::MF => "MF",
        record_type::CNAME => "CNAME",
        record_type::SOA => "SOA",
        record_type::MB => "MB",
        record_type::MG => "MG",
        record_type::MR => "MR",
        record_type::NULL => "NULL",
        record_type::WKS => "WKS",
        record_type::PTR => "PTR",
        record_type::HINFO => "HINFO",
        record_type::MINFO => "MINFO",
        record_type::MX => "MX",
        record_type::TXT => "TXT",
        record_type::RP => "RP",
        record_type::AFSDB => "AFSDB",
        record_type::X25 => "X25",
        record_type::ISDN => "ISDN",
        record_type::RT => "RT",
        record_type::NSAP => "NSAP",
        record_type::NSAP_PTR => "NSAP-PTR",
        record_type::SIG => "SIG",
        record_type::KEY => "KEY",
        record_type::PX => "PX",
        record_type::GPOS => "GPOS",
        record_type::AAAA => "AAAA",
        record_type::LOC => "LOC",
        record_type::NXT => "NXT",
        record_type::SRV => "SRV",
        record_type::NAPTR => "NAPTR",
        record_type::KX => "KX",
        record_type::CERT => "CERT",
        record_type::A6 => "A6",
        record_type::DNAME => "DNAME",
        record_type::OPT => "OPT",
        record_type::APL => "APL",
        record_type::DS => "DS",
        record_type::SSHFP => "SSHFP",
        record_type::IPSECKEY => "IPSECKEY",
        record_type::RRSIG => "RRSIG",
        record_type::NSEC => "NSEC",
        record_type::DNSKEY => "DNSKEY",
        record_type::DHCID => "DHCID",
        record_type::NSEC3 => "NSEC3",
        record_type::NSEC3PARAM => "NSEC3PARAM",
        record_type::TLSA => "TLSA",
        record_type::SMIMEA => "SMIMEA",
        record_type::HIP => "HIP",
        record_type::CDS => "CDS",
        record_type::CDNSKEY => "CDNSKEY",
        record_type::OPENPGPKEY => "OPENPGPKEY",
        record_type::CSYNC => "CSYNC",
        record_type::ZONEMD => "ZONEMD",
        record_type::SVCB => "SVCB",
        record_type::HTTPS => "HTTPS",
        record_type::SPF => "SPF",
        record_type::NID => "NID",
        record_type::L32 => "L32",
        record_type::L64 => "L64",
        record_type::LP => "LP",
        record_type::EUI48 => "EUI48",
        record_type::EUI64 => "EUI64",
        record_type::TKEY => "TKEY",
        record_type::TSIG => "TSIG",
        record_type::IXFR => "IXFR",
        record_type::AXFR => "AXFR",
        record_type::MAILB => "MAILB",
        record_type::MAILA => "MAILA",
        record_type::ANY => "ANY",
        record_type::URI => "URI",
        record_type::CAA => "CAA",
        record_type::TA => "TA",
        record_type::DLV => "DLV",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// DNS Classes
// Reference: RFC 1035 Section 3.2.4, RFC 2136
// ---------------------------------------------------------------------------

pub mod dns_class {
    /// Internet
    pub const IN: u16 = 1;
    /// CSNET (obsolete)
    pub const CS: u16 = 2;
    /// CHAOS
    pub const CH: u16 = 3;
    /// Hesiod
    pub const HS: u16 = 4;
    /// Any class (wildcard)
    pub const ANY: u16 = 255;
}

/// Returns a human-readable name for the given DNS class value.
pub fn dns_class_name(c: u16) -> &'static str {
    match c {
        dns_class::IN => "IN",
        dns_class::CS => "CS",
        dns_class::CH => "CH",
        dns_class::HS => "HS",
        dns_class::ANY => "ANY",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// DNS Opcodes
// Reference: RFC 1035 Section 4.1.1, RFC 1996, RFC 2136
// ---------------------------------------------------------------------------

pub mod dns_opcode {
    /// Standard query
    pub const QUERY: u8 = 0;
    /// Inverse query (obsolete)
    pub const IQUERY: u8 = 1;
    /// Server status request
    pub const STATUS: u8 = 2;
    /// Zone change notification
    pub const NOTIFY: u8 = 4;
    /// Dynamic update
    pub const UPDATE: u8 = 5;
}

/// Backward-compatible alias for `dns_opcode`.
pub use dns_opcode as opcode;

/// Returns a human-readable name for the given DNS opcode value.
pub fn dns_opcode_name(o: u8) -> &'static str {
    match o {
        dns_opcode::QUERY => "QUERY",
        dns_opcode::IQUERY => "IQUERY",
        dns_opcode::STATUS => "STATUS",
        dns_opcode::NOTIFY => "NOTIFY",
        dns_opcode::UPDATE => "UPDATE",
        _ => "UNKNOWN",
    }
}

/// Backward-compatible alias for `dns_opcode_name`.
pub fn opcode_name(o: u8) -> &'static str {
    dns_opcode_name(o)
}

// ---------------------------------------------------------------------------
// DNS Response Codes (RCODE)
// Reference: RFC 1035 Section 4.1.1, RFC 2136, RFC 6895
// ---------------------------------------------------------------------------

pub mod dns_rcode {
    /// No error condition
    pub const NOERROR: u8 = 0;
    /// Format error
    pub const FORMERR: u8 = 1;
    /// Server failure
    pub const SERVFAIL: u8 = 2;
    /// Non-existent domain
    pub const NXDOMAIN: u8 = 3;
    /// Not implemented
    pub const NOTIMP: u8 = 4;
    /// Query refused
    pub const REFUSED: u8 = 5;
    /// Name exists when it should not
    pub const YXDOMAIN: u8 = 6;
    /// RR set exists when it should not
    pub const YXRRSET: u8 = 7;
    /// RR set that should exist does not
    pub const NXRRSET: u8 = 8;
    /// Not authoritative / Not authorized
    pub const NOTAUTH: u8 = 9;
    /// Name not contained in zone
    pub const NOTZONE: u8 = 10;
}

/// Backward-compatible alias for `dns_rcode`.
pub use dns_rcode as rcode;

/// Returns a human-readable name for the given DNS response code value.
pub fn dns_rcode_name(r: u8) -> &'static str {
    match r {
        dns_rcode::NOERROR => "NOERROR",
        dns_rcode::FORMERR => "FORMERR",
        dns_rcode::SERVFAIL => "SERVFAIL",
        dns_rcode::NXDOMAIN => "NXDOMAIN",
        dns_rcode::NOTIMP => "NOTIMP",
        dns_rcode::REFUSED => "REFUSED",
        dns_rcode::YXDOMAIN => "YXDOMAIN",
        dns_rcode::YXRRSET => "YXRRSET",
        dns_rcode::NXRRSET => "NXRRSET",
        dns_rcode::NOTAUTH => "NOTAUTH",
        dns_rcode::NOTZONE => "NOTZONE",
        _ => "UNKNOWN",
    }
}

/// Backward-compatible alias for `dns_rcode_name`.
pub fn rcode_name(r: u8) -> &'static str {
    dns_rcode_name(r)
}

// ---------------------------------------------------------------------------
// DNSSEC Algorithm Types
// Reference: RFC 4034, RFC 5155, RFC 5702, RFC 6605, RFC 8080, RFC 8624
// ---------------------------------------------------------------------------

pub mod dnssec_algorithm {
    /// Reserved / Delete DS
    pub const DELETE: u8 = 0;
    /// RSA/MD5 (deprecated)
    pub const RSAMD5: u8 = 1;
    /// Diffie-Hellman
    pub const DH: u8 = 2;
    /// DSA/SHA-1
    pub const DSA: u8 = 3;
    /// Elliptic curve (reserved)
    pub const ECC: u8 = 4;
    /// RSA/SHA-1
    pub const RSASHA1: u8 = 5;
    /// DSA-NSEC3-SHA1
    pub const DSA_NSEC3_SHA1: u8 = 6;
    /// RSASHA1-NSEC3-SHA1
    pub const RSASHA1_NSEC3_SHA1: u8 = 7;
    /// RSA/SHA-256
    pub const RSASHA256: u8 = 8;
    /// RSA/SHA-512
    pub const RSASHA512: u8 = 10;
    /// GOST R 34.10-2001
    pub const ECC_GOST: u8 = 12;
    /// ECDSA Curve P-256 with SHA-256
    pub const ECDSAP256SHA256: u8 = 13;
    /// ECDSA Curve P-384 with SHA-384
    pub const ECDSAP384SHA384: u8 = 14;
    /// Ed25519
    pub const ED25519: u8 = 15;
    /// Ed448
    pub const ED448: u8 = 16;
    /// Indirect keys
    pub const INDIRECT: u8 = 252;
    /// Private algorithm (domain name)
    pub const PRIVATEDNS: u8 = 253;
    /// Private algorithm (OID)
    pub const PRIVATEOID: u8 = 254;
}

/// Backward-compatible alias for `dnssec_algorithm`.
pub use dnssec_algorithm as algorithm;

/// Returns a human-readable name for the given DNSSEC algorithm type value.
pub fn dnssec_algorithm_name(a: u8) -> &'static str {
    match a {
        dnssec_algorithm::DELETE => "DELETE",
        dnssec_algorithm::RSAMD5 => "RSAMD5",
        dnssec_algorithm::DH => "DH",
        dnssec_algorithm::DSA => "DSA",
        dnssec_algorithm::ECC => "ECC",
        dnssec_algorithm::RSASHA1 => "RSASHA1",
        dnssec_algorithm::DSA_NSEC3_SHA1 => "DSA-NSEC3-SHA1",
        dnssec_algorithm::RSASHA1_NSEC3_SHA1 => "RSASHA1-NSEC3-SHA1",
        dnssec_algorithm::RSASHA256 => "RSASHA256",
        dnssec_algorithm::RSASHA512 => "RSASHA512",
        dnssec_algorithm::ECC_GOST => "ECC-GOST",
        dnssec_algorithm::ECDSAP256SHA256 => "ECDSAP256SHA256",
        dnssec_algorithm::ECDSAP384SHA384 => "ECDSAP384SHA384",
        dnssec_algorithm::ED25519 => "ED25519",
        dnssec_algorithm::ED448 => "ED448",
        dnssec_algorithm::INDIRECT => "INDIRECT",
        dnssec_algorithm::PRIVATEDNS => "PRIVATEDNS",
        dnssec_algorithm::PRIVATEOID => "PRIVATEOID",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// DNSSEC Digest Types
// Reference: RFC 4034, RFC 4509, RFC 6605, RFC 5933
// ---------------------------------------------------------------------------

pub mod dnssec_digest {
    /// SHA-1
    pub const SHA1: u8 = 1;
    /// SHA-256
    pub const SHA256: u8 = 2;
    /// GOST R 34.11-94
    pub const GOST: u8 = 3;
    /// SHA-384
    pub const SHA384: u8 = 4;
}

/// Backward-compatible alias for `dnssec_digest`.
pub use dnssec_digest as digest_type;

/// Returns a human-readable name for the given DNSSEC digest type value.
pub fn dnssec_digest_name(d: u8) -> &'static str {
    match d {
        dnssec_digest::SHA1 => "SHA-1",
        dnssec_digest::SHA256 => "SHA-256",
        dnssec_digest::GOST => "GOST",
        dnssec_digest::SHA384 => "SHA-384",
        _ => "UNKNOWN",
    }
}

// ---------------------------------------------------------------------------
// EDNS0 Option Codes
// Reference: RFC 6891, RFC 7871, RFC 7873, RFC 8914
// ---------------------------------------------------------------------------

pub mod edns0_option {
    /// Long-lived queries
    pub const LLQ: u16 = 1;
    /// Update lease
    pub const UL: u16 = 2;
    /// Name server identifier
    pub const NSID: u16 = 3;
    /// OWNER (draft-cheshire-edns0-owner-option)
    pub const OWNER: u16 = 4;
    /// DNSSEC algorithm understood
    pub const DAU: u16 = 5;
    /// DS hash understood
    pub const DHU: u16 = 6;
    /// NSEC3 hash understood
    pub const N3U: u16 = 7;
    /// Client subnet
    pub const CLIENT_SUBNET: u16 = 8;
    /// DNS cookie
    pub const COOKIE: u16 = 10;
    /// Extended DNS error
    pub const EXTENDED_DNS_ERROR: u16 = 15;
}

/// Returns a human-readable name for the given EDNS0 option code value.
pub fn edns0_option_name(code: u16) -> &'static str {
    match code {
        edns0_option::LLQ => "LLQ",
        edns0_option::UL => "UL",
        edns0_option::NSID => "NSID",
        edns0_option::OWNER => "OWNER",
        edns0_option::DAU => "DAU",
        edns0_option::DHU => "DHU",
        edns0_option::N3U => "N3U",
        edns0_option::CLIENT_SUBNET => "CLIENT_SUBNET",
        edns0_option::COOKIE => "COOKIE",
        edns0_option::EXTENDED_DNS_ERROR => "EXTENDED_DNS_ERROR",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_type_names() {
        assert_eq!(dns_type_name(record_type::A), "A");
        assert_eq!(dns_type_name(record_type::AAAA), "AAAA");
        assert_eq!(dns_type_name(record_type::CNAME), "CNAME");
        assert_eq!(dns_type_name(record_type::MX), "MX");
        assert_eq!(dns_type_name(record_type::NS), "NS");
        assert_eq!(dns_type_name(record_type::SOA), "SOA");
        assert_eq!(dns_type_name(record_type::TXT), "TXT");
        assert_eq!(dns_type_name(record_type::SRV), "SRV");
        assert_eq!(dns_type_name(record_type::PTR), "PTR");
        assert_eq!(dns_type_name(record_type::OPT), "OPT");
        assert_eq!(dns_type_name(record_type::DS), "DS");
        assert_eq!(dns_type_name(record_type::RRSIG), "RRSIG");
        assert_eq!(dns_type_name(record_type::DNSKEY), "DNSKEY");
        assert_eq!(dns_type_name(record_type::NSEC), "NSEC");
        assert_eq!(dns_type_name(record_type::NSEC3), "NSEC3");
        assert_eq!(dns_type_name(record_type::NSEC3PARAM), "NSEC3PARAM");
        assert_eq!(dns_type_name(record_type::TLSA), "TLSA");
        assert_eq!(dns_type_name(record_type::HTTPS), "HTTPS");
        assert_eq!(dns_type_name(record_type::SVCB), "SVCB");
        assert_eq!(dns_type_name(record_type::CAA), "CAA");
        assert_eq!(dns_type_name(record_type::ANY), "ANY");
        assert_eq!(dns_type_name(record_type::AXFR), "AXFR");
        assert_eq!(dns_type_name(record_type::IXFR), "IXFR");
        assert_eq!(dns_type_name(record_type::TA), "TA");
        assert_eq!(dns_type_name(record_type::DLV), "DLV");
        assert_eq!(dns_type_name(record_type::NSAP_PTR), "NSAP-PTR");
    }

    #[test]
    fn test_dns_type_unknown() {
        assert_eq!(dns_type_name(0), "UNKNOWN");
        assert_eq!(dns_type_name(65534), "UNKNOWN");
    }

    #[test]
    fn test_dns_type_values() {
        assert_eq!(record_type::A, 1);
        assert_eq!(record_type::NS, 2);
        assert_eq!(record_type::MD, 3);
        assert_eq!(record_type::MF, 4);
        assert_eq!(record_type::CNAME, 5);
        assert_eq!(record_type::SOA, 6);
        assert_eq!(record_type::MB, 7);
        assert_eq!(record_type::MG, 8);
        assert_eq!(record_type::MR, 9);
        assert_eq!(record_type::NULL, 10);
        assert_eq!(record_type::WKS, 11);
        assert_eq!(record_type::PTR, 12);
        assert_eq!(record_type::HINFO, 13);
        assert_eq!(record_type::MINFO, 14);
        assert_eq!(record_type::MX, 15);
        assert_eq!(record_type::TXT, 16);
        assert_eq!(record_type::RP, 17);
        assert_eq!(record_type::AFSDB, 18);
        assert_eq!(record_type::X25, 19);
        assert_eq!(record_type::ISDN, 20);
        assert_eq!(record_type::RT, 21);
        assert_eq!(record_type::NSAP, 22);
        assert_eq!(record_type::NSAP_PTR, 23);
        assert_eq!(record_type::SIG, 24);
        assert_eq!(record_type::KEY, 25);
        assert_eq!(record_type::PX, 26);
        assert_eq!(record_type::GPOS, 27);
        assert_eq!(record_type::AAAA, 28);
        assert_eq!(record_type::LOC, 29);
        assert_eq!(record_type::NXT, 30);
        assert_eq!(record_type::SRV, 33);
        assert_eq!(record_type::NAPTR, 35);
        assert_eq!(record_type::KX, 36);
        assert_eq!(record_type::CERT, 37);
        assert_eq!(record_type::A6, 38);
        assert_eq!(record_type::DNAME, 39);
        assert_eq!(record_type::OPT, 41);
        assert_eq!(record_type::APL, 42);
        assert_eq!(record_type::DS, 43);
        assert_eq!(record_type::SSHFP, 44);
        assert_eq!(record_type::IPSECKEY, 45);
        assert_eq!(record_type::RRSIG, 46);
        assert_eq!(record_type::NSEC, 47);
        assert_eq!(record_type::DNSKEY, 48);
        assert_eq!(record_type::DHCID, 49);
        assert_eq!(record_type::NSEC3, 50);
        assert_eq!(record_type::NSEC3PARAM, 51);
        assert_eq!(record_type::TLSA, 52);
        assert_eq!(record_type::SMIMEA, 53);
        assert_eq!(record_type::HIP, 55);
        assert_eq!(record_type::CDS, 59);
        assert_eq!(record_type::CDNSKEY, 60);
        assert_eq!(record_type::OPENPGPKEY, 61);
        assert_eq!(record_type::CSYNC, 62);
        assert_eq!(record_type::ZONEMD, 63);
        assert_eq!(record_type::SVCB, 64);
        assert_eq!(record_type::HTTPS, 65);
        assert_eq!(record_type::SPF, 99);
        assert_eq!(record_type::NID, 104);
        assert_eq!(record_type::L32, 105);
        assert_eq!(record_type::L64, 106);
        assert_eq!(record_type::LP, 107);
        assert_eq!(record_type::EUI48, 108);
        assert_eq!(record_type::EUI64, 109);
        assert_eq!(record_type::TKEY, 249);
        assert_eq!(record_type::TSIG, 250);
        assert_eq!(record_type::IXFR, 251);
        assert_eq!(record_type::AXFR, 252);
        assert_eq!(record_type::MAILB, 253);
        assert_eq!(record_type::MAILA, 254);
        assert_eq!(record_type::ANY, 255);
        assert_eq!(record_type::URI, 256);
        assert_eq!(record_type::CAA, 257);
        assert_eq!(record_type::TA, 32768);
        assert_eq!(record_type::DLV, 32769);
    }

    #[test]
    fn test_rr_type_alias() {
        // Verify backward-compatible alias works
        assert_eq!(rr_type::A, record_type::A);
        assert_eq!(rr_type::AAAA, record_type::AAAA);
        assert_eq!(rr_type::CNAME, record_type::CNAME);
    }

    #[test]
    fn test_dns_class_names() {
        assert_eq!(dns_class_name(dns_class::IN), "IN");
        assert_eq!(dns_class_name(dns_class::CS), "CS");
        assert_eq!(dns_class_name(dns_class::CH), "CH");
        assert_eq!(dns_class_name(dns_class::HS), "HS");
        assert_eq!(dns_class_name(dns_class::ANY), "ANY");
    }

    #[test]
    fn test_dns_class_unknown() {
        assert_eq!(dns_class_name(0), "UNKNOWN");
        assert_eq!(dns_class_name(100), "UNKNOWN");
    }

    #[test]
    fn test_dns_class_values() {
        assert_eq!(dns_class::IN, 1);
        assert_eq!(dns_class::CS, 2);
        assert_eq!(dns_class::CH, 3);
        assert_eq!(dns_class::HS, 4);
        assert_eq!(dns_class::ANY, 255);
    }

    #[test]
    fn test_dns_opcode_names() {
        assert_eq!(dns_opcode_name(dns_opcode::QUERY), "QUERY");
        assert_eq!(dns_opcode_name(dns_opcode::IQUERY), "IQUERY");
        assert_eq!(dns_opcode_name(dns_opcode::STATUS), "STATUS");
        assert_eq!(dns_opcode_name(dns_opcode::NOTIFY), "NOTIFY");
        assert_eq!(dns_opcode_name(dns_opcode::UPDATE), "UPDATE");
    }

    #[test]
    fn test_dns_opcode_unknown() {
        assert_eq!(dns_opcode_name(3), "UNKNOWN");
        assert_eq!(dns_opcode_name(15), "UNKNOWN");
    }

    #[test]
    fn test_dns_opcode_values() {
        assert_eq!(dns_opcode::QUERY, 0);
        assert_eq!(dns_opcode::IQUERY, 1);
        assert_eq!(dns_opcode::STATUS, 2);
        assert_eq!(dns_opcode::NOTIFY, 4);
        assert_eq!(dns_opcode::UPDATE, 5);
    }

    #[test]
    fn test_opcode_alias() {
        assert_eq!(opcode::QUERY, dns_opcode::QUERY);
        assert_eq!(opcode_name(0), dns_opcode_name(0));
    }

    #[test]
    fn test_dns_rcode_names() {
        assert_eq!(dns_rcode_name(dns_rcode::NOERROR), "NOERROR");
        assert_eq!(dns_rcode_name(dns_rcode::FORMERR), "FORMERR");
        assert_eq!(dns_rcode_name(dns_rcode::SERVFAIL), "SERVFAIL");
        assert_eq!(dns_rcode_name(dns_rcode::NXDOMAIN), "NXDOMAIN");
        assert_eq!(dns_rcode_name(dns_rcode::NOTIMP), "NOTIMP");
        assert_eq!(dns_rcode_name(dns_rcode::REFUSED), "REFUSED");
        assert_eq!(dns_rcode_name(dns_rcode::YXDOMAIN), "YXDOMAIN");
        assert_eq!(dns_rcode_name(dns_rcode::YXRRSET), "YXRRSET");
        assert_eq!(dns_rcode_name(dns_rcode::NXRRSET), "NXRRSET");
        assert_eq!(dns_rcode_name(dns_rcode::NOTAUTH), "NOTAUTH");
        assert_eq!(dns_rcode_name(dns_rcode::NOTZONE), "NOTZONE");
    }

    #[test]
    fn test_dns_rcode_unknown() {
        assert_eq!(dns_rcode_name(11), "UNKNOWN");
        assert_eq!(dns_rcode_name(255), "UNKNOWN");
    }

    #[test]
    fn test_dns_rcode_values() {
        assert_eq!(dns_rcode::NOERROR, 0);
        assert_eq!(dns_rcode::FORMERR, 1);
        assert_eq!(dns_rcode::SERVFAIL, 2);
        assert_eq!(dns_rcode::NXDOMAIN, 3);
        assert_eq!(dns_rcode::NOTIMP, 4);
        assert_eq!(dns_rcode::REFUSED, 5);
        assert_eq!(dns_rcode::YXDOMAIN, 6);
        assert_eq!(dns_rcode::YXRRSET, 7);
        assert_eq!(dns_rcode::NXRRSET, 8);
        assert_eq!(dns_rcode::NOTAUTH, 9);
        assert_eq!(dns_rcode::NOTZONE, 10);
    }

    #[test]
    fn test_rcode_alias() {
        assert_eq!(rcode::NOERROR, dns_rcode::NOERROR);
        assert_eq!(rcode_name(0), dns_rcode_name(0));
    }

    #[test]
    fn test_dnssec_algorithm_names() {
        assert_eq!(dnssec_algorithm_name(dnssec_algorithm::DELETE), "DELETE");
        assert_eq!(dnssec_algorithm_name(dnssec_algorithm::RSAMD5), "RSAMD5");
        assert_eq!(dnssec_algorithm_name(dnssec_algorithm::DH), "DH");
        assert_eq!(dnssec_algorithm_name(dnssec_algorithm::DSA), "DSA");
        assert_eq!(dnssec_algorithm_name(dnssec_algorithm::ECC), "ECC");
        assert_eq!(dnssec_algorithm_name(dnssec_algorithm::RSASHA1), "RSASHA1");
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::DSA_NSEC3_SHA1),
            "DSA-NSEC3-SHA1"
        );
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::RSASHA1_NSEC3_SHA1),
            "RSASHA1-NSEC3-SHA1"
        );
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::RSASHA256),
            "RSASHA256"
        );
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::RSASHA512),
            "RSASHA512"
        );
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::ECC_GOST),
            "ECC-GOST"
        );
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::ECDSAP256SHA256),
            "ECDSAP256SHA256"
        );
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::ECDSAP384SHA384),
            "ECDSAP384SHA384"
        );
        assert_eq!(dnssec_algorithm_name(dnssec_algorithm::ED25519), "ED25519");
        assert_eq!(dnssec_algorithm_name(dnssec_algorithm::ED448), "ED448");
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::INDIRECT),
            "INDIRECT"
        );
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::PRIVATEDNS),
            "PRIVATEDNS"
        );
        assert_eq!(
            dnssec_algorithm_name(dnssec_algorithm::PRIVATEOID),
            "PRIVATEOID"
        );
    }

    #[test]
    fn test_dnssec_algorithm_unknown() {
        assert_eq!(dnssec_algorithm_name(9), "UNKNOWN");
        assert_eq!(dnssec_algorithm_name(11), "UNKNOWN");
        assert_eq!(dnssec_algorithm_name(200), "UNKNOWN");
    }

    #[test]
    fn test_dnssec_algorithm_values() {
        assert_eq!(dnssec_algorithm::DELETE, 0);
        assert_eq!(dnssec_algorithm::RSAMD5, 1);
        assert_eq!(dnssec_algorithm::DH, 2);
        assert_eq!(dnssec_algorithm::DSA, 3);
        assert_eq!(dnssec_algorithm::ECC, 4);
        assert_eq!(dnssec_algorithm::RSASHA1, 5);
        assert_eq!(dnssec_algorithm::DSA_NSEC3_SHA1, 6);
        assert_eq!(dnssec_algorithm::RSASHA1_NSEC3_SHA1, 7);
        assert_eq!(dnssec_algorithm::RSASHA256, 8);
        assert_eq!(dnssec_algorithm::RSASHA512, 10);
        assert_eq!(dnssec_algorithm::ECC_GOST, 12);
        assert_eq!(dnssec_algorithm::ECDSAP256SHA256, 13);
        assert_eq!(dnssec_algorithm::ECDSAP384SHA384, 14);
        assert_eq!(dnssec_algorithm::ED25519, 15);
        assert_eq!(dnssec_algorithm::ED448, 16);
        assert_eq!(dnssec_algorithm::INDIRECT, 252);
        assert_eq!(dnssec_algorithm::PRIVATEDNS, 253);
        assert_eq!(dnssec_algorithm::PRIVATEOID, 254);
    }

    #[test]
    fn test_algorithm_alias() {
        assert_eq!(algorithm::RSASHA256, dnssec_algorithm::RSASHA256);
    }

    #[test]
    fn test_dnssec_digest_names() {
        assert_eq!(dnssec_digest_name(dnssec_digest::SHA1), "SHA-1");
        assert_eq!(dnssec_digest_name(dnssec_digest::SHA256), "SHA-256");
        assert_eq!(dnssec_digest_name(dnssec_digest::GOST), "GOST");
        assert_eq!(dnssec_digest_name(dnssec_digest::SHA384), "SHA-384");
    }

    #[test]
    fn test_dnssec_digest_unknown() {
        assert_eq!(dnssec_digest_name(0), "UNKNOWN");
        assert_eq!(dnssec_digest_name(5), "UNKNOWN");
    }

    #[test]
    fn test_dnssec_digest_values() {
        assert_eq!(dnssec_digest::SHA1, 1);
        assert_eq!(dnssec_digest::SHA256, 2);
        assert_eq!(dnssec_digest::GOST, 3);
        assert_eq!(dnssec_digest::SHA384, 4);
    }

    #[test]
    fn test_digest_type_alias() {
        assert_eq!(digest_type::SHA256, dnssec_digest::SHA256);
    }

    #[test]
    fn test_edns0_option_names() {
        assert_eq!(edns0_option_name(edns0_option::LLQ), "LLQ");
        assert_eq!(edns0_option_name(edns0_option::UL), "UL");
        assert_eq!(edns0_option_name(edns0_option::NSID), "NSID");
        assert_eq!(edns0_option_name(edns0_option::OWNER), "OWNER");
        assert_eq!(edns0_option_name(edns0_option::DAU), "DAU");
        assert_eq!(edns0_option_name(edns0_option::DHU), "DHU");
        assert_eq!(edns0_option_name(edns0_option::N3U), "N3U");
        assert_eq!(
            edns0_option_name(edns0_option::CLIENT_SUBNET),
            "CLIENT_SUBNET"
        );
        assert_eq!(edns0_option_name(edns0_option::COOKIE), "COOKIE");
        assert_eq!(
            edns0_option_name(edns0_option::EXTENDED_DNS_ERROR),
            "EXTENDED_DNS_ERROR"
        );
    }

    #[test]
    fn test_edns0_option_unknown() {
        assert_eq!(edns0_option_name(0), "UNKNOWN");
        assert_eq!(edns0_option_name(9), "UNKNOWN");
        assert_eq!(edns0_option_name(65535), "UNKNOWN");
    }

    #[test]
    fn test_edns0_option_values() {
        assert_eq!(edns0_option::LLQ, 1);
        assert_eq!(edns0_option::UL, 2);
        assert_eq!(edns0_option::NSID, 3);
        assert_eq!(edns0_option::OWNER, 4);
        assert_eq!(edns0_option::DAU, 5);
        assert_eq!(edns0_option::DHU, 6);
        assert_eq!(edns0_option::N3U, 7);
        assert_eq!(edns0_option::CLIENT_SUBNET, 8);
        assert_eq!(edns0_option::COOKIE, 10);
        assert_eq!(edns0_option::EXTENDED_DNS_ERROR, 15);
    }
}
