//! DNS protocol layer implementation (RFC 1035).
//!
//! Provides full DNS parsing, building, and field access with:
//! - Header flag fields (QR, opcode, AA, TC, RD, RA, Z, AD, CD, RCODE)
//! - Question section with name compression
//! - Resource record sections (answer, authority, additional)
//! - All major RR types (A, AAAA, NS, CNAME, SOA, MX, TXT, SRV, etc.)
//! - DNSSEC types (RRSIG, NSEC, NSEC3, DNSKEY, DS)
//! - EDNS0 OPT records
//! - SVCB/HTTPS service binding records
//! - DNS name compression and decompression

pub mod bitmap;
pub mod builder;
pub mod edns;
pub mod header;
pub mod query;
pub mod rdata;
pub mod rr;
pub mod svcb;
pub mod types;

pub use builder::DnsBuilder;
pub use query::DnsQuestion;
pub use rdata::DnsRData;
pub use rr::DnsResourceRecord;

use crate::layer::field::{FieldError, FieldValue};
use crate::layer::{Layer, LayerIndex, LayerKind};

/// DNS header length in bytes.
pub const DNS_HEADER_LEN: usize = header::DNS_HEADER_LEN;

/// DNS layer — a zero-copy view into the packet buffer.
///
/// Provides lazy field access for all DNS header fields and
/// on-demand parsing of question/RR sections.
#[derive(Debug, Clone)]
pub struct DnsLayer {
    pub index: LayerIndex,
}

impl DnsLayer {
    /// Create a new `DnsLayer` from start/end offsets.
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            index: LayerIndex::new(LayerKind::Dns, start, end),
        }
    }

    // ========================================================================
    // Header field accessors
    // ========================================================================

    /// Transaction ID.
    pub fn id(&self, buf: &[u8]) -> Result<u16, FieldError> {
        header::read_id(buf, self.index.start)
    }

    /// QR flag: false=query, true=response.
    pub fn qr(&self, buf: &[u8]) -> Result<bool, FieldError> {
        header::read_qr(buf, self.index.start)
    }

    /// Operation code (4 bits).
    pub fn opcode(&self, buf: &[u8]) -> Result<u8, FieldError> {
        header::read_opcode(buf, self.index.start)
    }

    /// Authoritative Answer flag.
    pub fn aa(&self, buf: &[u8]) -> Result<bool, FieldError> {
        header::read_aa(buf, self.index.start)
    }

    /// Truncation flag.
    pub fn tc(&self, buf: &[u8]) -> Result<bool, FieldError> {
        header::read_tc(buf, self.index.start)
    }

    /// Recursion Desired flag.
    pub fn rd(&self, buf: &[u8]) -> Result<bool, FieldError> {
        header::read_rd(buf, self.index.start)
    }

    /// Recursion Available flag.
    pub fn ra(&self, buf: &[u8]) -> Result<bool, FieldError> {
        header::read_ra(buf, self.index.start)
    }

    /// Reserved flag (Z).
    pub fn z(&self, buf: &[u8]) -> Result<bool, FieldError> {
        header::read_z(buf, self.index.start)
    }

    /// Authenticated Data flag (DNSSEC).
    pub fn ad(&self, buf: &[u8]) -> Result<bool, FieldError> {
        header::read_ad(buf, self.index.start)
    }

    /// Checking Disabled flag (DNSSEC).
    pub fn cd(&self, buf: &[u8]) -> Result<bool, FieldError> {
        header::read_cd(buf, self.index.start)
    }

    /// Response code (4 bits).
    pub fn rcode(&self, buf: &[u8]) -> Result<u8, FieldError> {
        header::read_rcode(buf, self.index.start)
    }

    /// Question count.
    pub fn qdcount(&self, buf: &[u8]) -> Result<u16, FieldError> {
        header::read_qdcount(buf, self.index.start)
    }

    /// Answer count.
    pub fn ancount(&self, buf: &[u8]) -> Result<u16, FieldError> {
        header::read_ancount(buf, self.index.start)
    }

    /// Authority count.
    pub fn nscount(&self, buf: &[u8]) -> Result<u16, FieldError> {
        header::read_nscount(buf, self.index.start)
    }

    /// Additional count.
    pub fn arcount(&self, buf: &[u8]) -> Result<u16, FieldError> {
        header::read_arcount(buf, self.index.start)
    }

    // ========================================================================
    // Section parsing
    // ========================================================================

    /// Parse all questions from the packet.
    pub fn questions(&self, buf: &[u8]) -> Result<Vec<DnsQuestion>, FieldError> {
        let qdcount = self.qdcount(buf)? as usize;
        let mut questions = Vec::with_capacity(qdcount);
        let dns_data = &buf[self.index.start..self.index.end];
        let mut offset = DNS_HEADER_LEN;

        for _ in 0..qdcount {
            let (q, consumed) = DnsQuestion::parse(dns_data, offset)?;
            questions.push(q);
            offset += consumed;
        }

        Ok(questions)
    }

    /// Parse all answer RRs from the packet.
    pub fn answers_rr(&self, buf: &[u8]) -> Result<Vec<DnsResourceRecord>, FieldError> {
        let qdcount = self.qdcount(buf)? as usize;
        let ancount = self.ancount(buf)? as usize;
        let dns_data = &buf[self.index.start..self.index.end];

        // Skip past header and questions
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..qdcount {
            let (_, consumed) = DnsQuestion::parse(dns_data, offset)?;
            offset += consumed;
        }

        // Parse answer records
        let mut records = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            let (rr, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            records.push(rr);
            offset += consumed;
        }

        Ok(records)
    }

    /// Parse all authority RRs from the packet.
    pub fn authorities(&self, buf: &[u8]) -> Result<Vec<DnsResourceRecord>, FieldError> {
        let qdcount = self.qdcount(buf)? as usize;
        let ancount = self.ancount(buf)? as usize;
        let nscount = self.nscount(buf)? as usize;
        let dns_data = &buf[self.index.start..self.index.end];

        // Skip past header, questions, and answers
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..qdcount {
            let (_, consumed) = DnsQuestion::parse(dns_data, offset)?;
            offset += consumed;
        }
        for _ in 0..ancount {
            let (_, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            offset += consumed;
        }

        // Parse authority records
        let mut records = Vec::with_capacity(nscount);
        for _ in 0..nscount {
            let (rr, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            records.push(rr);
            offset += consumed;
        }

        Ok(records)
    }

    /// Parse all additional RRs from the packet.
    pub fn additionals(&self, buf: &[u8]) -> Result<Vec<DnsResourceRecord>, FieldError> {
        let qdcount = self.qdcount(buf)? as usize;
        let ancount = self.ancount(buf)? as usize;
        let nscount = self.nscount(buf)? as usize;
        let arcount = self.arcount(buf)? as usize;
        let dns_data = &buf[self.index.start..self.index.end];

        // Skip past header, questions, answers, and authority
        let mut offset = DNS_HEADER_LEN;
        for _ in 0..qdcount {
            let (_, consumed) = DnsQuestion::parse(dns_data, offset)?;
            offset += consumed;
        }
        for _ in 0..ancount {
            let (_, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            offset += consumed;
        }
        for _ in 0..nscount {
            let (_, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            offset += consumed;
        }

        // Parse additional records
        let mut records = Vec::with_capacity(arcount);
        for _ in 0..arcount {
            let (rr, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            records.push(rr);
            offset += consumed;
        }

        Ok(records)
    }

    /// Parse all sections at once.
    pub fn parse_all(
        &self,
        buf: &[u8],
    ) -> Result<
        (
            Vec<DnsQuestion>,
            Vec<DnsResourceRecord>,
            Vec<DnsResourceRecord>,
            Vec<DnsResourceRecord>,
        ),
        FieldError,
    > {
        let qdcount = self.qdcount(buf)? as usize;
        let ancount = self.ancount(buf)? as usize;
        let nscount = self.nscount(buf)? as usize;
        let arcount = self.arcount(buf)? as usize;
        let dns_data = &buf[self.index.start..self.index.end];
        let mut offset = DNS_HEADER_LEN;

        let mut questions = Vec::with_capacity(qdcount);
        for _ in 0..qdcount {
            let (q, consumed) = DnsQuestion::parse(dns_data, offset)?;
            questions.push(q);
            offset += consumed;
        }

        let mut answers = Vec::with_capacity(ancount);
        for _ in 0..ancount {
            let (rr, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            answers.push(rr);
            offset += consumed;
        }

        let mut authorities = Vec::with_capacity(nscount);
        for _ in 0..nscount {
            let (rr, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            authorities.push(rr);
            offset += consumed;
        }

        let mut additionals = Vec::with_capacity(arcount);
        for _ in 0..arcount {
            let (rr, consumed) = DnsResourceRecord::parse(dns_data, offset)?;
            additionals.push(rr);
            offset += consumed;
        }

        Ok((questions, answers, authorities, additionals))
    }

    // ========================================================================
    // Field access (dynamic)
    // ========================================================================

    /// Get a field value by name.
    pub fn get_field(&self, buf: &[u8], name: &str) -> Option<Result<FieldValue, FieldError>> {
        match name {
            "id" => Some(self.id(buf).map(FieldValue::U16)),
            "qr" => Some(self.qr(buf).map(FieldValue::Bool)),
            "opcode" => Some(self.opcode(buf).map(FieldValue::U8)),
            "aa" => Some(self.aa(buf).map(FieldValue::Bool)),
            "tc" => Some(self.tc(buf).map(FieldValue::Bool)),
            "rd" => Some(self.rd(buf).map(FieldValue::Bool)),
            "ra" => Some(self.ra(buf).map(FieldValue::Bool)),
            "z" => Some(self.z(buf).map(FieldValue::Bool)),
            "ad" => Some(self.ad(buf).map(FieldValue::Bool)),
            "cd" => Some(self.cd(buf).map(FieldValue::Bool)),
            "rcode" => Some(self.rcode(buf).map(FieldValue::U8)),
            "qdcount" => Some(self.qdcount(buf).map(FieldValue::U16)),
            "ancount" => Some(self.ancount(buf).map(FieldValue::U16)),
            "nscount" => Some(self.nscount(buf).map(FieldValue::U16)),
            "arcount" => Some(self.arcount(buf).map(FieldValue::U16)),
            _ => None,
        }
    }

    /// Set a field value by name.
    pub fn set_field(
        &self,
        buf: &mut [u8],
        name: &str,
        value: FieldValue,
    ) -> Option<Result<(), FieldError>> {
        match name {
            "id" => Some(match value.as_u16() {
                Some(v) => header::write_id(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected u16 for id".into())),
            }),
            "qr" => Some(match value.as_bool() {
                Some(v) => header::write_qr(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected bool for qr".into())),
            }),
            "opcode" => Some(match value.as_u8() {
                Some(v) => header::write_opcode(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected u8 for opcode".into())),
            }),
            "aa" => Some(match value.as_bool() {
                Some(v) => header::write_aa(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected bool for aa".into())),
            }),
            "tc" => Some(match value.as_bool() {
                Some(v) => header::write_tc(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected bool for tc".into())),
            }),
            "rd" => Some(match value.as_bool() {
                Some(v) => header::write_rd(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected bool for rd".into())),
            }),
            "ra" => Some(match value.as_bool() {
                Some(v) => header::write_ra(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected bool for ra".into())),
            }),
            "z" => Some(match value.as_bool() {
                Some(v) => header::write_z(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected bool for z".into())),
            }),
            "ad" => Some(match value.as_bool() {
                Some(v) => header::write_ad(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected bool for ad".into())),
            }),
            "cd" => Some(match value.as_bool() {
                Some(v) => header::write_cd(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected bool for cd".into())),
            }),
            "rcode" => Some(match value.as_u8() {
                Some(v) => header::write_rcode(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected u8 for rcode".into())),
            }),
            "qdcount" => Some(match value.as_u16() {
                Some(v) => header::write_qdcount(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected u16 for qdcount".into())),
            }),
            "ancount" => Some(match value.as_u16() {
                Some(v) => header::write_ancount(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected u16 for ancount".into())),
            }),
            "nscount" => Some(match value.as_u16() {
                Some(v) => header::write_nscount(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected u16 for nscount".into())),
            }),
            "arcount" => Some(match value.as_u16() {
                Some(v) => header::write_arcount(buf, self.index.start, v),
                None => Err(FieldError::InvalidValue("expected u16 for arcount".into())),
            }),
            _ => None,
        }
    }

    /// Get the list of field names.
    #[must_use]
    pub fn field_names() -> &'static [&'static str] {
        DNS_FIELDS
    }
}

/// DNS field names for dynamic access.
pub const DNS_FIELDS: &[&str] = &[
    "id", "qr", "opcode", "aa", "tc", "rd", "ra", "z", "ad", "cd", "rcode", "qdcount", "ancount",
    "nscount", "arcount",
];

impl Layer for DnsLayer {
    fn kind(&self) -> LayerKind {
        LayerKind::Dns
    }

    fn summary(&self, buf: &[u8]) -> String {
        let qr = self.qr(buf).unwrap_or(false);
        let opcode = self.opcode(buf).unwrap_or(0);
        let rcode = self.rcode(buf).unwrap_or(0);
        let qdcount = self.qdcount(buf).unwrap_or(0);
        let ancount = self.ancount(buf).unwrap_or(0);

        if qr {
            format!(
                "DNS {} {} qd={} an={}",
                types::opcode_name(opcode),
                types::rcode_name(rcode),
                qdcount,
                ancount,
            )
        } else {
            let qname_str = self
                .questions(buf)
                .ok()
                .and_then(|qs| qs.first().map(query::DnsQuestion::summary));
            match qname_str {
                Some(q) => format!("DNS {} {}", types::opcode_name(opcode), q),
                None => format!("DNS {} qd={}", types::opcode_name(opcode), qdcount),
            }
        }
    }

    fn header_len(&self, buf: &[u8]) -> usize {
        self.index
            .len()
            .min(buf.len().saturating_sub(self.index.start))
    }

    fn hashret(&self, buf: &[u8]) -> Vec<u8> {
        self.id(buf)
            .map(|id| id.to_be_bytes().to_vec())
            .unwrap_or_default()
    }

    fn field_names(&self) -> &'static [&'static str] {
        DNS_FIELDS
    }
}
