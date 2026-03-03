//! DNS packet builder with fluent API.
//!
//! Provides a builder pattern for constructing DNS packets,
//! similar to Scapy's `DNS()` constructor.

use std::collections::HashMap;

use super::header;
use super::query::DnsQuestion;
use super::rr::DnsResourceRecord;
use super::types;

/// Builder for constructing DNS packets.
#[derive(Debug, Clone)]
pub struct DnsBuilder {
    /// Transaction ID.
    pub id: u16,
    /// Query/Response flag.
    pub qr: bool,
    /// Operation code.
    pub opcode: u8,
    /// Authoritative Answer flag.
    pub aa: bool,
    /// Truncation flag.
    pub tc: bool,
    /// Recursion Desired flag.
    pub rd: bool,
    /// Recursion Available flag.
    pub ra: bool,
    /// Reserved (Z) flag.
    pub z: bool,
    /// Authenticated Data flag (DNSSEC).
    pub ad: bool,
    /// Checking Disabled flag (DNSSEC).
    pub cd: bool,
    /// Response code.
    pub rcode: u8,
    /// Question section.
    pub questions: Vec<DnsQuestion>,
    /// Answer section.
    pub answers: Vec<DnsResourceRecord>,
    /// Authority section.
    pub authorities: Vec<DnsResourceRecord>,
    /// Additional section.
    pub additionals: Vec<DnsResourceRecord>,
    /// Whether to use DNS name compression when building.
    pub compress: bool,
}

impl DnsBuilder {
    /// Create a new DNS builder with default values (standard query with RD=1).
    #[must_use]
    pub fn new() -> Self {
        Self {
            id: 0,
            qr: false,
            opcode: types::opcode::QUERY,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: false,
            ad: false,
            cd: false,
            rcode: types::rcode::NOERROR,
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            compress: true,
        }
    }

    /// Create a builder for a standard query.
    #[must_use]
    pub fn query(qname: &str, qtype: u16) -> Self {
        let mut b = Self::new();
        if let Ok(q) = DnsQuestion::from_name(qname) {
            let mut q = q;
            q.qtype = qtype;
            b.questions.push(q);
        }
        b
    }

    /// Create a builder for a standard response.
    #[must_use]
    pub fn response() -> Self {
        let mut b = Self::new();
        b.qr = true;
        b.ra = true;
        b
    }

    // Fluent setters

    #[must_use]
    pub fn id(mut self, id: u16) -> Self {
        self.id = id;
        self
    }

    #[must_use]
    pub fn qr(mut self, qr: bool) -> Self {
        self.qr = qr;
        self
    }

    #[must_use]
    pub fn opcode(mut self, opcode: u8) -> Self {
        self.opcode = opcode;
        self
    }

    #[must_use]
    pub fn aa(mut self, aa: bool) -> Self {
        self.aa = aa;
        self
    }

    #[must_use]
    pub fn tc(mut self, tc: bool) -> Self {
        self.tc = tc;
        self
    }

    #[must_use]
    pub fn rd(mut self, rd: bool) -> Self {
        self.rd = rd;
        self
    }

    #[must_use]
    pub fn ra(mut self, ra: bool) -> Self {
        self.ra = ra;
        self
    }

    #[must_use]
    pub fn z(mut self, z: bool) -> Self {
        self.z = z;
        self
    }

    #[must_use]
    pub fn ad(mut self, ad: bool) -> Self {
        self.ad = ad;
        self
    }

    #[must_use]
    pub fn cd(mut self, cd: bool) -> Self {
        self.cd = cd;
        self
    }

    #[must_use]
    pub fn rcode(mut self, rcode: u8) -> Self {
        self.rcode = rcode;
        self
    }

    #[must_use]
    pub fn compress(mut self, compress: bool) -> Self {
        self.compress = compress;
        self
    }

    /// Add a question to the question section.
    #[must_use]
    pub fn question(mut self, q: DnsQuestion) -> Self {
        self.questions.push(q);
        self
    }

    /// Add a resource record to the answer section.
    #[must_use]
    pub fn answer(mut self, rr: DnsResourceRecord) -> Self {
        self.answers.push(rr);
        self
    }

    /// Add a resource record to the authority section.
    #[must_use]
    pub fn authority(mut self, rr: DnsResourceRecord) -> Self {
        self.authorities.push(rr);
        self
    }

    /// Add a resource record to the additional section.
    #[must_use]
    pub fn additional(mut self, rr: DnsResourceRecord) -> Self {
        self.additionals.push(rr);
        self
    }

    /// Build the DNS packet bytes.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        if self.compress {
            self.build_compressed()
        } else {
            self.build_uncompressed()
        }
    }

    /// Build without name compression.
    fn build_uncompressed(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);

        // Header (12 bytes)
        out.extend_from_slice(&self.id.to_be_bytes());
        let flags = header::build_flags(
            self.qr,
            self.opcode,
            self.aa,
            self.tc,
            self.rd,
            self.ra,
            self.z,
            self.ad,
            self.cd,
            self.rcode,
        );
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        // Questions
        for q in &self.questions {
            out.extend_from_slice(&q.build());
        }

        // Answers
        for rr in &self.answers {
            out.extend_from_slice(&rr.build());
        }

        // Authorities
        for rr in &self.authorities {
            out.extend_from_slice(&rr.build());
        }

        // Additionals
        for rr in &self.additionals {
            out.extend_from_slice(&rr.build());
        }

        out
    }

    /// Build with name compression.
    fn build_compressed(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        let mut compression_map: HashMap<String, u16> = HashMap::new();

        // Header (12 bytes)
        out.extend_from_slice(&self.id.to_be_bytes());
        let flags = header::build_flags(
            self.qr,
            self.opcode,
            self.aa,
            self.tc,
            self.rd,
            self.ra,
            self.z,
            self.ad,
            self.cd,
            self.rcode,
        );
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&(self.questions.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.authorities.len() as u16).to_be_bytes());
        out.extend_from_slice(&(self.additionals.len() as u16).to_be_bytes());

        // Questions
        for q in &self.questions {
            let encoded = q.build_compressed(out.len(), &mut compression_map);
            out.extend_from_slice(&encoded);
        }

        // Answers
        for rr in &self.answers {
            let encoded = rr.build_compressed(out.len(), &mut compression_map);
            out.extend_from_slice(&encoded);
        }

        // Authorities
        for rr in &self.authorities {
            let encoded = rr.build_compressed(out.len(), &mut compression_map);
            out.extend_from_slice(&encoded);
        }

        // Additionals
        for rr in &self.additionals {
            let encoded = rr.build_compressed(out.len(), &mut compression_map);
            out.extend_from_slice(&encoded);
        }

        out
    }

    /// Get the minimum header size.
    #[must_use]
    pub fn header_size(&self) -> usize {
        header::DNS_HEADER_LEN
    }
}

impl Default for DnsBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::rr_type;
    use super::*;
    use crate::layer::field_ext::DnsName;

    #[test]
    fn test_builder_default_query() {
        let b = DnsBuilder::new();
        assert!(!b.qr);
        assert!(b.rd);
        assert_eq!(b.opcode, 0);
        assert_eq!(b.rcode, 0);
        assert!(b.questions.is_empty());
    }

    #[test]
    fn test_builder_query_shortcut() {
        let b = DnsBuilder::query("example.com", rr_type::A);
        assert_eq!(b.questions.len(), 1);
        assert_eq!(b.questions[0].qtype, rr_type::A);
        assert_eq!(b.questions[0].qname.labels, vec!["example", "com"]);
    }

    #[test]
    fn test_builder_fluent_api() {
        let b = DnsBuilder::new()
            .id(0x1234)
            .qr(true)
            .aa(true)
            .rd(true)
            .ra(true)
            .rcode(0);
        assert_eq!(b.id, 0x1234);
        assert!(b.qr);
        assert!(b.aa);
    }

    #[test]
    fn test_builder_build_simple_query() {
        let b = DnsBuilder::query("example.com", rr_type::A).id(0x1234);
        let packet = b.build();

        // Verify header
        assert_eq!(packet.len() >= 12, true);
        assert_eq!(u16::from_be_bytes([packet[0], packet[1]]), 0x1234); // ID
        let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
        assert_eq!(qdcount, 1);
    }

    #[test]
    fn test_builder_build_uncompressed() {
        let b = DnsBuilder::query("example.com", rr_type::A)
            .id(0x5678)
            .compress(false);
        let packet = b.build();
        assert!(packet.len() >= 12 + 4 + 13); // header + type/class + "example.com" encoded
    }

    #[test]
    fn test_builder_compression_reduces_size() {
        let q1 = DnsQuestion::from_name("www.example.com").unwrap();
        let q2 = DnsQuestion::from_name("mail.example.com").unwrap();
        let b = DnsBuilder::new()
            .question(q1.clone())
            .question(q2.clone())
            .compress(true);
        let compressed = b.build();

        let b2 = DnsBuilder::new().question(q1).question(q2).compress(false);
        let uncompressed = b2.build();

        assert!(compressed.len() < uncompressed.len());
    }

    #[test]
    fn test_builder_response() {
        let b = DnsBuilder::response();
        assert!(b.qr);
        assert!(b.ra);
    }
}
