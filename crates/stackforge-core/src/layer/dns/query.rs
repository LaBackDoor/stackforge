//! DNS Question Record (DNSQR) - RFC 1035 Section 4.1.2.
//!
//! ```text
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                     QNAME                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                     QTYPE                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                     QCLASS                      |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```

use std::collections::HashMap;

use super::types;
use crate::layer::field::FieldError;
use crate::layer::field_ext::DnsName;

/// A DNS question record.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsQuestion {
    /// The domain name being queried.
    pub qname: DnsName,
    /// The query type (e.g., A=1, AAAA=28, MX=15).
    pub qtype: u16,
    /// The query class (typically IN=1).
    /// For mDNS, bit 15 is the unicast-response flag.
    pub qclass: u16,
}

impl DnsQuestion {
    /// Create a new question with default type A and class IN.
    pub fn new(qname: DnsName) -> Self {
        Self {
            qname,
            qtype: types::rr_type::A,
            qclass: types::dns_class::IN,
        }
    }

    /// Create a question from a domain name string.
    pub fn from_name(name: &str) -> Result<Self, FieldError> {
        Ok(Self {
            qname: DnsName::from_str_dotted(name)?,
            qtype: types::rr_type::A,
            qclass: types::dns_class::IN,
        })
    }

    /// Whether this is an mDNS unicast-response question.
    pub fn unicast_response(&self) -> bool {
        self.qclass & 0x8000 != 0
    }

    /// Get the actual class (without the mDNS unicast-response bit).
    pub fn actual_class(&self) -> u16 {
        self.qclass & 0x7FFF
    }

    /// Set the mDNS unicast-response flag.
    pub fn set_unicast_response(&mut self, unicast: bool) {
        if unicast {
            self.qclass |= 0x8000;
        } else {
            self.qclass &= 0x7FFF;
        }
    }

    /// Parse a question from wire format.
    ///
    /// `packet` is the full DNS packet (for pointer decompression).
    /// `offset` is the start of the question record.
    ///
    /// Returns the parsed question and bytes consumed.
    pub fn parse(packet: &[u8], offset: usize) -> Result<(Self, usize), FieldError> {
        let (qname, name_len) = DnsName::decode(packet, offset)?;
        let type_offset = offset + name_len;

        if type_offset + 4 > packet.len() {
            return Err(FieldError::BufferTooShort {
                offset: type_offset,
                need: 4,
                have: packet.len() - type_offset,
            });
        }

        let qtype = u16::from_be_bytes([packet[type_offset], packet[type_offset + 1]]);
        let qclass = u16::from_be_bytes([packet[type_offset + 2], packet[type_offset + 3]]);

        Ok((
            Self {
                qname,
                qtype,
                qclass,
            },
            name_len + 4,
        ))
    }

    /// Build the question record without compression.
    pub fn build(&self) -> Vec<u8> {
        let mut out = self.qname.encode();
        out.extend_from_slice(&self.qtype.to_be_bytes());
        out.extend_from_slice(&self.qclass.to_be_bytes());
        out
    }

    /// Build with DNS name compression.
    pub fn build_compressed(
        &self,
        current_offset: usize,
        compression_map: &mut HashMap<String, u16>,
    ) -> Vec<u8> {
        let mut out = self
            .qname
            .encode_compressed(current_offset, compression_map);
        out.extend_from_slice(&self.qtype.to_be_bytes());
        out.extend_from_slice(&self.qclass.to_be_bytes());
        out
    }

    /// Human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "{} {} {}",
            self.qname,
            types::dns_type_name(self.qtype),
            types::dns_class_name(self.actual_class()),
        )
    }
}

impl Default for DnsQuestion {
    fn default() -> Self {
        Self {
            qname: DnsName::from_str_dotted("www.example.com").unwrap_or_default(),
            qtype: types::rr_type::A,
            qclass: types::dns_class::IN,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_question_parse() {
        // Build a question for "example.com" type A class IN
        let mut data = vec![];
        data.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        data.extend_from_slice(&[3, b'c', b'o', b'm']);
        data.push(0); // root label
        data.extend_from_slice(&[0x00, 0x01]); // type A
        data.extend_from_slice(&[0x00, 0x01]); // class IN

        let (q, consumed) = DnsQuestion::parse(&data, 0).unwrap();
        assert_eq!(q.qname.labels, vec!["example", "com"]);
        assert_eq!(q.qtype, 1);
        assert_eq!(q.qclass, 1);
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_question_build_roundtrip() {
        let q = DnsQuestion {
            qname: DnsName::from_str_dotted("www.example.com").unwrap(),
            qtype: types::rr_type::AAAA,
            qclass: types::dns_class::IN,
        };
        let built = q.build();
        let (parsed, consumed) = DnsQuestion::parse(&built, 0).unwrap();
        assert_eq!(parsed, q);
        assert_eq!(consumed, built.len());
    }

    #[test]
    fn test_question_with_pointer() {
        // Packet: "example.com" at offset 0, then question "www" + pointer to 0
        let mut data = vec![];
        // "example.com" at offset 0
        data.extend_from_slice(&[
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ]);
        // Question at offset 13: "www" + ptr(0) + type A + class IN
        data.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 0x00]);
        data.extend_from_slice(&[0x00, 0x01]); // type A
        data.extend_from_slice(&[0x00, 0x01]); // class IN

        let (q, consumed) = DnsQuestion::parse(&data, 13).unwrap();
        assert_eq!(q.qname.labels, vec!["www", "example", "com"]);
        assert_eq!(q.qtype, 1);
        assert_eq!(consumed, 10); // 1+3 + 2 (ptr) + 2 (type) + 2 (class)
    }

    #[test]
    fn test_question_mdns_unicast() {
        let mut q = DnsQuestion::new(DnsName::from_str_dotted("test.local").unwrap());
        assert!(!q.unicast_response());
        assert_eq!(q.actual_class(), 1);

        q.set_unicast_response(true);
        assert!(q.unicast_response());
        assert_eq!(q.actual_class(), 1);
        assert_eq!(q.qclass, 0x8001);
    }

    #[test]
    fn test_question_summary() {
        let q = DnsQuestion {
            qname: DnsName::from_str_dotted("example.com").unwrap(),
            qtype: types::rr_type::MX,
            qclass: types::dns_class::IN,
        };
        let summary = q.summary();
        assert!(summary.contains("example.com"));
        assert!(summary.contains("MX"));
    }

    #[test]
    fn test_question_from_name() {
        let q = DnsQuestion::from_name("google.com").unwrap();
        assert_eq!(q.qname.labels, vec!["google", "com"]);
        assert_eq!(q.qtype, types::rr_type::A);
    }

    #[test]
    fn test_question_buffer_too_short() {
        // Name only, no type/class
        let data = vec![4, b't', b'e', b's', b't', 0];
        let result = DnsQuestion::parse(&data, 0);
        assert!(result.is_err());
    }
}
