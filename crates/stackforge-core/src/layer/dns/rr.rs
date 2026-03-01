//! DNS Resource Record (RFC 1035 Section 4.1.3).
//!
//! ```text
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      NAME                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      TYPE                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                     CLASS                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                      TTL                        |
//! |                                                 |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                   RDLENGTH                      |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! |                     RDATA                       |
//! +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//! ```

use std::collections::HashMap;

use super::rdata::DnsRData;
use super::types;
use crate::layer::field::FieldError;
use crate::layer::field_ext::DnsName;

/// A DNS Resource Record.
#[derive(Debug, Clone, PartialEq)]
pub struct DnsResourceRecord {
    /// The owner name.
    pub rrname: DnsName,
    /// The RR type (e.g., A=1, AAAA=28).
    pub rtype: u16,
    /// The RR class (typically IN=1).
    /// For mDNS, bit 15 is the cache-flush flag.
    pub rclass: u16,
    /// Time to live in seconds.
    pub ttl: u32,
    /// The parsed RDATA.
    pub rdata: DnsRData,
}

impl DnsResourceRecord {
    /// Create a new resource record with default class IN and TTL 0.
    pub fn new(rrname: DnsName, rtype: u16, rdata: DnsRData) -> Self {
        Self {
            rrname,
            rtype,
            rclass: types::dns_class::IN,
            ttl: 0,
            rdata,
        }
    }

    /// Parse a resource record from wire format.
    ///
    /// `packet` is the full DNS packet (needed for pointer decompression).
    /// `offset` is the start of the resource record.
    ///
    /// Returns the parsed record and the number of bytes consumed from `offset`.
    pub fn parse(packet: &[u8], offset: usize) -> Result<(Self, usize), FieldError> {
        // Decode the owner name.
        let (rrname, name_len) = DnsName::decode(packet, offset)?;
        let fixed_start = offset + name_len;

        // We need 10 bytes for type(2) + class(2) + ttl(4) + rdlength(2).
        if fixed_start + 10 > packet.len() {
            return Err(FieldError::BufferTooShort {
                offset: fixed_start,
                need: 10,
                have: packet.len().saturating_sub(fixed_start),
            });
        }

        let rtype = u16::from_be_bytes([packet[fixed_start], packet[fixed_start + 1]]);
        let rclass = u16::from_be_bytes([packet[fixed_start + 2], packet[fixed_start + 3]]);
        let ttl = u32::from_be_bytes([
            packet[fixed_start + 4],
            packet[fixed_start + 5],
            packet[fixed_start + 6],
            packet[fixed_start + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[fixed_start + 8], packet[fixed_start + 9]]);

        let rdata_start = fixed_start + 10;
        let rdata_end = rdata_start + rdlength as usize;

        // Bounds-check the RDATA region.
        if rdata_end > packet.len() {
            return Err(FieldError::BufferTooShort {
                offset: rdata_start,
                need: rdlength as usize,
                have: packet.len().saturating_sub(rdata_start),
            });
        }

        let rdata = DnsRData::parse(rtype, packet, rdata_start, rdlength)?;

        let total_consumed = name_len + 10 + rdlength as usize;
        Ok((
            Self {
                rrname,
                rtype,
                rclass,
                ttl,
                rdata,
            },
            total_consumed,
        ))
    }

    /// Build the resource record to wire format without compression.
    pub fn build(&self) -> Vec<u8> {
        let rdata_bytes = self.rdata.build();
        let rdlength = rdata_bytes.len() as u16;

        let mut out = self.rrname.encode();
        out.extend_from_slice(&self.rtype.to_be_bytes());
        out.extend_from_slice(&self.rclass.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());
        out.extend_from_slice(&rdlength.to_be_bytes());
        out.extend_from_slice(&rdata_bytes);
        out
    }

    /// Build with DNS name compression.
    pub fn build_compressed(
        &self,
        current_offset: usize,
        compression_map: &mut HashMap<String, u16>,
    ) -> Vec<u8> {
        let mut out = self
            .rrname
            .encode_compressed(current_offset, compression_map);

        out.extend_from_slice(&self.rtype.to_be_bytes());
        out.extend_from_slice(&self.rclass.to_be_bytes());
        out.extend_from_slice(&self.ttl.to_be_bytes());

        // The RDATA offset is current_offset + name_bytes + 10 (type+class+ttl+rdlength).
        let rdata_offset = current_offset + out.len() + 2; // +2 for rdlength field
        let rdata_bytes = self.rdata.build_compressed(rdata_offset, compression_map);
        let rdlength = rdata_bytes.len() as u16;

        out.extend_from_slice(&rdlength.to_be_bytes());
        out.extend_from_slice(&rdata_bytes);
        out
    }

    /// Whether the mDNS cache-flush bit (bit 15 of rclass) is set.
    pub fn cache_flush(&self) -> bool {
        self.rclass & 0x8000 != 0
    }

    /// Get the actual class without the mDNS cache-flush bit.
    pub fn actual_class(&self) -> u16 {
        self.rclass & 0x7FFF
    }

    /// Set or clear the mDNS cache-flush bit.
    pub fn set_cache_flush(&mut self, flush: bool) {
        if flush {
            self.rclass |= 0x8000;
        } else {
            self.rclass &= 0x7FFF;
        }
    }

    /// Human-readable summary of this resource record.
    pub fn summary(&self) -> String {
        let type_name = types::dns_type_name(self.rtype);
        let class_name = types::dns_class_name(self.actual_class());
        let rdata_summary = self.rdata.summary();
        format!(
            "{} {} {} {}",
            self.rrname, type_name, class_name, rdata_summary
        )
    }

    /// Whether this is an OPT pseudo-record (EDNS0, RFC 6891).
    pub fn is_opt(&self) -> bool {
        self.rtype == types::rr_type::OPT
    }

    // ========================================================================
    // OPT pseudo-record helpers (RFC 6891)
    // ========================================================================

    /// For OPT records, the class field encodes the requestor's UDP payload size.
    pub fn opt_udp_size(&self) -> u16 {
        self.rclass
    }

    /// For OPT records, the upper 8 bits of the TTL encode the extended RCODE.
    pub fn opt_extended_rcode(&self) -> u8 {
        ((self.ttl >> 24) & 0xFF) as u8
    }

    /// For OPT records, bits 16-23 of the TTL encode the EDNS version.
    pub fn opt_version(&self) -> u8 {
        ((self.ttl >> 16) & 0xFF) as u8
    }

    /// For OPT records, the DNSSEC OK (DO) flag is bit 15 of the lower 16 bits of the TTL.
    pub fn opt_do_flag(&self) -> bool {
        self.ttl & 0x8000 != 0
    }
}

impl Default for DnsResourceRecord {
    fn default() -> Self {
        Self {
            rrname: DnsName::root(),
            rtype: types::rr_type::A,
            rclass: types::dns_class::IN,
            ttl: 0,
            rdata: DnsRData::Unknown {
                rtype: types::rr_type::A,
                data: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Helper: build a wire-format A record for "example.com" with address 93.184.216.34.
    fn build_example_a_record() -> Vec<u8> {
        let mut data = Vec::new();
        // Name: example.com
        data.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        data.extend_from_slice(&[3, b'c', b'o', b'm']);
        data.push(0); // root label
        // Type A (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // Class IN (1)
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL: 300 seconds
        data.extend_from_slice(&300u32.to_be_bytes());
        // RDLENGTH: 4
        data.extend_from_slice(&[0x00, 0x04]);
        // RDATA: 93.184.216.34
        data.extend_from_slice(&[93, 184, 216, 34]);
        data
    }

    #[test]
    fn test_parse_a_record() {
        let data = build_example_a_record();
        let (rr, consumed) = DnsResourceRecord::parse(&data, 0).unwrap();

        assert_eq!(rr.rrname.labels, vec!["example", "com"]);
        assert_eq!(rr.rtype, types::rr_type::A);
        assert_eq!(rr.rclass, types::dns_class::IN);
        assert_eq!(rr.ttl, 300);
        assert_eq!(rr.rdata, DnsRData::A(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(consumed, data.len());
    }

    #[test]
    fn test_build_roundtrip_a_record() {
        let rr = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("example.com").unwrap(),
            rtype: types::rr_type::A,
            rclass: types::dns_class::IN,
            ttl: 3600,
            rdata: DnsRData::A(Ipv4Addr::new(192, 168, 1, 1)),
        };

        let built = rr.build();
        let (parsed, consumed) = DnsResourceRecord::parse(&built, 0).unwrap();

        assert_eq!(consumed, built.len());
        assert_eq!(parsed.rrname, rr.rrname);
        assert_eq!(parsed.rtype, rr.rtype);
        assert_eq!(parsed.rclass, rr.rclass);
        assert_eq!(parsed.ttl, rr.ttl);
        assert_eq!(parsed.rdata, rr.rdata);
    }

    #[test]
    fn test_build_roundtrip_aaaa_record() {
        let rr = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("ipv6.example.com").unwrap(),
            rtype: types::rr_type::AAAA,
            rclass: types::dns_class::IN,
            ttl: 7200,
            rdata: DnsRData::AAAA("2001:db8::1".parse().unwrap()),
        };

        let built = rr.build();
        let (parsed, consumed) = DnsResourceRecord::parse(&built, 0).unwrap();

        assert_eq!(consumed, built.len());
        assert_eq!(parsed.rtype, types::rr_type::AAAA);
        assert_eq!(parsed.rdata, rr.rdata);
    }

    #[test]
    fn test_build_roundtrip_cname_record() {
        let rr = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("www.example.com").unwrap(),
            rtype: types::rr_type::CNAME,
            rclass: types::dns_class::IN,
            ttl: 600,
            rdata: DnsRData::CNAME(DnsName::from_str_dotted("example.com").unwrap()),
        };

        let built = rr.build();
        let (parsed, consumed) = DnsResourceRecord::parse(&built, 0).unwrap();

        assert_eq!(consumed, built.len());
        assert_eq!(parsed.rtype, types::rr_type::CNAME);
        assert_eq!(
            parsed.rdata,
            DnsRData::CNAME(DnsName::from_str_dotted("example.com").unwrap())
        );
    }

    #[test]
    fn test_build_roundtrip_mx_record() {
        let rr = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("example.com").unwrap(),
            rtype: types::rr_type::MX,
            rclass: types::dns_class::IN,
            ttl: 3600,
            rdata: DnsRData::MX {
                preference: 10,
                exchange: DnsName::from_str_dotted("mail.example.com").unwrap(),
            },
        };

        let built = rr.build();
        let (parsed, consumed) = DnsResourceRecord::parse(&built, 0).unwrap();

        assert_eq!(consumed, built.len());
        assert_eq!(parsed.rtype, types::rr_type::MX);
        assert_eq!(parsed.rdata, rr.rdata);
    }

    #[test]
    fn test_build_roundtrip_txt_record() {
        let rr = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("example.com").unwrap(),
            rtype: types::rr_type::TXT,
            rclass: types::dns_class::IN,
            ttl: 300,
            rdata: DnsRData::TXT(vec![b"v=spf1 include:example.com ~all".to_vec()]),
        };

        let built = rr.build();
        let (parsed, consumed) = DnsResourceRecord::parse(&built, 0).unwrap();

        assert_eq!(consumed, built.len());
        assert_eq!(parsed.rdata, rr.rdata);
    }

    #[test]
    fn test_opt_record_helpers() {
        // OPT pseudo-record:
        //   NAME: root (.)
        //   TYPE: OPT (41)
        //   CLASS: UDP payload size (e.g., 4096)
        //   TTL encodes: extended-rcode (8 bits) | version (8 bits) | DO flag + reserved (16 bits)
        let rr = DnsResourceRecord {
            rrname: DnsName::root(),
            rtype: types::rr_type::OPT,
            rclass: 4096, // UDP payload size
            // TTL: extended_rcode=0, version=0, DO=1, rest=0
            // DO flag is bit 15 of lower 16 bits => 0x0000_8000
            ttl: 0x0000_8000,
            rdata: DnsRData::OPT(vec![]),
        };

        assert!(rr.is_opt());
        assert_eq!(rr.opt_udp_size(), 4096);
        assert_eq!(rr.opt_extended_rcode(), 0);
        assert_eq!(rr.opt_version(), 0);
        assert!(rr.opt_do_flag());
    }

    #[test]
    fn test_opt_record_extended_rcode_and_version() {
        // TTL: extended_rcode=3, version=1, DO=0
        // 0x03_01_0000
        let rr = DnsResourceRecord {
            rrname: DnsName::root(),
            rtype: types::rr_type::OPT,
            rclass: 1232,
            ttl: 0x03_01_0000,
            rdata: DnsRData::OPT(vec![]),
        };

        assert!(rr.is_opt());
        assert_eq!(rr.opt_udp_size(), 1232);
        assert_eq!(rr.opt_extended_rcode(), 3);
        assert_eq!(rr.opt_version(), 1);
        assert!(!rr.opt_do_flag());
    }

    #[test]
    fn test_mdns_cache_flush() {
        let mut rr = DnsResourceRecord::new(
            DnsName::from_str_dotted("test.local").unwrap(),
            types::rr_type::A,
            DnsRData::A(Ipv4Addr::new(192, 168, 0, 1)),
        );

        assert!(!rr.cache_flush());
        assert_eq!(rr.actual_class(), types::dns_class::IN);

        rr.set_cache_flush(true);
        assert!(rr.cache_flush());
        assert_eq!(rr.actual_class(), types::dns_class::IN);
        assert_eq!(rr.rclass, 0x8001);

        rr.set_cache_flush(false);
        assert!(!rr.cache_flush());
        assert_eq!(rr.rclass, types::dns_class::IN);
    }

    #[test]
    fn test_buffer_too_short_no_fixed_fields() {
        // Name only, no type/class/ttl/rdlength
        let data = vec![4, b't', b'e', b's', b't', 0];
        let result = DnsResourceRecord::parse(&data, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            FieldError::BufferTooShort { need, .. } => assert_eq!(need, 10),
            other => panic!("Expected BufferTooShort, got {:?}", other),
        }
    }

    #[test]
    fn test_buffer_too_short_truncated_rdata() {
        let mut data = Vec::new();
        // Name: test
        data.extend_from_slice(&[4, b't', b'e', b's', b't', 0]);
        // Type A
        data.extend_from_slice(&[0x00, 0x01]);
        // Class IN
        data.extend_from_slice(&[0x00, 0x01]);
        // TTL
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
        // RDLENGTH: 4 (but we won't provide 4 bytes of RDATA)
        data.extend_from_slice(&[0x00, 0x04]);
        // Only 2 bytes of RDATA instead of 4
        data.extend_from_slice(&[192, 168]);

        let result = DnsResourceRecord::parse(&data, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            FieldError::BufferTooShort { need, have, .. } => {
                assert_eq!(need, 4);
                assert_eq!(have, 2);
            },
            other => panic!("Expected BufferTooShort, got {:?}", other),
        }
    }

    #[test]
    fn test_buffer_too_short_empty() {
        let result = DnsResourceRecord::parse(&[], 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_defaults() {
        let rr = DnsResourceRecord::new(
            DnsName::from_str_dotted("example.com").unwrap(),
            types::rr_type::A,
            DnsRData::A(Ipv4Addr::new(1, 2, 3, 4)),
        );

        assert_eq!(rr.rclass, types::dns_class::IN);
        assert_eq!(rr.ttl, 0);
    }

    #[test]
    fn test_default() {
        let rr = DnsResourceRecord::default();
        assert!(rr.rrname.is_root());
        assert_eq!(rr.rtype, types::rr_type::A);
        assert_eq!(rr.rclass, types::dns_class::IN);
        assert_eq!(rr.ttl, 0);
    }

    #[test]
    fn test_summary() {
        let rr = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("example.com").unwrap(),
            rtype: types::rr_type::A,
            rclass: types::dns_class::IN,
            ttl: 300,
            rdata: DnsRData::A(Ipv4Addr::new(192, 168, 1, 1)),
        };

        let summary = rr.summary();
        assert!(summary.contains("example.com."));
        assert!(summary.contains("A"));
        assert!(summary.contains("IN"));
        assert!(summary.contains("192.168.1.1"));
    }

    #[test]
    fn test_is_opt() {
        let opt = DnsResourceRecord {
            rrname: DnsName::root(),
            rtype: types::rr_type::OPT,
            rclass: 4096,
            ttl: 0,
            rdata: DnsRData::OPT(vec![]),
        };
        assert!(opt.is_opt());

        let a = DnsResourceRecord::new(
            DnsName::from_str_dotted("example.com").unwrap(),
            types::rr_type::A,
            DnsRData::A(Ipv4Addr::LOCALHOST),
        );
        assert!(!a.is_opt());
    }

    #[test]
    fn test_parse_at_nonzero_offset() {
        // Prepend some garbage bytes before the actual record.
        let record_bytes = build_example_a_record();
        let mut data = vec![0xDE, 0xAD, 0xBE, 0xEF]; // 4 bytes of header
        data.extend_from_slice(&record_bytes);

        let (rr, consumed) = DnsResourceRecord::parse(&data, 4).unwrap();
        assert_eq!(rr.rrname.labels, vec!["example", "com"]);
        assert_eq!(rr.rdata, DnsRData::A(Ipv4Addr::new(93, 184, 216, 34)));
        assert_eq!(consumed, record_bytes.len());
    }

    #[test]
    fn test_build_compressed_produces_valid_output() {
        let rr = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("example.com").unwrap(),
            rtype: types::rr_type::A,
            rclass: types::dns_class::IN,
            ttl: 60,
            rdata: DnsRData::A(Ipv4Addr::new(10, 0, 0, 1)),
        };

        let mut compression_map = HashMap::new();
        let built = rr.build_compressed(0, &mut compression_map);

        // The compressed output should be parseable (for A records, no name compression
        // in RDATA, so the result is the same as uncompressed).
        let (parsed, consumed) = DnsResourceRecord::parse(&built, 0).unwrap();
        assert_eq!(consumed, built.len());
        assert_eq!(parsed.rrname, rr.rrname);
        assert_eq!(parsed.rdata, rr.rdata);
    }

    #[test]
    fn test_build_compressed_reuses_names() {
        let rr1 = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("example.com").unwrap(),
            rtype: types::rr_type::A,
            rclass: types::dns_class::IN,
            ttl: 60,
            rdata: DnsRData::A(Ipv4Addr::new(10, 0, 0, 1)),
        };

        let rr2 = DnsResourceRecord {
            rrname: DnsName::from_str_dotted("example.com").unwrap(),
            rtype: types::rr_type::A,
            rclass: types::dns_class::IN,
            ttl: 60,
            rdata: DnsRData::A(Ipv4Addr::new(10, 0, 0, 2)),
        };

        let mut compression_map = HashMap::new();
        let built1 = rr1.build_compressed(0, &mut compression_map);
        let built2 = rr2.build_compressed(built1.len(), &mut compression_map);

        // The second record's name should be compressed (pointer instead of full name).
        let uncompressed2 = rr2.build();
        assert!(built2.len() < uncompressed2.len());

        // Both should be parseable from the combined buffer.
        let mut packet = Vec::new();
        packet.extend_from_slice(&built1);
        packet.extend_from_slice(&built2);

        let (parsed1, consumed1) = DnsResourceRecord::parse(&packet, 0).unwrap();
        assert_eq!(parsed1.rrname.labels, vec!["example", "com"]);

        let (parsed2, _consumed2) = DnsResourceRecord::parse(&packet, consumed1).unwrap();
        assert_eq!(parsed2.rrname.labels, vec!["example", "com"]);
        assert_eq!(parsed2.rdata, DnsRData::A(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn test_parse_with_name_pointer() {
        // Simulate a packet where the RR name uses a compression pointer.
        let mut packet = Vec::new();
        // Offset 0: "example.com" in wire format
        packet.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        packet.extend_from_slice(&[3, b'c', b'o', b'm']);
        packet.push(0); // root label -- 13 bytes total

        // Offset 13: RR with pointer to offset 0
        packet.extend_from_slice(&[0xC0, 0x00]); // pointer to offset 0
        packet.extend_from_slice(&[0x00, 0x01]); // type A
        packet.extend_from_slice(&[0x00, 0x01]); // class IN
        packet.extend_from_slice(&120u32.to_be_bytes()); // TTL 120
        packet.extend_from_slice(&[0x00, 0x04]); // rdlength 4
        packet.extend_from_slice(&[10, 20, 30, 40]); // 10.20.30.40

        let (rr, consumed) = DnsResourceRecord::parse(&packet, 13).unwrap();
        assert_eq!(rr.rrname.labels, vec!["example", "com"]);
        assert_eq!(rr.rtype, types::rr_type::A);
        assert_eq!(rr.ttl, 120);
        assert_eq!(rr.rdata, DnsRData::A(Ipv4Addr::new(10, 20, 30, 40)));
        // pointer(2) + type(2) + class(2) + ttl(4) + rdlength(2) + rdata(4) = 16
        assert_eq!(consumed, 16);
    }
}
