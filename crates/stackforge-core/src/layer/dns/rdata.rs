//! DNS Resource Record Data (RDATA) parsing and building.
//!
//! Implements parsing and serialization for all common DNS record types,
//! including DNSSEC records (RRSIG, NSEC, NSEC3, DNSKEY, DS),
//! service records (SRV, SVCB, HTTPS, NAPTR, TLSA, CAA),
//! and standard records (A, AAAA, MX, SOA, TXT, CNAME, NS, PTR, DNAME).

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::bitmap;
use super::edns::EdnsOption;
use super::svcb::SvcParam;
use super::types::{self, rr_type};
use crate::layer::field::FieldError;
use crate::layer::field_ext::DnsName;

/// Parsed DNS resource record data.
///
/// Each variant corresponds to one or more DNS RR types and contains
/// the fully parsed fields of that record's RDATA section.
#[derive(Debug, Clone, PartialEq)]
pub enum DnsRData {
    /// A record: IPv4 address (RFC 1035).
    A(Ipv4Addr),

    /// AAAA record: IPv6 address (RFC 3596).
    AAAA(Ipv6Addr),

    /// NS record: authoritative name server (RFC 1035).
    NS(DnsName),

    /// CNAME record: canonical name alias (RFC 1035).
    CNAME(DnsName),

    /// PTR record: pointer to a domain name (RFC 1035).
    PTR(DnsName),

    /// DNAME record: delegation of a subtree (RFC 6672).
    DNAME(DnsName),

    /// MX record: mail exchange (RFC 1035).
    MX { preference: u16, exchange: DnsName },

    /// TXT record: text strings (RFC 1035).
    /// Contains multiple character-strings, each up to 255 bytes.
    TXT(Vec<Vec<u8>>),

    /// SOA record: start of authority (RFC 1035).
    SOA {
        mname: DnsName,
        rname: DnsName,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },

    /// SRV record: service location (RFC 2782).
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: DnsName,
    },

    /// HINFO record: host information (RFC 1035).
    HINFO { cpu: Vec<u8>, os: Vec<u8> },

    /// NAPTR record: naming authority pointer (RFC 3403).
    NAPTR {
        order: u16,
        preference: u16,
        flags: Vec<u8>,
        services: Vec<u8>,
        regexp: Vec<u8>,
        replacement: DnsName,
    },

    /// SVCB record: service binding (RFC 9460).
    SVCB {
        priority: u16,
        target: DnsName,
        params: Vec<SvcParam>,
    },

    /// HTTPS record: HTTPS service binding (RFC 9460).
    HTTPS {
        priority: u16,
        target: DnsName,
        params: Vec<SvcParam>,
    },

    /// CAA record: certificate authority authorization (RFC 8659).
    CAA {
        flags: u8,
        tag: String,
        value: Vec<u8>,
    },

    /// RRSIG record: DNSSEC signature (RFC 4034).
    RRSIG {
        type_covered: u16,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        sig_expiration: u32,
        sig_inception: u32,
        key_tag: u16,
        signer_name: DnsName,
        signature: Vec<u8>,
    },

    /// NSEC record: authenticated denial of existence (RFC 4034).
    NSEC {
        next_domain: DnsName,
        type_bitmaps: Vec<u16>,
    },

    /// NSEC3 record: hashed authenticated denial of existence (RFC 5155).
    NSEC3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
        next_hashed: Vec<u8>,
        type_bitmaps: Vec<u16>,
    },

    /// NSEC3PARAM record: NSEC3 parameters (RFC 5155).
    NSEC3PARAM {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: Vec<u8>,
    },

    /// DNSKEY record: DNSSEC public key (RFC 4034).
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: Vec<u8>,
    },

    /// DS record: delegation signer (RFC 4034).
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },

    /// DLV record: DNSSEC lookaside validation (RFC 4431).
    DLV {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: Vec<u8>,
    },

    /// TSIG record: transaction signature (RFC 8945).
    TSIG {
        algorithm_name: DnsName,
        time_signed: u64,
        fudge: u16,
        mac: Vec<u8>,
        original_id: u16,
        error: u16,
        other_data: Vec<u8>,
    },

    /// TLSA record: TLS authentication (RFC 6698).
    TLSA {
        usage: u8,
        selector: u8,
        matching_type: u8,
        cert_data: Vec<u8>,
    },

    /// OPT pseudo-record: EDNS(0) options (RFC 6891).
    OPT(Vec<EdnsOption>),

    /// Unknown/unsupported record type.
    Unknown { rtype: u16, data: Vec<u8> },
}

impl DnsRData {
    /// Parse RDATA from wire format.
    ///
    /// # Arguments
    /// * `rtype` - DNS record type number
    /// * `packet` - Full DNS packet buffer (needed for name compression pointer resolution)
    /// * `rdata_offset` - Byte offset where RDATA begins in `packet`
    /// * `rdlength` - Length of RDATA in bytes
    pub fn parse(
        rtype: u16,
        packet: &[u8],
        rdata_offset: usize,
        rdlength: u16,
    ) -> Result<Self, FieldError> {
        let rdlen = rdlength as usize;
        let rdata_end = rdata_offset + rdlen;

        // Bounds check
        if rdata_end > packet.len() {
            return Err(FieldError::BufferTooShort {
                offset: rdata_offset,
                need: rdlen,
                have: packet.len().saturating_sub(rdata_offset),
            });
        }

        let rdata = &packet[rdata_offset..rdata_end];

        match rtype {
            rr_type::A => Self::parse_a(rdata),
            rr_type::AAAA => Self::parse_aaaa(rdata),
            rr_type::NS => Self::parse_name_record(packet, rdata_offset, rdlen, DnsRData::NS),
            rr_type::CNAME => Self::parse_name_record(packet, rdata_offset, rdlen, DnsRData::CNAME),
            rr_type::PTR => Self::parse_name_record(packet, rdata_offset, rdlen, DnsRData::PTR),
            rr_type::DNAME => Self::parse_name_record(packet, rdata_offset, rdlen, DnsRData::DNAME),
            rr_type::MX => Self::parse_mx(packet, rdata_offset, rdata),
            rr_type::TXT => Self::parse_txt(rdata),
            rr_type::SOA => Self::parse_soa(packet, rdata_offset, rdata_end),
            rr_type::SRV => Self::parse_srv(packet, rdata_offset, rdata),
            rr_type::HINFO => Self::parse_hinfo(rdata),
            rr_type::NAPTR => Self::parse_naptr(packet, rdata_offset, rdata_end),
            rr_type::SVCB => Self::parse_svcb(packet, rdata_offset, rdata, rdlen, false),
            rr_type::HTTPS => Self::parse_svcb(packet, rdata_offset, rdata, rdlen, true),
            rr_type::CAA => Self::parse_caa(rdata),
            rr_type::RRSIG => Self::parse_rrsig(packet, rdata_offset, rdata, rdlen),
            rr_type::NSEC => Self::parse_nsec(packet, rdata_offset, rdata, rdlen),
            rr_type::NSEC3 => Self::parse_nsec3(rdata),
            rr_type::NSEC3PARAM => Self::parse_nsec3param(rdata),
            rr_type::DNSKEY => Self::parse_dnskey(rdata),
            rr_type::DS => Self::parse_ds(rdata),
            rr_type::DLV => Self::parse_dlv(rdata),
            rr_type::TSIG => Self::parse_tsig(packet, rdata_offset, rdata_end),
            rr_type::TLSA => Self::parse_tlsa(rdata),
            rr_type::OPT => Self::parse_opt(rdata),
            _ => Ok(DnsRData::Unknown {
                rtype,
                data: rdata.to_vec(),
            }),
        }
    }

    // ========================================================================
    // Individual type parsers
    // ========================================================================

    fn parse_a(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() != 4 {
            return Err(FieldError::InvalidValue(format!(
                "A record RDATA must be 4 bytes, got {}",
                rdata.len()
            )));
        }
        Ok(DnsRData::A(Ipv4Addr::new(
            rdata[0], rdata[1], rdata[2], rdata[3],
        )))
    }

    fn parse_aaaa(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() != 16 {
            return Err(FieldError::InvalidValue(format!(
                "AAAA record RDATA must be 16 bytes, got {}",
                rdata.len()
            )));
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(rdata);
        Ok(DnsRData::AAAA(Ipv6Addr::from(bytes)))
    }

    /// Parse a record whose RDATA is a single domain name (NS, CNAME, PTR, DNAME).
    fn parse_name_record<F>(
        packet: &[u8],
        rdata_offset: usize,
        _rdlen: usize,
        constructor: F,
    ) -> Result<Self, FieldError>
    where
        F: FnOnce(DnsName) -> DnsRData,
    {
        let (name, _consumed) = DnsName::decode(packet, rdata_offset)?;
        Ok(constructor(name))
    }

    fn parse_mx(packet: &[u8], rdata_offset: usize, rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 2,
                have: rdata.len(),
            });
        }
        let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
        let (exchange, _consumed) = DnsName::decode(packet, rdata_offset + 2)?;
        Ok(DnsRData::MX {
            preference,
            exchange,
        })
    }

    fn parse_txt(rdata: &[u8]) -> Result<Self, FieldError> {
        let mut strings = Vec::new();
        let mut pos = 0;

        while pos < rdata.len() {
            let str_len = rdata[pos] as usize;
            pos += 1;

            if pos + str_len > rdata.len() {
                return Err(FieldError::BufferTooShort {
                    offset: pos,
                    need: str_len,
                    have: rdata.len() - pos,
                });
            }

            strings.push(rdata[pos..pos + str_len].to_vec());
            pos += str_len;
        }

        Ok(DnsRData::TXT(strings))
    }

    fn parse_soa(packet: &[u8], rdata_offset: usize, rdata_end: usize) -> Result<Self, FieldError> {
        let (mname, consumed1) = DnsName::decode(packet, rdata_offset)?;
        let (rname, consumed2) = DnsName::decode(packet, rdata_offset + consumed1)?;

        let fixed_start = rdata_offset + consumed1 + consumed2;
        if fixed_start + 20 > rdata_end {
            return Err(FieldError::BufferTooShort {
                offset: fixed_start,
                need: 20,
                have: rdata_end.saturating_sub(fixed_start),
            });
        }

        let fixed = &packet[fixed_start..fixed_start + 20];
        let serial = u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
        let refresh = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let retry = u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]);
        let expire = u32::from_be_bytes([fixed[12], fixed[13], fixed[14], fixed[15]]);
        let minimum = u32::from_be_bytes([fixed[16], fixed[17], fixed[18], fixed[19]]);

        Ok(DnsRData::SOA {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }

    fn parse_srv(packet: &[u8], rdata_offset: usize, rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() < 6 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 6,
                have: rdata.len(),
            });
        }
        let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
        let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
        let port = u16::from_be_bytes([rdata[4], rdata[5]]);
        let (target, _consumed) = DnsName::decode(packet, rdata_offset + 6)?;

        Ok(DnsRData::SRV {
            priority,
            weight,
            port,
            target,
        })
    }

    fn parse_hinfo(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.is_empty() {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 1,
                have: 0,
            });
        }

        let cpu_len = rdata[0] as usize;
        if 1 + cpu_len >= rdata.len() {
            return Err(FieldError::BufferTooShort {
                offset: 1,
                need: cpu_len + 1, // +1 for the OS length byte
                have: rdata.len() - 1,
            });
        }
        let cpu = rdata[1..=cpu_len].to_vec();

        let os_start = 1 + cpu_len;
        let os_len = rdata[os_start] as usize;
        if os_start + 1 + os_len > rdata.len() {
            return Err(FieldError::BufferTooShort {
                offset: os_start + 1,
                need: os_len,
                have: rdata.len() - os_start - 1,
            });
        }
        let os = rdata[os_start + 1..os_start + 1 + os_len].to_vec();

        Ok(DnsRData::HINFO { cpu, os })
    }

    fn parse_naptr(
        packet: &[u8],
        rdata_offset: usize,
        rdata_end: usize,
    ) -> Result<Self, FieldError> {
        let rdata = &packet[rdata_offset..rdata_end];
        if rdata.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 4,
                have: rdata.len(),
            });
        }

        let order = u16::from_be_bytes([rdata[0], rdata[1]]);
        let preference = u16::from_be_bytes([rdata[2], rdata[3]]);
        let mut pos = 4;

        // Parse three character-strings: flags, services, regexp
        let (flags, consumed) = Self::parse_character_string(rdata, pos)?;
        pos += consumed;

        let (services, consumed) = Self::parse_character_string(rdata, pos)?;
        pos += consumed;

        let (regexp, consumed) = Self::parse_character_string(rdata, pos)?;
        pos += consumed;

        // The replacement name may use compression pointers
        let (replacement, _consumed) = DnsName::decode(packet, rdata_offset + pos)?;

        Ok(DnsRData::NAPTR {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        })
    }

    fn parse_svcb(
        packet: &[u8],
        rdata_offset: usize,
        rdata: &[u8],
        rdlen: usize,
        is_https: bool,
    ) -> Result<Self, FieldError> {
        if rdata.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 2,
                have: rdata.len(),
            });
        }

        let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
        let (target, name_consumed) = DnsName::decode(packet, rdata_offset + 2)?;

        let params_start = 2 + name_consumed;
        let params = if params_start < rdlen {
            SvcParam::parse_all(&rdata[params_start..])?
        } else {
            Vec::new()
        };

        if is_https {
            Ok(DnsRData::HTTPS {
                priority,
                target,
                params,
            })
        } else {
            Ok(DnsRData::SVCB {
                priority,
                target,
                params,
            })
        }
    }

    fn parse_caa(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() < 2 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 2,
                have: rdata.len(),
            });
        }

        let flags = rdata[0];
        let tag_len = rdata[1] as usize;

        if 2 + tag_len > rdata.len() {
            return Err(FieldError::BufferTooShort {
                offset: 2,
                need: tag_len,
                have: rdata.len() - 2,
            });
        }

        let tag = String::from_utf8_lossy(&rdata[2..2 + tag_len]).into_owned();
        let value = rdata[2 + tag_len..].to_vec();

        Ok(DnsRData::CAA { flags, tag, value })
    }

    fn parse_rrsig(
        packet: &[u8],
        rdata_offset: usize,
        rdata: &[u8],
        rdlen: usize,
    ) -> Result<Self, FieldError> {
        if rdata.len() < 18 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 18,
                have: rdata.len(),
            });
        }

        let type_covered = u16::from_be_bytes([rdata[0], rdata[1]]);
        let algorithm = rdata[2];
        let labels = rdata[3];
        let original_ttl = u32::from_be_bytes([rdata[4], rdata[5], rdata[6], rdata[7]]);
        let sig_expiration = u32::from_be_bytes([rdata[8], rdata[9], rdata[10], rdata[11]]);
        let sig_inception = u32::from_be_bytes([rdata[12], rdata[13], rdata[14], rdata[15]]);
        let key_tag = u16::from_be_bytes([rdata[16], rdata[17]]);

        let (signer_name, name_consumed) = DnsName::decode(packet, rdata_offset + 18)?;
        let sig_start = 18 + name_consumed;

        let signature = if sig_start < rdlen {
            rdata[sig_start..].to_vec()
        } else {
            Vec::new()
        };

        Ok(DnsRData::RRSIG {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            sig_expiration,
            sig_inception,
            key_tag,
            signer_name,
            signature,
        })
    }

    fn parse_nsec(
        packet: &[u8],
        rdata_offset: usize,
        rdata: &[u8],
        rdlen: usize,
    ) -> Result<Self, FieldError> {
        let (next_domain, name_consumed) = DnsName::decode(packet, rdata_offset)?;

        let type_bitmaps = if name_consumed < rdlen {
            bitmap::bitmap_to_rr_list(&rdata[name_consumed..])?
        } else {
            Vec::new()
        };

        Ok(DnsRData::NSEC {
            next_domain,
            type_bitmaps,
        })
    }

    fn parse_nsec3(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() < 5 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 5,
                have: rdata.len(),
            });
        }

        let hash_algorithm = rdata[0];
        let flags = rdata[1];
        let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
        let salt_len = rdata[4] as usize;
        let mut pos = 5;

        if pos + salt_len >= rdata.len() {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: salt_len + 1, // +1 for hash length byte
                have: rdata.len() - pos,
            });
        }
        let salt = rdata[pos..pos + salt_len].to_vec();
        pos += salt_len;

        let hash_len = rdata[pos] as usize;
        pos += 1;

        if pos + hash_len > rdata.len() {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: hash_len,
                have: rdata.len() - pos,
            });
        }
        let next_hashed = rdata[pos..pos + hash_len].to_vec();
        pos += hash_len;

        let type_bitmaps = if pos < rdata.len() {
            bitmap::bitmap_to_rr_list(&rdata[pos..])?
        } else {
            Vec::new()
        };

        Ok(DnsRData::NSEC3 {
            hash_algorithm,
            flags,
            iterations,
            salt,
            next_hashed,
            type_bitmaps,
        })
    }

    fn parse_nsec3param(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() < 5 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 5,
                have: rdata.len(),
            });
        }

        let hash_algorithm = rdata[0];
        let flags = rdata[1];
        let iterations = u16::from_be_bytes([rdata[2], rdata[3]]);
        let salt_len = rdata[4] as usize;

        if 5 + salt_len > rdata.len() {
            return Err(FieldError::BufferTooShort {
                offset: 5,
                need: salt_len,
                have: rdata.len() - 5,
            });
        }

        let salt = rdata[5..5 + salt_len].to_vec();

        Ok(DnsRData::NSEC3PARAM {
            hash_algorithm,
            flags,
            iterations,
            salt,
        })
    }

    fn parse_dnskey(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 4,
                have: rdata.len(),
            });
        }

        let flags = u16::from_be_bytes([rdata[0], rdata[1]]);
        let protocol = rdata[2];
        let algorithm = rdata[3];
        let public_key = rdata[4..].to_vec();

        Ok(DnsRData::DNSKEY {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    fn parse_ds(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 4,
                have: rdata.len(),
            });
        }

        let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
        let algorithm = rdata[2];
        let digest_type = rdata[3];
        let digest = rdata[4..].to_vec();

        Ok(DnsRData::DS {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    fn parse_dlv(rdata: &[u8]) -> Result<Self, FieldError> {
        // DLV has the same format as DS
        if rdata.len() < 4 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 4,
                have: rdata.len(),
            });
        }

        let key_tag = u16::from_be_bytes([rdata[0], rdata[1]]);
        let algorithm = rdata[2];
        let digest_type = rdata[3];
        let digest = rdata[4..].to_vec();

        Ok(DnsRData::DLV {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    fn parse_tsig(
        packet: &[u8],
        rdata_offset: usize,
        rdata_end: usize,
    ) -> Result<Self, FieldError> {
        let (algorithm_name, name_consumed) = DnsName::decode(packet, rdata_offset)?;
        let mut pos = rdata_offset + name_consumed;

        // Time signed: 48-bit (6 bytes)
        if pos + 6 > rdata_end {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: 6,
                have: rdata_end.saturating_sub(pos),
            });
        }
        let time_signed = (u64::from(packet[pos]) << 40)
            | (u64::from(packet[pos + 1]) << 32)
            | (u64::from(packet[pos + 2]) << 24)
            | (u64::from(packet[pos + 3]) << 16)
            | (u64::from(packet[pos + 4]) << 8)
            | u64::from(packet[pos + 5]);
        pos += 6;

        // Fudge: 2 bytes
        if pos + 2 > rdata_end {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: 2,
                have: rdata_end.saturating_sub(pos),
            });
        }
        let fudge = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        pos += 2;

        // MAC size + MAC
        if pos + 2 > rdata_end {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: 2,
                have: rdata_end.saturating_sub(pos),
            });
        }
        let mac_size = u16::from_be_bytes([packet[pos], packet[pos + 1]]) as usize;
        pos += 2;

        if pos + mac_size > rdata_end {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: mac_size,
                have: rdata_end.saturating_sub(pos),
            });
        }
        let mac = packet[pos..pos + mac_size].to_vec();
        pos += mac_size;

        // Original ID, Error, Other Data Length + Other Data
        if pos + 6 > rdata_end {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: 6,
                have: rdata_end.saturating_sub(pos),
            });
        }
        let original_id = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
        let error = u16::from_be_bytes([packet[pos + 2], packet[pos + 3]]);
        let other_len = u16::from_be_bytes([packet[pos + 4], packet[pos + 5]]) as usize;
        pos += 6;

        if pos + other_len > rdata_end {
            return Err(FieldError::BufferTooShort {
                offset: pos,
                need: other_len,
                have: rdata_end.saturating_sub(pos),
            });
        }
        let other_data = packet[pos..pos + other_len].to_vec();

        Ok(DnsRData::TSIG {
            algorithm_name,
            time_signed,
            fudge,
            mac,
            original_id,
            error,
            other_data,
        })
    }

    fn parse_tlsa(rdata: &[u8]) -> Result<Self, FieldError> {
        if rdata.len() < 3 {
            return Err(FieldError::BufferTooShort {
                offset: 0,
                need: 3,
                have: rdata.len(),
            });
        }

        let usage = rdata[0];
        let selector = rdata[1];
        let matching_type = rdata[2];
        let cert_data = rdata[3..].to_vec();

        Ok(DnsRData::TLSA {
            usage,
            selector,
            matching_type,
            cert_data,
        })
    }

    fn parse_opt(rdata: &[u8]) -> Result<Self, FieldError> {
        let options = EdnsOption::parse_all(rdata)?;
        Ok(DnsRData::OPT(options))
    }

    /// Parse a DNS character-string (length-prefixed byte string).
    /// Returns the data and total bytes consumed (including length byte).
    fn parse_character_string(data: &[u8], offset: usize) -> Result<(Vec<u8>, usize), FieldError> {
        if offset >= data.len() {
            return Err(FieldError::BufferTooShort {
                offset,
                need: 1,
                have: 0,
            });
        }
        let len = data[offset] as usize;
        if offset + 1 + len > data.len() {
            return Err(FieldError::BufferTooShort {
                offset: offset + 1,
                need: len,
                have: data.len() - offset - 1,
            });
        }
        Ok((data[offset + 1..offset + 1 + len].to_vec(), 1 + len))
    }

    // ========================================================================
    // Build (serialize) without compression
    // ========================================================================

    /// Serialize RDATA to wire format without DNS name compression.
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        match self {
            DnsRData::A(addr) => addr.octets().to_vec(),

            DnsRData::AAAA(addr) => addr.octets().to_vec(),

            DnsRData::NS(name)
            | DnsRData::CNAME(name)
            | DnsRData::PTR(name)
            | DnsRData::DNAME(name) => name.encode(),

            DnsRData::MX {
                preference,
                exchange,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&preference.to_be_bytes());
                out.extend_from_slice(&exchange.encode());
                out
            },

            DnsRData::TXT(strings) => {
                let mut out = Vec::new();
                for s in strings {
                    out.push(s.len() as u8);
                    out.extend_from_slice(s);
                }
                out
            },

            DnsRData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&mname.encode());
                out.extend_from_slice(&rname.encode());
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
                out
            },

            DnsRData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                out.extend_from_slice(&target.encode());
                out
            },

            DnsRData::HINFO { cpu, os } => {
                let mut out = Vec::new();
                out.push(cpu.len() as u8);
                out.extend_from_slice(cpu);
                out.push(os.len() as u8);
                out.extend_from_slice(os);
                out
            },

            DnsRData::NAPTR {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&order.to_be_bytes());
                out.extend_from_slice(&preference.to_be_bytes());
                out.push(flags.len() as u8);
                out.extend_from_slice(flags);
                out.push(services.len() as u8);
                out.extend_from_slice(services);
                out.push(regexp.len() as u8);
                out.extend_from_slice(regexp);
                out.extend_from_slice(&replacement.encode());
                out
            },

            DnsRData::SVCB {
                priority,
                target,
                params,
            }
            | DnsRData::HTTPS {
                priority,
                target,
                params,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&target.encode());
                for p in params {
                    out.extend_from_slice(&p.build());
                }
                out
            },

            DnsRData::CAA { flags, tag, value } => {
                let mut out = Vec::new();
                out.push(*flags);
                out.push(tag.len() as u8);
                out.extend_from_slice(tag.as_bytes());
                out.extend_from_slice(value);
                out
            },

            DnsRData::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                sig_expiration,
                sig_inception,
                key_tag,
                signer_name,
                signature,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&type_covered.to_be_bytes());
                out.push(*algorithm);
                out.push(*labels);
                out.extend_from_slice(&original_ttl.to_be_bytes());
                out.extend_from_slice(&sig_expiration.to_be_bytes());
                out.extend_from_slice(&sig_inception.to_be_bytes());
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.extend_from_slice(&signer_name.encode());
                out.extend_from_slice(signature);
                out
            },

            DnsRData::NSEC {
                next_domain,
                type_bitmaps,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&next_domain.encode());
                out.extend_from_slice(&bitmap::rr_list_to_bitmap(type_bitmaps));
                out
            },

            DnsRData::NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_hashed,
                type_bitmaps,
            } => {
                let mut out = Vec::new();
                out.push(*hash_algorithm);
                out.push(*flags);
                out.extend_from_slice(&iterations.to_be_bytes());
                out.push(salt.len() as u8);
                out.extend_from_slice(salt);
                out.push(next_hashed.len() as u8);
                out.extend_from_slice(next_hashed);
                out.extend_from_slice(&bitmap::rr_list_to_bitmap(type_bitmaps));
                out
            },

            DnsRData::NSEC3PARAM {
                hash_algorithm,
                flags,
                iterations,
                salt,
            } => {
                let mut out = Vec::new();
                out.push(*hash_algorithm);
                out.push(*flags);
                out.extend_from_slice(&iterations.to_be_bytes());
                out.push(salt.len() as u8);
                out.extend_from_slice(salt);
                out
            },

            DnsRData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&flags.to_be_bytes());
                out.push(*protocol);
                out.push(*algorithm);
                out.extend_from_slice(public_key);
                out
            },

            DnsRData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            }
            | DnsRData::DLV {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&key_tag.to_be_bytes());
                out.push(*algorithm);
                out.push(*digest_type);
                out.extend_from_slice(digest);
                out
            },

            DnsRData::TSIG {
                algorithm_name,
                time_signed,
                fudge,
                mac,
                original_id,
                error,
                other_data,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&algorithm_name.encode());
                // Time signed: 48 bits (6 bytes)
                out.push((time_signed >> 40) as u8);
                out.push((time_signed >> 32) as u8);
                out.push((time_signed >> 24) as u8);
                out.push((time_signed >> 16) as u8);
                out.push((time_signed >> 8) as u8);
                out.push(*time_signed as u8);
                out.extend_from_slice(&fudge.to_be_bytes());
                out.extend_from_slice(&(mac.len() as u16).to_be_bytes());
                out.extend_from_slice(mac);
                out.extend_from_slice(&original_id.to_be_bytes());
                out.extend_from_slice(&error.to_be_bytes());
                out.extend_from_slice(&(other_data.len() as u16).to_be_bytes());
                out.extend_from_slice(other_data);
                out
            },

            DnsRData::TLSA {
                usage,
                selector,
                matching_type,
                cert_data,
            } => {
                let mut out = Vec::new();
                out.push(*usage);
                out.push(*selector);
                out.push(*matching_type);
                out.extend_from_slice(cert_data);
                out
            },

            DnsRData::OPT(options) => {
                let mut out = Vec::new();
                for opt in options {
                    out.extend_from_slice(&opt.build());
                }
                out
            },

            DnsRData::Unknown { data, .. } => data.clone(),
        }
    }

    // ========================================================================
    // Build with compression
    // ========================================================================

    /// Serialize RDATA to wire format with DNS name compression.
    ///
    /// # Arguments
    /// * `offset` - Byte offset where this RDATA will be placed in the packet.
    ///   Used to record name positions in the compression map.
    /// * `map` - Compression map tracking previously written domain names and
    ///   their offsets.
    pub fn build_compressed(&self, offset: usize, map: &mut HashMap<String, u16>) -> Vec<u8> {
        match self {
            DnsRData::NS(name)
            | DnsRData::CNAME(name)
            | DnsRData::PTR(name)
            | DnsRData::DNAME(name) => name.encode_compressed(offset, map),

            DnsRData::MX {
                preference,
                exchange,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&preference.to_be_bytes());
                let name_bytes = exchange.encode_compressed(offset + 2, map);
                out.extend_from_slice(&name_bytes);
                out
            },

            DnsRData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                let mut out = Vec::new();
                let mname_bytes = mname.encode_compressed(offset, map);
                out.extend_from_slice(&mname_bytes);
                let rname_bytes = rname.encode_compressed(offset + mname_bytes.len(), map);
                out.extend_from_slice(&rname_bytes);
                out.extend_from_slice(&serial.to_be_bytes());
                out.extend_from_slice(&refresh.to_be_bytes());
                out.extend_from_slice(&retry.to_be_bytes());
                out.extend_from_slice(&expire.to_be_bytes());
                out.extend_from_slice(&minimum.to_be_bytes());
                out
            },

            DnsRData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&priority.to_be_bytes());
                out.extend_from_slice(&weight.to_be_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                // RFC 2782: SRV target MUST NOT use compression
                out.extend_from_slice(&target.encode());
                out
            },

            DnsRData::NAPTR {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&order.to_be_bytes());
                out.extend_from_slice(&preference.to_be_bytes());
                out.push(flags.len() as u8);
                out.extend_from_slice(flags);
                out.push(services.len() as u8);
                out.extend_from_slice(services);
                out.push(regexp.len() as u8);
                out.extend_from_slice(regexp);
                let name_bytes = replacement.encode_compressed(offset + out.len(), map);
                out.extend_from_slice(&name_bytes);
                out
            },

            DnsRData::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                sig_expiration,
                sig_inception,
                key_tag,
                signer_name,
                signature,
            } => {
                let mut out = Vec::new();
                out.extend_from_slice(&type_covered.to_be_bytes());
                out.push(*algorithm);
                out.push(*labels);
                out.extend_from_slice(&original_ttl.to_be_bytes());
                out.extend_from_slice(&sig_expiration.to_be_bytes());
                out.extend_from_slice(&sig_inception.to_be_bytes());
                out.extend_from_slice(&key_tag.to_be_bytes());
                // RFC 4034: signer name MUST NOT use compression in DNSSEC
                // However, some implementations do. We support it for flexibility.
                let name_bytes = signer_name.encode_compressed(offset + out.len(), map);
                out.extend_from_slice(&name_bytes);
                out.extend_from_slice(signature);
                out
            },

            DnsRData::NSEC {
                next_domain,
                type_bitmaps,
            } => {
                let mut out = Vec::new();
                // RFC 4034: NSEC next domain MUST NOT use compression
                out.extend_from_slice(&next_domain.encode());
                out.extend_from_slice(&bitmap::rr_list_to_bitmap(type_bitmaps));
                out
            },

            // For SVCB/HTTPS, the target name MUST NOT be compressed per RFC 9460
            DnsRData::SVCB { .. } | DnsRData::HTTPS { .. } => self.build(),

            // These types do not contain compressible names
            _ => self.build(),
        }
    }

    // ========================================================================
    // Summary
    // ========================================================================

    /// Get a human-readable summary of this RDATA.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            DnsRData::A(addr) => addr.to_string(),

            DnsRData::AAAA(addr) => addr.to_string(),

            DnsRData::NS(name) => format!("NS {name}"),

            DnsRData::CNAME(name) => format!("CNAME {name}"),

            DnsRData::PTR(name) => format!("PTR {name}"),

            DnsRData::DNAME(name) => format!("DNAME {name}"),

            DnsRData::MX {
                preference,
                exchange,
            } => {
                format!("MX {preference} {exchange}")
            },

            DnsRData::TXT(strings) => {
                let parts: Vec<String> = strings
                    .iter()
                    .map(|s| format!("\"{}\"", String::from_utf8_lossy(s)))
                    .collect();
                format!("TXT {}", parts.join(" "))
            },

            DnsRData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                format!("SOA {mname} {rname} {serial} {refresh} {retry} {expire} {minimum}")
            },

            DnsRData::SRV {
                priority,
                weight,
                port,
                target,
            } => {
                format!("SRV {priority} {weight} {port} {target}")
            },

            DnsRData::HINFO { cpu, os } => {
                format!(
                    "HINFO \"{}\" \"{}\"",
                    String::from_utf8_lossy(cpu),
                    String::from_utf8_lossy(os)
                )
            },

            DnsRData::NAPTR {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                format!(
                    "NAPTR {} {} \"{}\" \"{}\" \"{}\" {}",
                    order,
                    preference,
                    String::from_utf8_lossy(flags),
                    String::from_utf8_lossy(services),
                    String::from_utf8_lossy(regexp),
                    replacement
                )
            },

            DnsRData::SVCB {
                priority,
                target,
                params,
            } => {
                let param_strs: Vec<String> = params
                    .iter()
                    .map(|p| {
                        let val = p.build_value();
                        format!("key{}={} bytes", p.key(), val.len())
                    })
                    .collect();
                format!("SVCB {} {} {}", priority, target, param_strs.join(" "))
            },

            DnsRData::HTTPS {
                priority,
                target,
                params,
            } => {
                let param_strs: Vec<String> = params
                    .iter()
                    .map(|p| {
                        let val = p.build_value();
                        format!("key{}={} bytes", p.key(), val.len())
                    })
                    .collect();
                format!("HTTPS {} {} {}", priority, target, param_strs.join(" "))
            },

            DnsRData::CAA { flags, tag, value } => {
                format!(
                    "CAA {} {} \"{}\"",
                    flags,
                    tag,
                    String::from_utf8_lossy(value)
                )
            },

            DnsRData::RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                key_tag,
                signer_name,
                ..
            } => {
                format!(
                    "RRSIG {} {} {} {} {} {}",
                    types::dns_type_name(*type_covered),
                    algorithm,
                    labels,
                    original_ttl,
                    key_tag,
                    signer_name
                )
            },

            DnsRData::NSEC {
                next_domain,
                type_bitmaps,
            } => {
                let type_names: Vec<&str> = type_bitmaps
                    .iter()
                    .map(|t| types::dns_type_name(*t))
                    .collect();
                format!("NSEC {} [{}]", next_domain, type_names.join(" "))
            },

            DnsRData::NSEC3 {
                hash_algorithm,
                iterations,
                next_hashed,
                type_bitmaps,
                ..
            } => {
                let type_names: Vec<&str> = type_bitmaps
                    .iter()
                    .map(|t| types::dns_type_name(*t))
                    .collect();
                format!(
                    "NSEC3 alg={} iter={} hash={} [{}]",
                    hash_algorithm,
                    iterations,
                    hex(next_hashed),
                    type_names.join(" ")
                )
            },

            DnsRData::NSEC3PARAM {
                hash_algorithm,
                flags,
                iterations,
                salt,
            } => {
                format!(
                    "NSEC3PARAM alg={} flags={} iter={} salt={}",
                    hash_algorithm,
                    flags,
                    iterations,
                    if salt.is_empty() {
                        "-".to_string()
                    } else {
                        hex(salt)
                    }
                )
            },

            DnsRData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                format!(
                    "DNSKEY flags={} proto={} alg={} key={} bytes",
                    flags,
                    protocol,
                    algorithm,
                    public_key.len()
                )
            },

            DnsRData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                format!(
                    "DS {} {} {} {}",
                    key_tag,
                    algorithm,
                    digest_type,
                    hex(digest)
                )
            },

            DnsRData::DLV {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                format!(
                    "DLV {} {} {} {}",
                    key_tag,
                    algorithm,
                    digest_type,
                    hex(digest)
                )
            },

            DnsRData::TSIG {
                algorithm_name,
                original_id,
                error,
                mac,
                ..
            } => {
                format!(
                    "TSIG {} id={} err={} mac={} bytes",
                    algorithm_name,
                    original_id,
                    error,
                    mac.len()
                )
            },

            DnsRData::TLSA {
                usage,
                selector,
                matching_type,
                cert_data,
            } => {
                format!(
                    "TLSA {} {} {} {} bytes",
                    usage,
                    selector,
                    matching_type,
                    cert_data.len()
                )
            },

            DnsRData::OPT(options) => {
                if options.is_empty() {
                    "OPT (empty)".to_string()
                } else {
                    let summaries: Vec<String> = options
                        .iter()
                        .map(super::edns::EdnsOption::summary)
                        .collect();
                    format!("OPT [{}]", summaries.join(", "))
                }
            },

            DnsRData::Unknown { rtype, data } => {
                format!("TYPE{} ({} bytes)", rtype, data.len())
            },
        }
    }
}

/// Convert bytes to a hex string.
fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build RDATA, then parse it back, treating the built bytes as
    /// both the packet and the RDATA region (no compression pointers needed
    /// for uncompressed names).
    fn roundtrip(rtype: u16, rdata: &DnsRData) -> DnsRData {
        let built = rdata.build();
        DnsRData::parse(rtype, &built, 0, built.len() as u16).unwrap()
    }

    // ====================================================================
    // A record
    // ====================================================================

    #[test]
    fn test_a_parse() {
        let wire = [192, 0, 2, 1]; // 192.0.2.1
        let rdata = DnsRData::parse(rr_type::A, &wire, 0, 4).unwrap();
        assert_eq!(rdata, DnsRData::A(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn test_a_build_roundtrip() {
        let original = DnsRData::A(Ipv4Addr::new(10, 0, 0, 1));
        let result = roundtrip(rr_type::A, &original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_a_invalid_length() {
        let wire = [192, 0, 2]; // 3 bytes instead of 4
        assert!(DnsRData::parse(rr_type::A, &wire, 0, 3).is_err());
    }

    // ====================================================================
    // AAAA record
    // ====================================================================

    #[test]
    fn test_aaaa_parse() {
        let wire = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        let rdata = DnsRData::parse(rr_type::AAAA, &wire, 0, 16).unwrap();
        assert_eq!(rdata, DnsRData::AAAA("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_aaaa_build_roundtrip() {
        let original = DnsRData::AAAA("::1".parse().unwrap());
        let result = roundtrip(rr_type::AAAA, &original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_aaaa_invalid_length() {
        let wire = [0u8; 15]; // 15 bytes instead of 16
        assert!(DnsRData::parse(rr_type::AAAA, &wire, 0, 15).is_err());
    }

    // ====================================================================
    // MX record
    // ====================================================================

    #[test]
    fn test_mx_parse() {
        // preference=10, exchange=mail.example.com
        let mut wire = Vec::new();
        wire.extend_from_slice(&10u16.to_be_bytes());
        wire.extend_from_slice(&DnsName::from("mail.example.com").encode());
        let rdlen = wire.len() as u16;

        let rdata = DnsRData::parse(rr_type::MX, &wire, 0, rdlen).unwrap();
        match &rdata {
            DnsRData::MX {
                preference,
                exchange,
            } => {
                assert_eq!(*preference, 10);
                assert_eq!(exchange.to_fqdn(), "mail.example.com.");
            },
            _ => panic!("expected MX, got {:?}", rdata),
        }
    }

    #[test]
    fn test_mx_build_roundtrip() {
        let original = DnsRData::MX {
            preference: 20,
            exchange: DnsName::from("mx.test.org"),
        };
        let result = roundtrip(rr_type::MX, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // TXT record
    // ====================================================================

    #[test]
    fn test_txt_single_string() {
        let text = b"v=spf1 include:example.com ~all";
        let mut wire = Vec::new();
        wire.push(text.len() as u8);
        wire.extend_from_slice(text);
        let rdlen = wire.len() as u16;

        let rdata = DnsRData::parse(rr_type::TXT, &wire, 0, rdlen).unwrap();
        match &rdata {
            DnsRData::TXT(strings) => {
                assert_eq!(strings.len(), 1);
                assert_eq!(strings[0], text.to_vec());
            },
            _ => panic!("expected TXT"),
        }
    }

    #[test]
    fn test_txt_multiple_strings() {
        let s1 = b"hello";
        let s2 = b"world";
        let mut wire = Vec::new();
        wire.push(s1.len() as u8);
        wire.extend_from_slice(s1);
        wire.push(s2.len() as u8);
        wire.extend_from_slice(s2);
        let rdlen = wire.len() as u16;

        let rdata = DnsRData::parse(rr_type::TXT, &wire, 0, rdlen).unwrap();
        match &rdata {
            DnsRData::TXT(strings) => {
                assert_eq!(strings.len(), 2);
                assert_eq!(strings[0], s1.to_vec());
                assert_eq!(strings[1], s2.to_vec());
            },
            _ => panic!("expected TXT"),
        }
    }

    #[test]
    fn test_txt_zero_length_string() {
        let mut wire = Vec::new();
        wire.push(0); // zero-length string
        wire.push(5); // "hello"
        wire.extend_from_slice(b"hello");
        let rdlen = wire.len() as u16;

        let rdata = DnsRData::parse(rr_type::TXT, &wire, 0, rdlen).unwrap();
        match &rdata {
            DnsRData::TXT(strings) => {
                assert_eq!(strings.len(), 2);
                assert!(strings[0].is_empty());
                assert_eq!(strings[1], b"hello".to_vec());
            },
            _ => panic!("expected TXT"),
        }
    }

    #[test]
    fn test_txt_build_roundtrip() {
        let original = DnsRData::TXT(vec![
            b"first".to_vec(),
            Vec::new(), // empty string
            b"third".to_vec(),
        ]);
        let result = roundtrip(rr_type::TXT, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // SOA record
    // ====================================================================

    #[test]
    fn test_soa_parse_and_roundtrip() {
        let original = DnsRData::SOA {
            mname: DnsName::from("ns1.example.com"),
            rname: DnsName::from("admin.example.com"),
            serial: 2024010101,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 86400,
        };
        let result = roundtrip(rr_type::SOA, &original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_soa_with_compressed_names() {
        // Build a fake packet where SOA names share a suffix with an earlier name.
        // First, write "example.com" name, then the SOA RDATA with compressed names.
        let example_name = DnsName::from("example.com");
        let mut packet = example_name.encode(); // offset 0: "example.com"
        let rdata_offset = packet.len();

        // SOA MNAME: ns1.example.com (with "example.com" compressed to pointer 0)
        let mut compression_map = HashMap::new();
        compression_map.insert("example.com".to_string(), 0u16);

        let mname = DnsName::from("ns1.example.com");
        let mname_bytes = mname.encode_compressed(rdata_offset, &mut compression_map);
        packet.extend_from_slice(&mname_bytes);

        let rname = DnsName::from("admin.example.com");
        let rname_offset = rdata_offset + mname_bytes.len();
        let rname_bytes = rname.encode_compressed(rname_offset, &mut compression_map);
        packet.extend_from_slice(&rname_bytes);

        // Fixed fields
        packet.extend_from_slice(&2024010101u32.to_be_bytes());
        packet.extend_from_slice(&3600u32.to_be_bytes());
        packet.extend_from_slice(&900u32.to_be_bytes());
        packet.extend_from_slice(&604800u32.to_be_bytes());
        packet.extend_from_slice(&86400u32.to_be_bytes());

        let rdlen = (packet.len() - rdata_offset) as u16;
        let rdata = DnsRData::parse(rr_type::SOA, &packet, rdata_offset, rdlen).unwrap();

        match &rdata {
            DnsRData::SOA {
                mname,
                rname,
                serial,
                ..
            } => {
                assert_eq!(mname.to_fqdn(), "ns1.example.com.");
                assert_eq!(rname.to_fqdn(), "admin.example.com.");
                assert_eq!(*serial, 2024010101);
            },
            _ => panic!("expected SOA"),
        }
    }

    // ====================================================================
    // SRV record
    // ====================================================================

    #[test]
    fn test_srv_build_roundtrip() {
        let original = DnsRData::SRV {
            priority: 10,
            weight: 60,
            port: 5060,
            target: DnsName::from("sipserver.example.com"),
        };
        let result = roundtrip(rr_type::SRV, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // CNAME / NS / PTR
    // ====================================================================

    #[test]
    fn test_cname_roundtrip() {
        let original = DnsRData::CNAME(DnsName::from("www.example.com"));
        let result = roundtrip(rr_type::CNAME, &original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_ns_roundtrip() {
        let original = DnsRData::NS(DnsName::from("ns1.example.com"));
        let result = roundtrip(rr_type::NS, &original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_ptr_roundtrip() {
        let original = DnsRData::PTR(DnsName::from("1.2.0.192.in-addr.arpa"));
        let result = roundtrip(rr_type::PTR, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // HINFO record
    // ====================================================================

    #[test]
    fn test_hinfo_roundtrip() {
        let original = DnsRData::HINFO {
            cpu: b"x86_64".to_vec(),
            os: b"Linux".to_vec(),
        };
        let result = roundtrip(rr_type::HINFO, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // CAA record
    // ====================================================================

    #[test]
    fn test_caa_roundtrip() {
        let original = DnsRData::CAA {
            flags: 0,
            tag: "issue".to_string(),
            value: b"letsencrypt.org".to_vec(),
        };
        let result = roundtrip(rr_type::CAA, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // DNSKEY record
    // ====================================================================

    #[test]
    fn test_dnskey_roundtrip() {
        let original = DnsRData::DNSKEY {
            flags: 257,    // KSK
            protocol: 3,   // DNSSEC
            algorithm: 13, // ECDSAP256SHA256
            public_key: vec![0x01, 0x02, 0x03, 0x04],
        };
        let result = roundtrip(rr_type::DNSKEY, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // DS record
    // ====================================================================

    #[test]
    fn test_ds_roundtrip() {
        let original = DnsRData::DS {
            key_tag: 12345,
            algorithm: 8,
            digest_type: 2,
            digest: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };
        let result = roundtrip(rr_type::DS, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // NSEC record
    // ====================================================================

    #[test]
    fn test_nsec_roundtrip() {
        let original = DnsRData::NSEC {
            next_domain: DnsName::from("next.example.com"),
            type_bitmaps: vec![1, 2, 5, 6, 15, 16, 28, 46, 47], // A NS CNAME SOA MX TXT AAAA RRSIG NSEC
        };
        let result = roundtrip(rr_type::NSEC, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // NSEC3 record
    // ====================================================================

    #[test]
    fn test_nsec3_roundtrip() {
        let original = DnsRData::NSEC3 {
            hash_algorithm: 1,
            flags: 0,
            iterations: 10,
            salt: vec![0xAA, 0xBB],
            next_hashed: vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
            type_bitmaps: vec![1, 28], // A AAAA
        };
        let result = roundtrip(rr_type::NSEC3, &original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_nsec3_empty_salt() {
        let original = DnsRData::NSEC3 {
            hash_algorithm: 1,
            flags: 1,
            iterations: 0,
            salt: Vec::new(),
            next_hashed: vec![0x01, 0x02, 0x03, 0x04],
            type_bitmaps: vec![1],
        };
        let result = roundtrip(rr_type::NSEC3, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // NSEC3PARAM record
    // ====================================================================

    #[test]
    fn test_nsec3param_roundtrip() {
        let original = DnsRData::NSEC3PARAM {
            hash_algorithm: 1,
            flags: 0,
            iterations: 10,
            salt: vec![0xDE, 0xAD],
        };
        let result = roundtrip(rr_type::NSEC3PARAM, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // RRSIG record
    // ====================================================================

    #[test]
    fn test_rrsig_roundtrip() {
        let original = DnsRData::RRSIG {
            type_covered: rr_type::A,
            algorithm: 8,
            labels: 3,
            original_ttl: 3600,
            sig_expiration: 1700000000,
            sig_inception: 1690000000,
            key_tag: 54321,
            signer_name: DnsName::from("example.com"),
            signature: vec![0x01, 0x02, 0x03, 0x04, 0x05],
        };
        let result = roundtrip(rr_type::RRSIG, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // TLSA record
    // ====================================================================

    #[test]
    fn test_tlsa_roundtrip() {
        let original = DnsRData::TLSA {
            usage: 3,         // DANE-EE
            selector: 1,      // SPKI
            matching_type: 1, // SHA-256
            cert_data: vec![0xAB; 32],
        };
        let result = roundtrip(rr_type::TLSA, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // NAPTR record
    // ====================================================================

    #[test]
    fn test_naptr_roundtrip() {
        let original = DnsRData::NAPTR {
            order: 100,
            preference: 10,
            flags: b"s".to_vec(),
            services: b"SIP+D2T".to_vec(),
            regexp: Vec::new(),
            replacement: DnsName::from("_sip._tcp.example.com"),
        };
        let result = roundtrip(rr_type::NAPTR, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // SVCB / HTTPS records
    // ====================================================================

    #[test]
    fn test_svcb_roundtrip() {
        let original = DnsRData::SVCB {
            priority: 1,
            target: DnsName::from("svc.example.com"),
            params: vec![SvcParam::Alpn(vec!["h2".to_string()]), SvcParam::Port(443)],
        };
        let result = roundtrip(rr_type::SVCB, &original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_https_roundtrip() {
        let original = DnsRData::HTTPS {
            priority: 1,
            target: DnsName::root(),
            params: vec![SvcParam::Alpn(vec!["h2".to_string(), "h3".to_string()])],
        };
        let result = roundtrip(rr_type::HTTPS, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // OPT record
    // ====================================================================

    #[test]
    fn test_opt_roundtrip() {
        let original = DnsRData::OPT(vec![
            EdnsOption::NSID(b"my-ns".to_vec()),
            EdnsOption::Cookie {
                client: vec![1, 2, 3, 4, 5, 6, 7, 8],
                server: vec![11, 12, 13, 14, 15, 16, 17, 18],
            },
        ]);
        let result = roundtrip(rr_type::OPT, &original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_opt_empty() {
        let original = DnsRData::OPT(vec![]);
        let result = roundtrip(rr_type::OPT, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // TSIG record
    // ====================================================================

    #[test]
    fn test_tsig_roundtrip() {
        let original = DnsRData::TSIG {
            algorithm_name: DnsName::from("hmac-sha256"),
            time_signed: 1700000000,
            fudge: 300,
            mac: vec![0xAA; 32],
            original_id: 0x1234,
            error: 0,
            other_data: Vec::new(),
        };
        let result = roundtrip(rr_type::TSIG, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // DLV record
    // ====================================================================

    #[test]
    fn test_dlv_roundtrip() {
        let original = DnsRData::DLV {
            key_tag: 9999,
            algorithm: 13,
            digest_type: 2,
            digest: vec![0x11, 0x22, 0x33, 0x44],
        };
        let result = roundtrip(rr_type::DLV, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // DNAME record
    // ====================================================================

    #[test]
    fn test_dname_roundtrip() {
        let original = DnsRData::DNAME(DnsName::from("target.example.com"));
        let result = roundtrip(rr_type::DNAME, &original);
        assert_eq!(result, original);
    }

    // ====================================================================
    // Unknown record
    // ====================================================================

    #[test]
    fn test_unknown_roundtrip() {
        let original = DnsRData::Unknown {
            rtype: 9999,
            data: vec![0x01, 0x02, 0x03],
        };
        let built = original.build();
        let parsed = DnsRData::parse(9999, &built, 0, built.len() as u16).unwrap();
        assert_eq!(parsed, original);
    }

    // ====================================================================
    // Compression tests
    // ====================================================================

    #[test]
    fn test_mx_compressed() {
        let rdata = DnsRData::MX {
            preference: 10,
            exchange: DnsName::from("mail.example.com"),
        };

        let mut map = HashMap::new();
        // Pretend "example.com" was written at offset 20
        map.insert("example.com".to_string(), 20u16);

        let compressed = rdata.build_compressed(100, &mut map);
        let uncompressed = rdata.build();

        // Compressed should be shorter because "example.com" is replaced by a pointer
        assert!(compressed.len() < uncompressed.len());

        // Preference should still be at the start
        assert_eq!(u16::from_be_bytes([compressed[0], compressed[1]]), 10);
    }

    #[test]
    fn test_soa_compressed() {
        let rdata = DnsRData::SOA {
            mname: DnsName::from("ns1.example.com"),
            rname: DnsName::from("admin.example.com"),
            serial: 1,
            refresh: 2,
            retry: 3,
            expire: 4,
            minimum: 5,
        };

        let mut map = HashMap::new();
        let compressed = rdata.build_compressed(0, &mut map);

        // After writing mname, "example.com" should be in the map,
        // so rname should compress "example.com" part.
        let uncompressed = rdata.build();
        assert!(compressed.len() < uncompressed.len());
    }

    // ====================================================================
    // Summary tests
    // ====================================================================

    #[test]
    fn test_summary_a() {
        let rdata = DnsRData::A(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(rdata.summary(), "1.2.3.4");
    }

    #[test]
    fn test_summary_aaaa() {
        let rdata = DnsRData::AAAA("::1".parse().unwrap());
        assert_eq!(rdata.summary(), "::1");
    }

    #[test]
    fn test_summary_mx() {
        let rdata = DnsRData::MX {
            preference: 10,
            exchange: DnsName::from("mail.example.com"),
        };
        assert_eq!(rdata.summary(), "MX 10 mail.example.com.");
    }

    #[test]
    fn test_summary_txt() {
        let rdata = DnsRData::TXT(vec![b"hello world".to_vec()]);
        assert_eq!(rdata.summary(), "TXT \"hello world\"");
    }

    #[test]
    fn test_summary_unknown() {
        let rdata = DnsRData::Unknown {
            rtype: 9999,
            data: vec![0; 10],
        };
        assert_eq!(rdata.summary(), "TYPE9999 (10 bytes)");
    }
}
