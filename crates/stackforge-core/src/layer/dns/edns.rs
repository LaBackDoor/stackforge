//! EDNS0 (Extension Mechanisms for DNS) option types.
//!
//! Implements RFC 6891 (EDNS0), RFC 7871 (Client Subnet), RFC 7873 (Cookies),
//! RFC 8914 (Extended DNS Errors), and other EDNS0 options.

use crate::layer::field::FieldError;
use crate::layer::field::MacAddress;

/// EDNS0 option parsed from OPT record RDATA.
#[derive(Debug, Clone, PartialEq)]
pub enum EdnsOption {
    /// NSID - Name Server Identifier (RFC 5001)
    NSID(Vec<u8>),

    /// DAU - DNSSEC Algorithm Understood (RFC 6975)
    DAU(Vec<u8>),

    /// DHU - DS Hash Understood (RFC 6975)
    DHU(Vec<u8>),

    /// N3U - NSEC3 Hash Understood (RFC 6975)
    N3U(Vec<u8>),

    /// Client Subnet (RFC 7871)
    ClientSubnet {
        family: u16, // 1=IPv4, 2=IPv6
        source_prefix: u8,
        scope_prefix: u8,
        address: Vec<u8>,
    },

    /// DNS Cookie (RFC 7873)
    Cookie {
        client: Vec<u8>, // 8 bytes
        server: Vec<u8>, // 0 or 8-32 bytes
    },

    /// Extended DNS Error (RFC 8914)
    ExtendedDnsError { info_code: u16, extra_text: String },

    /// Owner option (Apple mDNS)
    Owner {
        version: u8,
        seq: u8,
        primary_mac: MacAddress,
    },

    /// Unknown/unsupported option
    Unknown { code: u16, data: Vec<u8> },
}

/// EDNS0 option codes
pub mod option_code {
    pub const LLQ: u16 = 1;
    pub const UL: u16 = 2;
    pub const NSID: u16 = 3;
    pub const OWNER: u16 = 4;
    pub const DAU: u16 = 5;
    pub const DHU: u16 = 6;
    pub const N3U: u16 = 7;
    pub const CLIENT_SUBNET: u16 = 8;
    pub const COOKIE: u16 = 10;
    pub const TCP_KEEPALIVE: u16 = 11;
    pub const PADDING: u16 = 12;
    pub const CHAIN: u16 = 13;
    pub const KEY_TAG: u16 = 14;
    pub const EXTENDED_DNS_ERROR: u16 = 15;
}

/// Extended DNS Error info codes (RFC 8914)
pub mod ede_code {
    pub const OTHER: u16 = 0;
    pub const UNSUPPORTED_DNSKEY_ALGORITHM: u16 = 1;
    pub const UNSUPPORTED_DS_DIGEST_TYPE: u16 = 2;
    pub const STALE_ANSWER: u16 = 3;
    pub const FORGED_ANSWER: u16 = 4;
    pub const DNSSEC_INDETERMINATE: u16 = 5;
    pub const DNSSEC_BOGUS: u16 = 6;
    pub const SIGNATURE_EXPIRED: u16 = 7;
    pub const SIGNATURE_NOT_YET_VALID: u16 = 8;
    pub const DNSKEY_MISSING: u16 = 9;
    pub const RRSIGS_MISSING: u16 = 10;
    pub const NO_ZONE_KEY_BIT_SET: u16 = 11;
    pub const NSEC_MISSING: u16 = 12;
    pub const CACHED_ERROR: u16 = 13;
    pub const NOT_READY: u16 = 14;
    pub const BLOCKED: u16 = 15;
    pub const CENSORED: u16 = 16;
    pub const FILTERED: u16 = 17;
    pub const PROHIBITED: u16 = 18;
    pub const STALE_NXDOMAIN_ANSWER: u16 = 19;
    pub const NOT_AUTHORITATIVE: u16 = 20;
    pub const NOT_SUPPORTED: u16 = 21;
    pub const NO_REACHABLE_AUTHORITY: u16 = 22;
    pub const NETWORK_ERROR: u16 = 23;
    pub const INVALID_DATA: u16 = 24;
}

impl EdnsOption {
    /// Parse a single EDNS0 option from wire format.
    /// `data` contains the option data (after code and length).
    pub fn parse(code: u16, data: &[u8]) -> Result<Self, FieldError> {
        match code {
            option_code::NSID => Ok(EdnsOption::NSID(data.to_vec())),

            option_code::DAU => Ok(EdnsOption::DAU(data.to_vec())),

            option_code::DHU => Ok(EdnsOption::DHU(data.to_vec())),

            option_code::N3U => Ok(EdnsOption::N3U(data.to_vec())),

            option_code::CLIENT_SUBNET => {
                if data.len() < 4 {
                    return Err(FieldError::BufferTooShort {
                        offset: 0,
                        need: 4,
                        have: data.len(),
                    });
                }
                let family = u16::from_be_bytes([data[0], data[1]]);
                let source_prefix = data[2];
                let scope_prefix = data[3];
                let address = data[4..].to_vec();
                Ok(EdnsOption::ClientSubnet {
                    family,
                    source_prefix,
                    scope_prefix,
                    address,
                })
            },

            option_code::COOKIE => {
                if data.len() < 8 {
                    return Err(FieldError::BufferTooShort {
                        offset: 0,
                        need: 8,
                        have: data.len(),
                    });
                }
                let client = data[..8].to_vec();
                let server = if data.len() > 8 {
                    data[8..].to_vec()
                } else {
                    Vec::new()
                };
                Ok(EdnsOption::Cookie { client, server })
            },

            option_code::EXTENDED_DNS_ERROR => {
                if data.len() < 2 {
                    return Err(FieldError::BufferTooShort {
                        offset: 0,
                        need: 2,
                        have: data.len(),
                    });
                }
                let info_code = u16::from_be_bytes([data[0], data[1]]);
                let extra_text = if data.len() > 2 {
                    String::from_utf8_lossy(&data[2..]).into_owned()
                } else {
                    String::new()
                };
                Ok(EdnsOption::ExtendedDnsError {
                    info_code,
                    extra_text,
                })
            },

            option_code::OWNER => {
                if data.len() < 8 {
                    return Err(FieldError::BufferTooShort {
                        offset: 0,
                        need: 8,
                        have: data.len(),
                    });
                }
                let version = data[0];
                let seq = data[1];
                let primary_mac =
                    MacAddress::new([data[2], data[3], data[4], data[5], data[6], data[7]]);
                Ok(EdnsOption::Owner {
                    version,
                    seq,
                    primary_mac,
                })
            },

            _ => Ok(EdnsOption::Unknown {
                code,
                data: data.to_vec(),
            }),
        }
    }

    /// Get the option code for this EDNS0 option.
    pub fn code(&self) -> u16 {
        match self {
            EdnsOption::NSID(_) => option_code::NSID,
            EdnsOption::DAU(_) => option_code::DAU,
            EdnsOption::DHU(_) => option_code::DHU,
            EdnsOption::N3U(_) => option_code::N3U,
            EdnsOption::ClientSubnet { .. } => option_code::CLIENT_SUBNET,
            EdnsOption::Cookie { .. } => option_code::COOKIE,
            EdnsOption::ExtendedDnsError { .. } => option_code::EXTENDED_DNS_ERROR,
            EdnsOption::Owner { .. } => option_code::OWNER,
            EdnsOption::Unknown { code, .. } => *code,
        }
    }

    /// Serialize the option data (without the code and length header).
    pub fn build_data(&self) -> Vec<u8> {
        match self {
            EdnsOption::NSID(data) => data.clone(),
            EdnsOption::DAU(data) => data.clone(),
            EdnsOption::DHU(data) => data.clone(),
            EdnsOption::N3U(data) => data.clone(),
            EdnsOption::ClientSubnet {
                family,
                source_prefix,
                scope_prefix,
                address,
            } => {
                let mut out = Vec::with_capacity(4 + address.len());
                out.extend_from_slice(&family.to_be_bytes());
                out.push(*source_prefix);
                out.push(*scope_prefix);
                out.extend_from_slice(address);
                out
            },
            EdnsOption::Cookie { client, server } => {
                let mut out = Vec::with_capacity(client.len() + server.len());
                out.extend_from_slice(client);
                out.extend_from_slice(server);
                out
            },
            EdnsOption::ExtendedDnsError {
                info_code,
                extra_text,
            } => {
                let mut out = Vec::with_capacity(2 + extra_text.len());
                out.extend_from_slice(&info_code.to_be_bytes());
                out.extend_from_slice(extra_text.as_bytes());
                out
            },
            EdnsOption::Owner {
                version,
                seq,
                primary_mac,
            } => {
                let mut out = vec![*version, *seq];
                out.extend_from_slice(primary_mac.as_bytes());
                out
            },
            EdnsOption::Unknown { data, .. } => data.clone(),
        }
    }

    /// Build the complete TLV (code + length + data).
    pub fn build(&self) -> Vec<u8> {
        let data = self.build_data();
        let mut out = Vec::with_capacity(4 + data.len());
        out.extend_from_slice(&self.code().to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(&data);
        out
    }

    /// Parse all EDNS0 options from the OPT record RDATA.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, FieldError> {
        let mut options = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            if pos + 4 > data.len() {
                return Err(FieldError::BufferTooShort {
                    offset: pos,
                    need: 4,
                    have: data.len(),
                });
            }
            let code = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let opt_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + opt_len > data.len() {
                return Err(FieldError::BufferTooShort {
                    offset: pos,
                    need: opt_len,
                    have: data.len() - pos,
                });
            }

            let option = Self::parse(code, &data[pos..pos + opt_len])?;
            options.push(option);
            pos += opt_len;
        }

        Ok(options)
    }

    /// Summary string for display.
    pub fn summary(&self) -> String {
        match self {
            EdnsOption::NSID(data) => format!("NSID: {:?}", String::from_utf8_lossy(data)),
            EdnsOption::DAU(algs) => format!("DAU: {:?}", algs),
            EdnsOption::DHU(algs) => format!("DHU: {:?}", algs),
            EdnsOption::N3U(algs) => format!("N3U: {:?}", algs),
            EdnsOption::ClientSubnet {
                family,
                source_prefix,
                scope_prefix,
                ..
            } => {
                format!(
                    "ClientSubnet: family={} source=/{} scope=/{}",
                    family, source_prefix, scope_prefix
                )
            },
            EdnsOption::Cookie { client, server } => {
                format!("Cookie: client={} server={}", hex(client), hex(server))
            },
            EdnsOption::ExtendedDnsError {
                info_code,
                extra_text,
            } => {
                format!("EDE: code={} text={:?}", info_code, extra_text)
            },
            EdnsOption::Owner {
                version,
                seq,
                primary_mac,
            } => {
                format!("Owner: v={} seq={} mac={}", version, seq, primary_mac)
            },
            EdnsOption::Unknown { code, data } => {
                format!("Option({}): {} bytes", code, data.len())
            },
        }
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_subnet_parse() {
        // IPv4, source prefix /24, scope /0, address 192.168.1.0
        let data = vec![0x00, 0x01, 24, 0, 192, 168, 1];
        let opt = EdnsOption::parse(option_code::CLIENT_SUBNET, &data).unwrap();
        match opt {
            EdnsOption::ClientSubnet {
                family,
                source_prefix,
                scope_prefix,
                address,
            } => {
                assert_eq!(family, 1);
                assert_eq!(source_prefix, 24);
                assert_eq!(scope_prefix, 0);
                assert_eq!(address, vec![192, 168, 1]);
            },
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_client_subnet_roundtrip() {
        let opt = EdnsOption::ClientSubnet {
            family: 1,
            source_prefix: 24,
            scope_prefix: 0,
            address: vec![192, 168, 1],
        };
        let built = opt.build();
        assert_eq!(built[0..2], [0x00, 0x08]); // code = 8
        assert_eq!(built[2..4], [0x00, 0x07]); // length = 7
        let parsed = EdnsOption::parse(option_code::CLIENT_SUBNET, &built[4..]).unwrap();
        assert_eq!(parsed, opt);
    }

    #[test]
    fn test_cookie_parse() {
        let mut data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]; // client
        data.extend_from_slice(&[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]); // server
        let opt = EdnsOption::parse(option_code::COOKIE, &data).unwrap();
        match &opt {
            EdnsOption::Cookie { client, server } => {
                assert_eq!(client.len(), 8);
                assert_eq!(server.len(), 8);
            },
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_extended_dns_error_parse() {
        let mut data = vec![0x00, 0x06]; // DNSSEC Bogus
        data.extend_from_slice(b"signature verification failed");
        let opt = EdnsOption::parse(option_code::EXTENDED_DNS_ERROR, &data).unwrap();
        match opt {
            EdnsOption::ExtendedDnsError {
                info_code,
                extra_text,
            } => {
                assert_eq!(info_code, 6);
                assert_eq!(extra_text, "signature verification failed");
            },
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_dau_roundtrip() {
        let opt = EdnsOption::DAU(vec![8, 10, 13, 14]); // RSA/SHA-256, RSA/SHA-512, ECDSA P256, ECDSA P384
        let built = opt.build();
        let parsed_opts = EdnsOption::parse_all(&built).unwrap();
        assert_eq!(parsed_opts.len(), 1);
        assert_eq!(parsed_opts[0], opt);
    }

    #[test]
    fn test_parse_multiple_options() {
        let opt1 = EdnsOption::DAU(vec![8, 10]);
        let opt2 = EdnsOption::DHU(vec![1, 2]);
        let mut data = opt1.build();
        data.extend_from_slice(&opt2.build());

        let parsed = EdnsOption::parse_all(&data).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], opt1);
        assert_eq!(parsed[1], opt2);
    }

    #[test]
    fn test_unknown_option() {
        let opt = EdnsOption::parse(9999, &[0x01, 0x02, 0x03]).unwrap();
        match opt {
            EdnsOption::Unknown { code, data } => {
                assert_eq!(code, 9999);
                assert_eq!(data, vec![1, 2, 3]);
            },
            _ => panic!("wrong variant"),
        }
    }
}
