//! SVCB/HTTPS Service Parameters (RFC 9460).

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::layer::field::FieldError;

/// SVCB/HTTPS Service Parameter keys.
pub mod svc_key {
    pub const MANDATORY: u16 = 0;
    pub const ALPN: u16 = 1;
    pub const NO_DEFAULT_ALPN: u16 = 2;
    pub const PORT: u16 = 3;
    pub const IPV4HINT: u16 = 4;
    pub const ECH: u16 = 5;
    pub const IPV6HINT: u16 = 6;
}

/// A single service parameter from SVCB/HTTPS records.
#[derive(Debug, Clone, PartialEq)]
pub enum SvcParam {
    /// Mandatory keys that must be understood.
    Mandatory(Vec<u16>),
    /// Application-Layer Protocol Negotiation.
    Alpn(Vec<String>),
    /// No default ALPN (empty value).
    NoDefaultAlpn,
    /// Port number.
    Port(u16),
    /// IPv4 address hints.
    Ipv4Hint(Vec<Ipv4Addr>),
    /// Encrypted Client Hello.
    Ech(Vec<u8>),
    /// IPv6 address hints.
    Ipv6Hint(Vec<Ipv6Addr>),
    /// Unknown parameter.
    Unknown { key: u16, value: Vec<u8> },
}

impl SvcParam {
    /// Parse a single SvcParam from wire format.
    pub fn parse(key: u16, data: &[u8]) -> Result<Self, FieldError> {
        match key {
            svc_key::MANDATORY => {
                if data.len() % 2 != 0 {
                    return Err(FieldError::InvalidValue(
                        "mandatory param length must be even".to_string(),
                    ));
                }
                let keys: Vec<u16> = data
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                Ok(SvcParam::Mandatory(keys))
            }

            svc_key::ALPN => {
                let mut alpns = Vec::new();
                let mut pos = 0;
                while pos < data.len() {
                    let len = data[pos] as usize;
                    pos += 1;
                    if pos + len > data.len() {
                        return Err(FieldError::BufferTooShort {
                            offset: pos,
                            need: len,
                            have: data.len() - pos,
                        });
                    }
                    alpns.push(String::from_utf8_lossy(&data[pos..pos + len]).into_owned());
                    pos += len;
                }
                Ok(SvcParam::Alpn(alpns))
            }

            svc_key::NO_DEFAULT_ALPN => Ok(SvcParam::NoDefaultAlpn),

            svc_key::PORT => {
                if data.len() != 2 {
                    return Err(FieldError::InvalidValue(
                        "port param must be 2 bytes".to_string(),
                    ));
                }
                Ok(SvcParam::Port(u16::from_be_bytes([data[0], data[1]])))
            }

            svc_key::IPV4HINT => {
                if data.len() % 4 != 0 {
                    return Err(FieldError::InvalidValue(
                        "ipv4hint length must be multiple of 4".to_string(),
                    ));
                }
                let addrs: Vec<Ipv4Addr> = data
                    .chunks_exact(4)
                    .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]))
                    .collect();
                Ok(SvcParam::Ipv4Hint(addrs))
            }

            svc_key::ECH => Ok(SvcParam::Ech(data.to_vec())),

            svc_key::IPV6HINT => {
                if data.len() % 16 != 0 {
                    return Err(FieldError::InvalidValue(
                        "ipv6hint length must be multiple of 16".to_string(),
                    ));
                }
                let addrs: Vec<Ipv6Addr> = data
                    .chunks_exact(16)
                    .map(|c| {
                        let mut arr = [0u8; 16];
                        arr.copy_from_slice(c);
                        Ipv6Addr::from(arr)
                    })
                    .collect();
                Ok(SvcParam::Ipv6Hint(addrs))
            }

            _ => Ok(SvcParam::Unknown {
                key,
                value: data.to_vec(),
            }),
        }
    }

    /// Get the key for this parameter.
    pub fn key(&self) -> u16 {
        match self {
            SvcParam::Mandatory(_) => svc_key::MANDATORY,
            SvcParam::Alpn(_) => svc_key::ALPN,
            SvcParam::NoDefaultAlpn => svc_key::NO_DEFAULT_ALPN,
            SvcParam::Port(_) => svc_key::PORT,
            SvcParam::Ipv4Hint(_) => svc_key::IPV4HINT,
            SvcParam::Ech(_) => svc_key::ECH,
            SvcParam::Ipv6Hint(_) => svc_key::IPV6HINT,
            SvcParam::Unknown { key, .. } => *key,
        }
    }

    /// Serialize the parameter value (without key and length header).
    pub fn build_value(&self) -> Vec<u8> {
        match self {
            SvcParam::Mandatory(keys) => keys.iter().flat_map(|k| k.to_be_bytes()).collect(),
            SvcParam::Alpn(alpns) => {
                let mut out = Vec::new();
                for alpn in alpns {
                    out.push(alpn.len() as u8);
                    out.extend_from_slice(alpn.as_bytes());
                }
                out
            }
            SvcParam::NoDefaultAlpn => Vec::new(),
            SvcParam::Port(port) => port.to_be_bytes().to_vec(),
            SvcParam::Ipv4Hint(addrs) => addrs.iter().flat_map(|a| a.octets()).collect(),
            SvcParam::Ech(data) => data.clone(),
            SvcParam::Ipv6Hint(addrs) => addrs.iter().flat_map(|a| a.octets()).collect(),
            SvcParam::Unknown { value, .. } => value.clone(),
        }
    }

    /// Build the complete key-value pair (key + length + value).
    pub fn build(&self) -> Vec<u8> {
        let value = self.build_value();
        let mut out = Vec::with_capacity(4 + value.len());
        out.extend_from_slice(&self.key().to_be_bytes());
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(&value);
        out
    }

    /// Parse all SvcParams from wire format.
    pub fn parse_all(data: &[u8]) -> Result<Vec<Self>, FieldError> {
        let mut params = Vec::new();
        let mut pos = 0;

        while pos < data.len() {
            if pos + 4 > data.len() {
                return Err(FieldError::BufferTooShort {
                    offset: pos,
                    need: 4,
                    have: data.len(),
                });
            }
            let key = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let val_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
            pos += 4;

            if pos + val_len > data.len() {
                return Err(FieldError::BufferTooShort {
                    offset: pos,
                    need: val_len,
                    have: data.len() - pos,
                });
            }

            let param = Self::parse(key, &data[pos..pos + val_len])?;
            params.push(param);
            pos += val_len;
        }

        Ok(params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_alpn_roundtrip() {
        let param = SvcParam::Alpn(vec!["h2".to_string(), "h3".to_string()]);
        let built = param.build();
        let parsed = SvcParam::parse_all(&built).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], param);
    }

    #[test]
    fn test_port_roundtrip() {
        let param = SvcParam::Port(443);
        let built = param.build();
        let parsed = SvcParam::parse_all(&built).unwrap();
        assert_eq!(parsed[0], param);
    }

    #[test]
    fn test_ipv4hint_roundtrip() {
        let param = SvcParam::Ipv4Hint(vec![Ipv4Addr::new(1, 2, 3, 4), Ipv4Addr::new(5, 6, 7, 8)]);
        let built = param.build();
        let parsed = SvcParam::parse_all(&built).unwrap();
        assert_eq!(parsed[0], param);
    }

    #[test]
    fn test_ipv6hint_roundtrip() {
        let param = SvcParam::Ipv6Hint(vec![Ipv6Addr::LOCALHOST]);
        let built = param.build();
        let parsed = SvcParam::parse_all(&built).unwrap();
        assert_eq!(parsed[0], param);
    }

    #[test]
    fn test_mandatory_roundtrip() {
        let param = SvcParam::Mandatory(vec![1, 3]); // alpn, port
        let built = param.build();
        let parsed = SvcParam::parse_all(&built).unwrap();
        assert_eq!(parsed[0], param);
    }

    #[test]
    fn test_no_default_alpn() {
        let param = SvcParam::NoDefaultAlpn;
        let built = param.build();
        assert_eq!(built.len(), 4); // key(2) + len(2) + value(0)
        let parsed = SvcParam::parse_all(&built).unwrap();
        assert_eq!(parsed[0], param);
    }

    #[test]
    fn test_multiple_params() {
        let params = vec![
            SvcParam::Alpn(vec!["h2".to_string()]),
            SvcParam::Port(443),
            SvcParam::Ipv4Hint(vec![Ipv4Addr::new(1, 1, 1, 1)]),
        ];
        let mut data = Vec::new();
        for p in &params {
            data.extend_from_slice(&p.build());
        }
        let parsed = SvcParam::parse_all(&data).unwrap();
        assert_eq!(parsed, params);
    }
}
