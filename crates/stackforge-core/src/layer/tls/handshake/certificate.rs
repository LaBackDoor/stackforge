//! TLS Certificate, `CertificateVerify`, and `CertificateRequest` messages.

/// Parsed TLS Certificate message (type 11).
///
/// TLS 1.2:
/// ```text
/// uint24 certificates_length;
/// repeat {
///     uint24 cert_length;
///     opaque cert[cert_length];  // DER-encoded X.509
/// }
/// ```
///
/// TLS 1.3 adds per-certificate extensions.
#[derive(Debug, Clone)]
pub struct Certificate {
    /// List of DER-encoded certificates.
    pub certificates: Vec<Vec<u8>>,
    /// TLS 1.3: certificate request context.
    pub request_context: Vec<u8>,
    /// TLS 1.3: per-certificate extensions (parallel to certificates).
    pub cert_extensions: Vec<Vec<u8>>,
}

impl Certificate {
    /// Parse Certificate message body (TLS 1.2 format).
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 3 {
            return None;
        }

        let certs_len = u32::from_be_bytes([0, data[0], data[1], data[2]]) as usize;
        let mut offset = 3;
        let end = (3 + certs_len).min(data.len());

        let mut certificates = Vec::new();
        while offset + 3 <= end {
            let cert_len =
                u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
            offset += 3;
            if offset + cert_len > data.len() {
                break;
            }
            certificates.push(data[offset..offset + cert_len].to_vec());
            offset += cert_len;
        }

        Some(Self {
            certificates,
            request_context: Vec::new(),
            cert_extensions: Vec::new(),
        })
    }

    /// Parse Certificate message body (TLS 1.3 format).
    #[must_use]
    pub fn parse_tls13(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let mut offset = 0;

        // Certificate request context
        let ctx_len = data[offset] as usize;
        offset += 1;
        if offset + ctx_len > data.len() {
            return None;
        }
        let request_context = data[offset..offset + ctx_len].to_vec();
        offset += ctx_len;

        // Certificate list
        if offset + 3 > data.len() {
            return None;
        }
        let certs_len =
            u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
        offset += 3;
        let end = (offset + certs_len).min(data.len());

        let mut certificates = Vec::new();
        let mut cert_extensions = Vec::new();

        while offset + 3 <= end {
            let cert_len =
                u32::from_be_bytes([0, data[offset], data[offset + 1], data[offset + 2]]) as usize;
            offset += 3;
            if offset + cert_len > data.len() {
                break;
            }
            certificates.push(data[offset..offset + cert_len].to_vec());
            offset += cert_len;

            // Per-certificate extensions
            if offset + 2 <= data.len() {
                let ext_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                if offset + ext_len <= data.len() {
                    cert_extensions.push(data[offset..offset + ext_len].to_vec());
                    offset += ext_len;
                } else {
                    cert_extensions.push(Vec::new());
                }
            } else {
                cert_extensions.push(Vec::new());
            }
        }

        Some(Self {
            certificates,
            request_context,
            cert_extensions,
        })
    }

    /// Build Certificate message body (TLS 1.2 format).
    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut cert_data = Vec::new();
        for cert in &self.certificates {
            let len = cert.len() as u32;
            let bytes = len.to_be_bytes();
            cert_data.extend_from_slice(&bytes[1..4]);
            cert_data.extend_from_slice(cert);
        }

        let total_len = cert_data.len() as u32;
        let bytes = total_len.to_be_bytes();
        let mut buf = Vec::with_capacity(3 + cert_data.len());
        buf.extend_from_slice(&bytes[1..4]);
        buf.extend_from_slice(&cert_data);
        buf
    }
}

/// TLS `CertificateVerify` message (type 15).
///
/// ```text
/// SignatureScheme algorithm;    // 2 bytes
/// opaque signature<0..2^16-1>; // 2 byte length + signature
/// ```
#[derive(Debug, Clone)]
pub struct CertificateVerify {
    /// Signature algorithm.
    pub algorithm: u16,
    /// Signature value.
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 4 {
            return None;
        }
        let algorithm = u16::from_be_bytes([data[0], data[1]]);
        let sig_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + sig_len {
            return None;
        }
        let signature = data[4..4 + sig_len].to_vec();
        Some(Self {
            algorithm,
            signature,
        })
    }

    #[must_use]
    pub fn build(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.signature.len());
        buf.extend_from_slice(&self.algorithm.to_be_bytes());
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        buf
    }
}

/// TLS `CertificateRequest` message (type 13).
#[derive(Debug, Clone)]
pub struct CertificateRequest {
    /// Certificate types.
    pub certificate_types: Vec<u8>,
    /// Supported signature algorithms.
    pub signature_algorithms: Vec<u16>,
    /// Distinguished names (DER-encoded).
    pub distinguished_names: Vec<Vec<u8>>,
}

impl CertificateRequest {
    #[must_use]
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }
        let mut offset = 0;

        // Certificate types
        let types_len = data[offset] as usize;
        offset += 1;
        if offset + types_len > data.len() {
            return None;
        }
        let certificate_types = data[offset..offset + types_len].to_vec();
        offset += types_len;

        // Signature algorithms
        let mut signature_algorithms = Vec::new();
        if offset + 2 <= data.len() {
            let algs_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let end = (offset + algs_len).min(data.len());
            while offset + 2 <= end {
                signature_algorithms.push(u16::from_be_bytes([data[offset], data[offset + 1]]));
                offset += 2;
            }
        }

        // Distinguished names
        let mut distinguished_names = Vec::new();
        if offset + 2 <= data.len() {
            let dn_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;
            let end = (offset + dn_len).min(data.len());
            while offset + 2 <= end {
                let name_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                offset += 2;
                if offset + name_len <= data.len() {
                    distinguished_names.push(data[offset..offset + name_len].to_vec());
                    offset += name_len;
                } else {
                    break;
                }
            }
        }

        Some(Self {
            certificate_types,
            signature_algorithms,
            distinguished_names,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_certificate() {
        // Two certificates of 3 bytes each
        let mut data = Vec::new();
        // Total certs length = 12 (2 * (3 + 3))
        data.extend_from_slice(&[0x00, 0x00, 0x0C]);
        // Cert 1: length=3
        data.extend_from_slice(&[0x00, 0x00, 0x03]);
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);
        // Cert 2: length=3
        data.extend_from_slice(&[0x00, 0x00, 0x03]);
        data.extend_from_slice(&[0xDD, 0xEE, 0xFF]);

        let cert = Certificate::parse(&data).unwrap();
        assert_eq!(cert.certificates.len(), 2);
        assert_eq!(cert.certificates[0], vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(cert.certificates[1], vec![0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn test_certificate_roundtrip() {
        let cert = Certificate {
            certificates: vec![vec![0x01, 0x02], vec![0x03, 0x04, 0x05]],
            request_context: Vec::new(),
            cert_extensions: Vec::new(),
        };
        let built = cert.build();
        let parsed = Certificate::parse(&built).unwrap();
        assert_eq!(parsed.certificates, cert.certificates);
    }

    #[test]
    fn test_parse_certificate_verify() {
        let data = vec![
            0x08, 0x04, // RSA-PSS-SHA256
            0x00, 0x04, // signature length = 4
            0xDE, 0xAD, 0xBE, 0xEF,
        ];
        let cv = CertificateVerify::parse(&data).unwrap();
        assert_eq!(cv.algorithm, 0x0804);
        assert_eq!(cv.signature, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
