//! TLS Certificate handling.
//!
//! Wraps raw DER-encoded X.509 certificates for basic inspection.
//! This is intentionally minimal - just enough for TLS protocol operations.

/// A TLS certificate wrapping raw DER-encoded X.509 data.
#[derive(Debug, Clone)]
pub struct TlsCertificate {
    /// Raw DER-encoded certificate data.
    pub der: Vec<u8>,
}

impl TlsCertificate {
    /// Create from DER-encoded bytes.
    pub fn from_der(der: Vec<u8>) -> Self {
        Self { der }
    }

    /// Create from PEM-encoded string.
    pub fn from_pem(pem: &str) -> Option<Self> {
        let lines: Vec<&str> = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let b64 = lines.join("");
        let der = base64_decode(&b64)?;
        Some(Self { der })
    }

    /// Get the DER-encoded data.
    pub fn as_der(&self) -> &[u8] {
        &self.der
    }

    /// Get the certificate length.
    pub fn len(&self) -> usize {
        self.der.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.der.is_empty()
    }

    /// Extract the subject common name (CN) from the certificate.
    ///
    /// This is a basic ASN.1 parser that looks for the CN OID (2.5.4.3).
    /// In X.509, issuer comes before subject, so subject CN is the second occurrence.
    /// For self-signed certs (only one CN), falls back to the first occurrence.
    pub fn subject_cn(&self) -> Option<String> {
        let cn_oid = [0x55, 0x04, 0x03];
        find_nth_string_after_oid(&self.der, &cn_oid, 1)
            .or_else(|| find_nth_string_after_oid(&self.der, &cn_oid, 0))
    }

    /// Extract the issuer common name from the certificate.
    pub fn issuer_cn(&self) -> Option<String> {
        let cn_oid = [0x55, 0x04, 0x03];
        find_nth_string_after_oid(&self.der, &cn_oid, 0)
    }
}

/// Parse a certificate chain from multiple PEM blocks.
pub fn parse_pem_chain(pem: &str) -> Vec<TlsCertificate> {
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut current = String::new();

    for line in pem.lines() {
        if line.contains("BEGIN CERTIFICATE") {
            in_cert = true;
            current.clear();
            current.push_str(line);
            current.push('\n');
        } else if line.contains("END CERTIFICATE") {
            current.push_str(line);
            current.push('\n');
            if let Some(cert) = TlsCertificate::from_pem(&current) {
                certs.push(cert);
            }
            in_cert = false;
        } else if in_cert {
            current.push_str(line);
            current.push('\n');
        }
    }

    certs
}

/// Simple base64 decoder (no dependencies).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input: Vec<u8> = input
        .bytes()
        .filter(|&b| b != b'\n' && b != b'\r' && b != b' ')
        .collect();
    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf: u32 = 0;
    let mut bits = 0;

    for &byte in &input {
        let val = if byte == b'=' {
            continue;
        } else if let Some(pos) = TABLE.iter().position(|&b| b == byte) {
            pos as u32
        } else {
            return None;
        };

        buf = (buf << 6) | val;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(output)
}

/// Find the nth UTF-8/PrintableString value after an OID in DER data.
/// `n=0` returns the first occurrence (issuer CN in X.509),
/// `n=1` returns the second (subject CN in X.509).
fn find_nth_string_after_oid(data: &[u8], oid: &[u8], n: usize) -> Option<String> {
    let mut count = 0;
    for i in 0..data.len().saturating_sub(oid.len()) {
        if data[i..].starts_with(oid) {
            let pos = i + oid.len();
            if pos + 2 > data.len() {
                continue;
            }
            let tag = data[pos];
            // UTF8String (0x0C), PrintableString (0x13), IA5String (0x16)
            if tag == 0x0C || tag == 0x13 || tag == 0x16 {
                let len = data[pos + 1] as usize;
                if pos + 2 + len <= data.len() {
                    if count == n {
                        return String::from_utf8(data[pos + 2..pos + 2 + len].to_vec()).ok();
                    }
                    count += 1;
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_der() {
        let cert = TlsCertificate::from_der(vec![0x30, 0x82, 0x01, 0x00]);
        assert_eq!(cert.len(), 4);
        assert!(!cert.is_empty());
    }

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("SGVsbG8="), Some(b"Hello".to_vec()));
        assert_eq!(base64_decode(""), Some(Vec::new()));
        assert_eq!(base64_decode("YQ=="), Some(b"a".to_vec()));
    }

    #[test]
    fn test_from_pem() {
        let pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
        let cert = TlsCertificate::from_pem(pem);
        assert!(cert.is_some());
    }

    #[test]
    fn test_find_cn() {
        // Construct a minimal DER with CN OID followed by UTF8String "test"
        let mut data = Vec::new();
        data.extend_from_slice(&[0x30, 0x20]); // SEQUENCE
        data.extend_from_slice(&[0x06, 0x03, 0x55, 0x04, 0x03]); // OID 2.5.4.3
        data.extend_from_slice(&[0x0C, 0x04]); // UTF8String, length 4
        data.extend_from_slice(b"test");

        let result = find_nth_string_after_oid(&data, &[0x55, 0x04, 0x03], 0);
        assert_eq!(result, Some("test".to_string()));
    }
}
