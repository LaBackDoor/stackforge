//! TLS HMAC abstractions.
//!
//! Provides HMAC computation for TLS MAC operations, supporting
//! both standard HMAC (RFC 2104) and `SSLv3` MAC.

use hmac::{Hmac, Mac};

use super::hash::TlsHash;

/// TLS HMAC wrapper.
#[derive(Debug, Clone)]
pub struct TlsHmac {
    hash: TlsHash,
    key: Vec<u8>,
}

impl TlsHmac {
    /// Create a new HMAC instance with the given hash and key.
    #[must_use]
    pub fn new(hash: TlsHash, key: &[u8]) -> Self {
        Self {
            hash,
            key: key.to_vec(),
        }
    }

    /// Returns the HMAC output length.
    #[must_use]
    pub fn hmac_len(&self) -> usize {
        self.hash.hash_len()
    }

    /// Compute HMAC over the given data.
    #[must_use]
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self.hash {
            TlsHash::Null => vec![],
            TlsHash::Md5 => {
                let mut mac = Hmac::<md5::Md5>::new_from_slice(&self.key).expect("HMAC key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            },
            TlsHash::Sha1 => {
                let mut mac =
                    Hmac::<sha1::Sha1>::new_from_slice(&self.key).expect("HMAC key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            },
            TlsHash::Sha224 => {
                let mut mac =
                    Hmac::<sha2::Sha224>::new_from_slice(&self.key).expect("HMAC key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            },
            TlsHash::Sha256 => {
                let mut mac =
                    Hmac::<sha2::Sha256>::new_from_slice(&self.key).expect("HMAC key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            },
            TlsHash::Sha384 => {
                let mut mac =
                    Hmac::<sha2::Sha384>::new_from_slice(&self.key).expect("HMAC key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            },
            TlsHash::Sha512 => {
                let mut mac =
                    Hmac::<sha2::Sha512>::new_from_slice(&self.key).expect("HMAC key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            },
        }
    }

    /// SSLv3-style MAC computation.
    ///
    /// `SSLv3` MAC = hash(key + pad2 + hash(key + pad1 + data))
    #[must_use]
    pub fn digest_sslv3(&self, data: &[u8]) -> Vec<u8> {
        let pad_len = match self.hash {
            TlsHash::Md5 => 48,
            _ => 40,
        };
        let pad1: Vec<u8> = vec![0x36; pad_len];
        let pad2: Vec<u8> = vec![0x5c; pad_len];

        // inner = hash(key + pad1 + data)
        let mut inner_input = Vec::with_capacity(self.key.len() + pad_len + data.len());
        inner_input.extend_from_slice(&self.key);
        inner_input.extend_from_slice(&pad1);
        inner_input.extend_from_slice(data);
        let inner = self.hash.digest(&inner_input);

        // outer = hash(key + pad2 + inner)
        let mut outer_input = Vec::with_capacity(self.key.len() + pad_len + inner.len());
        outer_input.extend_from_slice(&self.key);
        outer_input.extend_from_slice(&pad2);
        outer_input.extend_from_slice(&inner);
        self.hash.digest(&outer_input)
    }

    /// Verify HMAC.
    #[must_use]
    pub fn verify(&self, data: &[u8], expected: &[u8]) -> bool {
        let computed = self.digest(data);
        constant_time_eq(&computed, expected)
    }
}

/// Constant-time comparison to prevent timing attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 2202 Test Vectors for HMAC-MD5
    #[test]
    fn test_hmac_md5_rfc2202_1() {
        // Test Case 1
        let key = vec![0x0b; 16];
        let data = b"Hi There";
        let hmac = TlsHmac::new(TlsHash::Md5, &key);
        let result = hmac.digest(data);
        let expected: Vec<u8> = vec![
            0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c, 0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b,
            0xfc, 0x9d,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_md5_rfc2202_2() {
        // Test Case 2: key = "Jefe"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let hmac = TlsHmac::new(TlsHash::Md5, key);
        let result = hmac.digest(data);
        let expected: Vec<u8> = vec![
            0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03, 0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d,
            0xb7, 0x38,
        ];
        assert_eq!(result, expected);
    }

    // RFC 2202 Test Vectors for HMAC-SHA1
    #[test]
    fn test_hmac_sha1_rfc2202_1() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let hmac = TlsHmac::new(TlsHash::Sha1, &key);
        let result = hmac.digest(data);
        let expected: Vec<u8> = vec![
            0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b, 0xc0, 0xb6, 0xfb, 0x37,
            0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha1_rfc2202_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let hmac = TlsHmac::new(TlsHash::Sha1, key);
        let result = hmac.digest(data);
        let expected: Vec<u8> = vec![
            0xef, 0xfc, 0xdf, 0x6a, 0xe5, 0xeb, 0x2f, 0xa2, 0xd2, 0x74, 0x16, 0xd5, 0xf1, 0x84,
            0xdf, 0x9c, 0x25, 0x9a, 0x7c, 0x79,
        ];
        assert_eq!(result, expected);
    }

    // RFC 4231 Test Vectors for HMAC-SHA256
    #[test]
    fn test_hmac_sha256_rfc4231_1() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let hmac = TlsHmac::new(TlsHash::Sha256, &key);
        let result = hmac.digest(data);
        let expected: Vec<u8> = vec![
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_2() {
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let hmac = TlsHmac::new(TlsHash::Sha256, key);
        let result = hmac.digest(data);
        let expected: Vec<u8> = vec![
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_hmac_verify() {
        let key = vec![0x0b; 20];
        let data = b"Hi There";
        let hmac = TlsHmac::new(TlsHash::Sha256, &key);
        let mac = hmac.digest(data);
        assert!(hmac.verify(data, &mac));
        let mut bad_mac = mac.clone();
        bad_mac[0] ^= 1;
        assert!(!hmac.verify(data, &bad_mac));
    }

    #[test]
    fn test_hmac_null() {
        let hmac = TlsHmac::new(TlsHash::Null, b"");
        assert_eq!(hmac.digest(b"test"), Vec::<u8>::new());
        assert_eq!(hmac.hmac_len(), 0);
    }
}
