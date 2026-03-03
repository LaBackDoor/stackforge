//! TLS cipher suite definitions and registry.
//!
//! Maps cipher suite IDs to their component algorithms.

/// Cipher type classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    Stream,
    Block,
    Aead,
}

/// Key exchange algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyExchange {
    Null,
    Rsa,
    DheRsa,
    DheDss,
    EcdheRsa,
    EcdheEcdsa,
    Psk,
    DhePsk,
    RsaPsk,
    EcdhePsk,
    /// TLS 1.3 (no separate KX in suite name)
    Tls13,
    /// `SSLv2`
    Sslv2,
}

/// Hash algorithm used in the cipher suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteHash {
    Null,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

/// Bulk cipher algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum BulkCipher {
    Null,
    Rc4_128,
    Des_Cbc,
    TripleDes_Cbc,
    Aes128_Cbc,
    Aes256_Cbc,
    Aes128_Gcm,
    Aes256_Gcm,
    ChaCha20_Poly1305,
    Aes128_Ccm,
    Aes256_Ccm,
    Aes128_Ccm8,
}

/// HMAC algorithm for MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteHmac {
    Null,
    Md5,
    Sha1,
    Sha256,
    Sha384,
    /// AEAD ciphers have no separate HMAC
    Aead,
}

/// A TLS cipher suite definition.
#[derive(Debug, Clone, Copy)]
pub struct CipherSuite {
    /// Numeric cipher suite ID (e.g., 0x002F for `TLS_RSA_WITH_AES_128_CBC_SHA`).
    pub id: u16,
    /// Human-readable name.
    pub name: &'static str,
    /// Key exchange algorithm.
    pub kx: KeyExchange,
    /// Bulk cipher.
    pub cipher: BulkCipher,
    /// Cipher type.
    pub cipher_type: CipherType,
    /// HMAC/MAC algorithm.
    pub hmac: SuiteHmac,
    /// Hash algorithm for PRF.
    pub hash: SuiteHash,
    /// Key length in bytes.
    pub key_len: usize,
    /// IV length in bytes (0 for stream/AEAD).
    pub iv_len: usize,
    /// MAC length in bytes (0 for AEAD).
    pub mac_len: usize,
    /// Whether this is a TLS 1.3 suite.
    pub tls13: bool,
}

impl CipherSuite {
    /// Total key block length needed for key derivation.
    ///
    /// `key_block_len` = 2 * (`mac_len` + `key_len` + `iv_len`)
    #[must_use]
    pub fn key_block_len(&self) -> usize {
        2 * (self.mac_len + self.key_len + self.iv_len)
    }
}

/// Static registry of common cipher suites.
pub static CIPHER_SUITES: &[CipherSuite] = &[
    // TLS 1.3 suites
    CipherSuite {
        id: 0x1301,
        name: "TLS_AES_128_GCM_SHA256",
        kx: KeyExchange::Tls13,
        cipher: BulkCipher::Aes128_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 12,
        mac_len: 0,
        tls13: true,
    },
    CipherSuite {
        id: 0x1302,
        name: "TLS_AES_256_GCM_SHA384",
        kx: KeyExchange::Tls13,
        cipher: BulkCipher::Aes256_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha384,
        key_len: 32,
        iv_len: 12,
        mac_len: 0,
        tls13: true,
    },
    CipherSuite {
        id: 0x1303,
        name: "TLS_CHACHA20_POLY1305_SHA256",
        kx: KeyExchange::Tls13,
        cipher: BulkCipher::ChaCha20_Poly1305,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 32,
        iv_len: 12,
        mac_len: 0,
        tls13: true,
    },
    CipherSuite {
        id: 0x1304,
        name: "TLS_AES_128_CCM_SHA256",
        kx: KeyExchange::Tls13,
        cipher: BulkCipher::Aes128_Ccm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 12,
        mac_len: 0,
        tls13: true,
    },
    CipherSuite {
        id: 0x1305,
        name: "TLS_AES_128_CCM_8_SHA256",
        kx: KeyExchange::Tls13,
        cipher: BulkCipher::Aes128_Ccm8,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 12,
        mac_len: 0,
        tls13: true,
    },
    // TLS 1.2 RSA suites
    CipherSuite {
        id: 0x002F,
        name: "TLS_RSA_WITH_AES_128_CBC_SHA",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::Aes128_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha1,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 16,
        mac_len: 20,
        tls13: false,
    },
    CipherSuite {
        id: 0x0035,
        name: "TLS_RSA_WITH_AES_256_CBC_SHA",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::Aes256_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha1,
        hash: SuiteHash::Sha256,
        key_len: 32,
        iv_len: 16,
        mac_len: 20,
        tls13: false,
    },
    CipherSuite {
        id: 0x003C,
        name: "TLS_RSA_WITH_AES_128_CBC_SHA256",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::Aes128_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha256,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 16,
        mac_len: 32,
        tls13: false,
    },
    CipherSuite {
        id: 0x003D,
        name: "TLS_RSA_WITH_AES_256_CBC_SHA256",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::Aes256_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha256,
        hash: SuiteHash::Sha256,
        key_len: 32,
        iv_len: 16,
        mac_len: 32,
        tls13: false,
    },
    CipherSuite {
        id: 0x009C,
        name: "TLS_RSA_WITH_AES_128_GCM_SHA256",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::Aes128_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 4,
        mac_len: 0,
        tls13: false,
    },
    CipherSuite {
        id: 0x009D,
        name: "TLS_RSA_WITH_AES_256_GCM_SHA384",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::Aes256_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha384,
        key_len: 32,
        iv_len: 4,
        mac_len: 0,
        tls13: false,
    },
    // TLS 1.2 ECDHE-RSA suites
    CipherSuite {
        id: 0xC013,
        name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
        kx: KeyExchange::EcdheRsa,
        cipher: BulkCipher::Aes128_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha1,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 16,
        mac_len: 20,
        tls13: false,
    },
    CipherSuite {
        id: 0xC014,
        name: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
        kx: KeyExchange::EcdheRsa,
        cipher: BulkCipher::Aes256_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha1,
        hash: SuiteHash::Sha256,
        key_len: 32,
        iv_len: 16,
        mac_len: 20,
        tls13: false,
    },
    CipherSuite {
        id: 0xC027,
        name: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
        kx: KeyExchange::EcdheRsa,
        cipher: BulkCipher::Aes128_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha256,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 16,
        mac_len: 32,
        tls13: false,
    },
    CipherSuite {
        id: 0xC02F,
        name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        kx: KeyExchange::EcdheRsa,
        cipher: BulkCipher::Aes128_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 4,
        mac_len: 0,
        tls13: false,
    },
    CipherSuite {
        id: 0xC030,
        name: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        kx: KeyExchange::EcdheRsa,
        cipher: BulkCipher::Aes256_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha384,
        key_len: 32,
        iv_len: 4,
        mac_len: 0,
        tls13: false,
    },
    // ECDHE-RSA with ChaCha20
    CipherSuite {
        id: 0xCCA8,
        name: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
        kx: KeyExchange::EcdheRsa,
        cipher: BulkCipher::ChaCha20_Poly1305,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 32,
        iv_len: 12,
        mac_len: 0,
        tls13: false,
    },
    // ECDHE-ECDSA suites
    CipherSuite {
        id: 0xC009,
        name: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
        kx: KeyExchange::EcdheEcdsa,
        cipher: BulkCipher::Aes128_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha1,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 16,
        mac_len: 20,
        tls13: false,
    },
    CipherSuite {
        id: 0xC02B,
        name: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        kx: KeyExchange::EcdheEcdsa,
        cipher: BulkCipher::Aes128_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 4,
        mac_len: 0,
        tls13: false,
    },
    CipherSuite {
        id: 0xC02C,
        name: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        kx: KeyExchange::EcdheEcdsa,
        cipher: BulkCipher::Aes256_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha384,
        key_len: 32,
        iv_len: 4,
        mac_len: 0,
        tls13: false,
    },
    CipherSuite {
        id: 0xCCA9,
        name: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
        kx: KeyExchange::EcdheEcdsa,
        cipher: BulkCipher::ChaCha20_Poly1305,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 32,
        iv_len: 12,
        mac_len: 0,
        tls13: false,
    },
    // DHE-RSA suites
    CipherSuite {
        id: 0x0033,
        name: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
        kx: KeyExchange::DheRsa,
        cipher: BulkCipher::Aes128_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha1,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 16,
        mac_len: 20,
        tls13: false,
    },
    CipherSuite {
        id: 0x009E,
        name: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
        kx: KeyExchange::DheRsa,
        cipher: BulkCipher::Aes128_Gcm,
        cipher_type: CipherType::Aead,
        hmac: SuiteHmac::Aead,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 4,
        mac_len: 0,
        tls13: false,
    },
    // NULL cipher (for testing)
    CipherSuite {
        id: 0x0000,
        name: "TLS_NULL_WITH_NULL_NULL",
        kx: KeyExchange::Null,
        cipher: BulkCipher::Null,
        cipher_type: CipherType::Stream,
        hmac: SuiteHmac::Null,
        hash: SuiteHash::Null,
        key_len: 0,
        iv_len: 0,
        mac_len: 0,
        tls13: false,
    },
    // Legacy suites
    CipherSuite {
        id: 0x000A,
        name: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::TripleDes_Cbc,
        cipher_type: CipherType::Block,
        hmac: SuiteHmac::Sha1,
        hash: SuiteHash::Sha256,
        key_len: 24,
        iv_len: 8,
        mac_len: 20,
        tls13: false,
    },
    CipherSuite {
        id: 0x0004,
        name: "TLS_RSA_WITH_RC4_128_MD5",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::Rc4_128,
        cipher_type: CipherType::Stream,
        hmac: SuiteHmac::Md5,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 0,
        mac_len: 16,
        tls13: false,
    },
    CipherSuite {
        id: 0x0005,
        name: "TLS_RSA_WITH_RC4_128_SHA",
        kx: KeyExchange::Rsa,
        cipher: BulkCipher::Rc4_128,
        cipher_type: CipherType::Stream,
        hmac: SuiteHmac::Sha1,
        hash: SuiteHash::Sha256,
        key_len: 16,
        iv_len: 0,
        mac_len: 20,
        tls13: false,
    },
];

/// Look up a cipher suite by its numeric ID.
#[must_use]
pub fn find_suite(id: u16) -> Option<&'static CipherSuite> {
    CIPHER_SUITES.iter().find(|s| s.id == id)
}

/// Look up a cipher suite by name (case-insensitive).
#[must_use]
pub fn find_suite_by_name(name: &str) -> Option<&'static CipherSuite> {
    let upper = name.to_uppercase();
    CIPHER_SUITES.iter().find(|s| s.name == upper)
}

/// Get all TLS 1.3 cipher suites.
pub fn tls13_suites() -> impl Iterator<Item = &'static CipherSuite> {
    CIPHER_SUITES.iter().filter(|s| s.tls13)
}

/// Get all cipher suites for a given key exchange type.
pub fn suites_by_kx(kx: KeyExchange) -> impl Iterator<Item = &'static CipherSuite> {
    CIPHER_SUITES.iter().filter(move |s| s.kx == kx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_suite() {
        let suite = find_suite(0x1301).unwrap();
        assert_eq!(suite.name, "TLS_AES_128_GCM_SHA256");
        assert!(suite.tls13);
        assert_eq!(suite.key_len, 16);
    }

    #[test]
    fn test_find_suite_by_name() {
        let suite = find_suite_by_name("TLS_AES_256_GCM_SHA384").unwrap();
        assert_eq!(suite.id, 0x1302);
    }

    #[test]
    fn test_tls13_suites() {
        let suites: Vec<_> = tls13_suites().collect();
        assert!(suites.len() >= 3);
        assert!(suites.iter().all(|s| s.tls13));
    }

    #[test]
    fn test_key_block_len() {
        // TLS_RSA_WITH_AES_128_CBC_SHA: mac=20, key=16, iv=16 -> 2*(20+16+16) = 104
        let suite = find_suite(0x002F).unwrap();
        assert_eq!(suite.key_block_len(), 104);
    }

    #[test]
    fn test_aead_suite_no_mac() {
        let suite = find_suite(0x009C).unwrap();
        assert_eq!(suite.mac_len, 0);
        assert_eq!(suite.cipher_type, CipherType::Aead);
    }

    #[test]
    fn test_unknown_suite() {
        assert!(find_suite(0xFFFF).is_none());
    }
}
