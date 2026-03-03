//! TLS protocol constants and type definitions.
//!
//! Based on Scapy's `basefields.py` and RFC 8446/5246.
//! Covers TLS record types, versions, alert codes, and handshake types.

/// TLS record content types (RFC 5246 Section 6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum TlsContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
    Unknown(u8),
}

impl TlsContentType {
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            20 => Self::ChangeCipherSpec,
            21 => Self::Alert,
            22 => Self::Handshake,
            23 => Self::ApplicationData,
            24 => Self::Heartbeat,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::ChangeCipherSpec => 20,
            Self::Alert => 21,
            Self::Handshake => 22,
            Self::ApplicationData => 23,
            Self::Heartbeat => 24,
            Self::Unknown(v) => *v,
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::ChangeCipherSpec => "change_cipher_spec",
            Self::Alert => "alert",
            Self::Handshake => "handshake",
            Self::ApplicationData => "application_data",
            Self::Heartbeat => "heartbeat",
            Self::Unknown(_) => "unknown",
        }
    }
}

impl std::fmt::Display for TlsContentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// TLS protocol version constants.
///
/// Mirrors Scapy's `_tls_version` dictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TlsVersion(pub u16);

impl TlsVersion {
    pub const SSLV2: Self = Self(0x0002);
    pub const SSLV2_ALT: Self = Self(0x0200);
    pub const SSLV3: Self = Self(0x0300);
    pub const TLS10: Self = Self(0x0301);
    pub const TLS11: Self = Self(0x0302);
    pub const TLS12: Self = Self(0x0303);
    pub const TLS13_DRAFT18: Self = Self(0x7f12);
    pub const TLS13_DRAFT19: Self = Self(0x7f13);
    pub const TLS13: Self = Self(0x0304);

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.0 {
            0x0002 => "SSLv2",
            0x0200 => "SSLv2",
            0x0300 => "SSLv3",
            0x0301 => "TLS 1.0",
            0x0302 => "TLS 1.1",
            0x0303 => "TLS 1.2",
            0x7f12 => "TLS 1.3-d18",
            0x7f13 => "TLS 1.3-d19",
            0x0304 => "TLS 1.3",
            _ => "Unknown",
        }
    }

    /// Check if this version is `SSLv2`.
    #[must_use]
    pub fn is_sslv2(&self) -> bool {
        self.0 == 0x0002 || self.0 == 0x0200
    }

    /// Check if this version is TLS 1.3 or a draft.
    #[must_use]
    pub fn is_tls13(&self) -> bool {
        self.0 == 0x0304 || (self.0 & 0xff00) == 0x7f00
    }

    /// For TLS 1.3, the record layer uses legacy version 0x0301 (TLS 1.0).
    #[must_use]
    pub fn record_version(&self) -> u16 {
        if self.is_tls13() { 0x0301 } else { self.0 }
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:#06x})", self.name(), self.0)
    }
}

/// TLS alert level (RFC 5246 Section 7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsAlertLevel {
    Warning = 1,
    Fatal = 2,
    Unknown(u8),
}

impl TlsAlertLevel {
    #[must_use]
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Warning,
            2 => Self::Fatal,
            other => Self::Unknown(other),
        }
    }

    #[must_use]
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::Warning => 1,
            Self::Fatal => 2,
            Self::Unknown(v) => *v,
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Fatal => "fatal",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// TLS alert description (RFC 5246 Section 7.2.2 + RFC 8446).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsAlertDescription(pub u8);

impl TlsAlertDescription {
    pub const CLOSE_NOTIFY: Self = Self(0);
    pub const UNEXPECTED_MESSAGE: Self = Self(10);
    pub const BAD_RECORD_MAC: Self = Self(20);
    pub const DECRYPTION_FAILED: Self = Self(21);
    pub const RECORD_OVERFLOW: Self = Self(22);
    pub const DECOMPRESSION_FAILURE: Self = Self(30);
    pub const HANDSHAKE_FAILURE: Self = Self(40);
    pub const NO_CERTIFICATE: Self = Self(41);
    pub const BAD_CERTIFICATE: Self = Self(42);
    pub const UNSUPPORTED_CERTIFICATE: Self = Self(43);
    pub const CERTIFICATE_REVOKED: Self = Self(44);
    pub const CERTIFICATE_EXPIRED: Self = Self(45);
    pub const CERTIFICATE_UNKNOWN: Self = Self(46);
    pub const ILLEGAL_PARAMETER: Self = Self(47);
    pub const UNKNOWN_CA: Self = Self(48);
    pub const ACCESS_DENIED: Self = Self(49);
    pub const DECODE_ERROR: Self = Self(50);
    pub const DECRYPT_ERROR: Self = Self(51);
    pub const PROTOCOL_VERSION: Self = Self(70);
    pub const INSUFFICIENT_SECURITY: Self = Self(71);
    pub const INTERNAL_ERROR: Self = Self(80);
    pub const INAPPROPRIATE_FALLBACK: Self = Self(86);
    pub const USER_CANCELED: Self = Self(90);
    pub const NO_RENEGOTIATION: Self = Self(100);
    pub const MISSING_EXTENSION: Self = Self(109);
    pub const UNSUPPORTED_EXTENSION: Self = Self(110);
    pub const UNRECOGNIZED_NAME: Self = Self(112);
    pub const BAD_CERTIFICATE_STATUS_RESPONSE: Self = Self(113);
    pub const UNKNOWN_PSK_IDENTITY: Self = Self(115);
    pub const CERTIFICATE_REQUIRED: Self = Self(116);
    pub const NO_APPLICATION_PROTOCOL: Self = Self(120);

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.0 {
            0 => "close_notify",
            10 => "unexpected_message",
            20 => "bad_record_mac",
            21 => "decryption_failed",
            22 => "record_overflow",
            30 => "decompression_failure",
            40 => "handshake_failure",
            41 => "no_certificate",
            42 => "bad_certificate",
            43 => "unsupported_certificate",
            44 => "certificate_revoked",
            45 => "certificate_expired",
            46 => "certificate_unknown",
            47 => "illegal_parameter",
            48 => "unknown_ca",
            49 => "access_denied",
            50 => "decode_error",
            51 => "decrypt_error",
            70 => "protocol_version",
            71 => "insufficient_security",
            80 => "internal_error",
            86 => "inappropriate_fallback",
            90 => "user_canceled",
            100 => "no_renegotiation",
            109 => "missing_extension",
            110 => "unsupported_extension",
            112 => "unrecognized_name",
            113 => "bad_certificate_status_response",
            115 => "unknown_psk_identity",
            116 => "certificate_required",
            120 => "no_application_protocol",
            _ => "unknown",
        }
    }
}

/// TLS handshake message types (RFC 5246 Section 7.4 + RFC 8446).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandshakeType(pub u8);

impl HandshakeType {
    pub const HELLO_REQUEST: Self = Self(0);
    pub const CLIENT_HELLO: Self = Self(1);
    pub const SERVER_HELLO: Self = Self(2);
    pub const HELLO_VERIFY_REQUEST: Self = Self(3);
    pub const NEW_SESSION_TICKET: Self = Self(4);
    pub const END_OF_EARLY_DATA: Self = Self(5);
    pub const HELLO_RETRY_REQUEST: Self = Self(6);
    pub const ENCRYPTED_EXTENSIONS: Self = Self(8);
    pub const CERTIFICATE: Self = Self(11);
    pub const SERVER_KEY_EXCHANGE: Self = Self(12);
    pub const CERTIFICATE_REQUEST: Self = Self(13);
    pub const SERVER_HELLO_DONE: Self = Self(14);
    pub const CERTIFICATE_VERIFY: Self = Self(15);
    pub const CLIENT_KEY_EXCHANGE: Self = Self(16);
    pub const FINISHED: Self = Self(20);
    pub const CERTIFICATE_URL: Self = Self(21);
    pub const CERTIFICATE_STATUS: Self = Self(22);
    pub const KEY_UPDATE: Self = Self(24);
    pub const COMPRESSED_CERTIFICATE: Self = Self(25);
    pub const MESSAGE_HASH: Self = Self(254);

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.0 {
            0 => "HelloRequest",
            1 => "ClientHello",
            2 => "ServerHello",
            3 => "HelloVerifyRequest",
            4 => "NewSessionTicket",
            5 => "EndOfEarlyData",
            6 => "HelloRetryRequest",
            8 => "EncryptedExtensions",
            11 => "Certificate",
            12 => "ServerKeyExchange",
            13 => "CertificateRequest",
            14 => "ServerHelloDone",
            15 => "CertificateVerify",
            16 => "ClientKeyExchange",
            20 => "Finished",
            21 => "CertificateURL",
            22 => "CertificateStatus",
            24 => "KeyUpdate",
            25 => "CompressedCertificate",
            254 => "MessageHash",
            _ => "Unknown",
        }
    }
}

impl std::fmt::Display for HandshakeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name(), self.0)
    }
}

/// TLS extension type IDs (RFC 8446 Section 4.2 + IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ExtensionType(pub u16);

impl ExtensionType {
    pub const SERVER_NAME: Self = Self(0);
    pub const MAX_FRAGMENT_LENGTH: Self = Self(1);
    pub const CLIENT_CERTIFICATE_URL: Self = Self(2);
    pub const TRUSTED_CA_KEYS: Self = Self(3);
    pub const TRUNCATED_HMAC: Self = Self(4);
    pub const STATUS_REQUEST: Self = Self(5);
    pub const EC_POINT_FORMATS: Self = Self(11);
    pub const SUPPORTED_GROUPS: Self = Self(10);
    pub const SIGNATURE_ALGORITHMS: Self = Self(13);
    pub const USE_SRTP: Self = Self(14);
    pub const HEARTBEAT: Self = Self(15);
    pub const ALPN: Self = Self(16);
    pub const SCT: Self = Self(18);
    pub const ENCRYPT_THEN_MAC: Self = Self(22);
    pub const EXTENDED_MASTER_SECRET: Self = Self(23);
    pub const SESSION_TICKET: Self = Self(35);
    pub const PRE_SHARED_KEY: Self = Self(41);
    pub const EARLY_DATA: Self = Self(42);
    pub const SUPPORTED_VERSIONS: Self = Self(43);
    pub const COOKIE: Self = Self(44);
    pub const PSK_KEY_EXCHANGE_MODES: Self = Self(45);
    pub const CERTIFICATE_AUTHORITIES: Self = Self(47);
    pub const OID_FILTERS: Self = Self(48);
    pub const POST_HANDSHAKE_AUTH: Self = Self(49);
    pub const SIGNATURE_ALGORITHMS_CERT: Self = Self(50);
    pub const KEY_SHARE: Self = Self(51);
    pub const RENEGOTIATION_INFO: Self = Self(0xff01);

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.0 {
            0 => "server_name",
            1 => "max_fragment_length",
            2 => "client_certificate_url",
            3 => "trusted_ca_keys",
            4 => "truncated_hmac",
            5 => "status_request",
            10 => "supported_groups",
            11 => "ec_point_formats",
            13 => "signature_algorithms",
            14 => "use_srtp",
            15 => "heartbeat",
            16 => "application_layer_protocol_negotiation",
            18 => "signed_certificate_timestamp",
            22 => "encrypt_then_mac",
            23 => "extended_master_secret",
            35 => "session_ticket",
            41 => "pre_shared_key",
            42 => "early_data",
            43 => "supported_versions",
            44 => "cookie",
            45 => "psk_key_exchange_modes",
            47 => "certificate_authorities",
            48 => "oid_filters",
            49 => "post_handshake_auth",
            50 => "signature_algorithms_cert",
            51 => "key_share",
            0xff01 => "renegotiation_info",
            _ => "unknown",
        }
    }
}

impl std::fmt::Display for ExtensionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({:#06x})", self.name(), self.0)
    }
}

/// TLS cipher suite IDs (commonly used).
pub mod cipher_suite_ids {
    // TLS 1.3 cipher suites
    pub const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
    pub const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
    pub const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
    pub const TLS_AES_128_CCM_SHA256: u16 = 0x1304;
    pub const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

    // TLS 1.2 cipher suites (common)
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: u16 = 0x002f;
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: u16 = 0x0035;
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: u16 = 0x003c;
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: u16 = 0x003d;
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: u16 = 0x009c;
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: u16 = 0x009d;
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02f;
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: u16 = 0xc030;
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: u16 = 0xc02b;
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: u16 = 0xc02c;
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca8;
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: u16 = 0xcca9;

    // SSLv2 cipher suites (for legacy support)
    pub const SSL_CK_RC4_128_WITH_MD5: u32 = 0x010080;
    pub const SSL_CK_RC4_128_EXPORT40_WITH_MD5: u32 = 0x020080;
    pub const SSL_CK_RC2_128_CBC_WITH_MD5: u32 = 0x030080;
    pub const SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5: u32 = 0x040080;
    pub const SSL_CK_IDEA_128_CBC_WITH_MD5: u32 = 0x050080;
    pub const SSL_CK_DES_64_CBC_WITH_MD5: u32 = 0x060040;
    pub const SSL_CK_DES_192_EDE3_CBC_WITH_MD5: u32 = 0x0700c0;

    /// Get human-readable name for a cipher suite.
    #[must_use]
    pub fn name(id: u16) -> &'static str {
        match id {
            0x1301 => "TLS_AES_128_GCM_SHA256",
            0x1302 => "TLS_AES_256_GCM_SHA384",
            0x1303 => "TLS_CHACHA20_POLY1305_SHA256",
            0x1304 => "TLS_AES_128_CCM_SHA256",
            0x1305 => "TLS_AES_128_CCM_8_SHA256",
            0x002f => "TLS_RSA_WITH_AES_128_CBC_SHA",
            0x0035 => "TLS_RSA_WITH_AES_256_CBC_SHA",
            0x003c => "TLS_RSA_WITH_AES_128_CBC_SHA256",
            0x003d => "TLS_RSA_WITH_AES_256_CBC_SHA256",
            0x009c => "TLS_RSA_WITH_AES_128_GCM_SHA256",
            0x009d => "TLS_RSA_WITH_AES_256_GCM_SHA384",
            0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
            0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
            _ => "Unknown",
        }
    }
}

/// Named groups for key exchange (IANA registry).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NamedGroup(pub u16);

impl NamedGroup {
    pub const SECP256R1: Self = Self(0x0017);
    pub const SECP384R1: Self = Self(0x0018);
    pub const SECP521R1: Self = Self(0x0019);
    pub const X25519: Self = Self(0x001d);
    pub const X448: Self = Self(0x001e);
    pub const FFDHE2048: Self = Self(0x0100);
    pub const FFDHE3072: Self = Self(0x0101);
    pub const FFDHE4096: Self = Self(0x0102);
    pub const FFDHE6144: Self = Self(0x0103);
    pub const FFDHE8192: Self = Self(0x0104);

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.0 {
            0x0017 => "secp256r1",
            0x0018 => "secp384r1",
            0x0019 => "secp521r1",
            0x001d => "x25519",
            0x001e => "x448",
            0x0100 => "ffdhe2048",
            0x0101 => "ffdhe3072",
            0x0102 => "ffdhe4096",
            0x0103 => "ffdhe6144",
            0x0104 => "ffdhe8192",
            _ => "unknown",
        }
    }
}

/// Signature scheme IDs (RFC 8446 Section 4.2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureScheme(pub u16);

impl SignatureScheme {
    pub const RSA_PKCS1_SHA256: Self = Self(0x0401);
    pub const RSA_PKCS1_SHA384: Self = Self(0x0501);
    pub const RSA_PKCS1_SHA512: Self = Self(0x0601);
    pub const ECDSA_SECP256R1_SHA256: Self = Self(0x0403);
    pub const ECDSA_SECP384R1_SHA384: Self = Self(0x0503);
    pub const ECDSA_SECP521R1_SHA512: Self = Self(0x0603);
    pub const RSA_PSS_RSAE_SHA256: Self = Self(0x0804);
    pub const RSA_PSS_RSAE_SHA384: Self = Self(0x0805);
    pub const RSA_PSS_RSAE_SHA512: Self = Self(0x0806);
    pub const ED25519: Self = Self(0x0807);
    pub const ED448: Self = Self(0x0808);
    pub const RSA_PKCS1_SHA1: Self = Self(0x0201);
    pub const ECDSA_SHA1: Self = Self(0x0203);

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self.0 {
            0x0401 => "rsa_pkcs1_sha256",
            0x0501 => "rsa_pkcs1_sha384",
            0x0601 => "rsa_pkcs1_sha512",
            0x0403 => "ecdsa_secp256r1_sha256",
            0x0503 => "ecdsa_secp384r1_sha384",
            0x0603 => "ecdsa_secp521r1_sha512",
            0x0804 => "rsa_pss_rsae_sha256",
            0x0805 => "rsa_pss_rsae_sha384",
            0x0806 => "rsa_pss_rsae_sha512",
            0x0807 => "ed25519",
            0x0808 => "ed448",
            0x0201 => "rsa_pkcs1_sha1",
            0x0203 => "ecdsa_sha1",
            _ => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_type() {
        assert_eq!(TlsContentType::from_u8(22), TlsContentType::Handshake);
        assert_eq!(TlsContentType::Handshake.as_u8(), 22);
        assert_eq!(TlsContentType::Handshake.name(), "handshake");
    }

    #[test]
    fn test_tls_version() {
        let v = TlsVersion::TLS12;
        assert_eq!(v.name(), "TLS 1.2");
        assert!(!v.is_tls13());
        assert!(!v.is_sslv2());

        let v13 = TlsVersion::TLS13;
        assert!(v13.is_tls13());
        assert_eq!(v13.record_version(), 0x0301);
    }

    #[test]
    fn test_handshake_type() {
        assert_eq!(HandshakeType::CLIENT_HELLO.name(), "ClientHello");
        assert_eq!(HandshakeType::SERVER_HELLO.0, 2);
    }

    #[test]
    fn test_alert_description() {
        assert_eq!(
            TlsAlertDescription::HANDSHAKE_FAILURE.name(),
            "handshake_failure"
        );
    }

    #[test]
    fn test_extension_type() {
        assert_eq!(ExtensionType::SERVER_NAME.name(), "server_name");
        assert_eq!(ExtensionType::KEY_SHARE.0, 51);
    }

    #[test]
    fn test_named_group() {
        assert_eq!(NamedGroup::X25519.name(), "x25519");
        assert_eq!(NamedGroup::SECP256R1.0, 0x0017);
    }
}
