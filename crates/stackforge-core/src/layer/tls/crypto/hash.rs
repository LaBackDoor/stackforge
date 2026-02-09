//! TLS hash algorithm abstractions.
//!
//! Wraps digest crates to provide a unified TLS hash interface.

use digest::Digest;

/// Supported TLS hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TlsHash {
    Null,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
}

impl TlsHash {
    /// Returns the hash output length in bytes.
    pub fn hash_len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Md5 => 16,
            Self::Sha1 => 20,
            Self::Sha224 => 28,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Returns the internal block size in bytes.
    pub fn block_len(&self) -> usize {
        match self {
            Self::Null => 0,
            Self::Md5 => 64,
            Self::Sha1 => 64,
            Self::Sha224 => 64,
            Self::Sha256 => 64,
            Self::Sha384 => 128,
            Self::Sha512 => 128,
        }
    }

    /// Compute the hash of the given data.
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Null => vec![],
            Self::Md5 => {
                let mut hasher = md5::Md5::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Self::Sha1 => {
                let mut hasher = sha1::Sha1::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Self::Sha224 => {
                let mut hasher = sha2::Sha224::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Self::Sha256 => {
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Self::Sha384 => {
                let mut hasher = sha2::Sha384::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            Self::Sha512 => {
                let mut hasher = sha2::Sha512::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        }
    }

    /// Get a TlsHash from a name string (case-insensitive).
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "null" => Some(Self::Null),
            "md5" => Some(Self::Md5),
            "sha" | "sha1" | "sha-1" => Some(Self::Sha1),
            "sha224" | "sha-224" => Some(Self::Sha224),
            "sha256" | "sha-256" => Some(Self::Sha256),
            "sha384" | "sha-384" => Some(Self::Sha384),
            "sha512" | "sha-512" => Some(Self::Sha512),
            _ => None,
        }
    }

    /// Name of this hash algorithm.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Null => "NULL",
            Self::Md5 => "MD5",
            Self::Sha1 => "SHA",
            Self::Sha224 => "SHA224",
            Self::Sha256 => "SHA256",
            Self::Sha384 => "SHA384",
            Self::Sha512 => "SHA512",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_lengths() {
        assert_eq!(TlsHash::Md5.hash_len(), 16);
        assert_eq!(TlsHash::Sha1.hash_len(), 20);
        assert_eq!(TlsHash::Sha256.hash_len(), 32);
        assert_eq!(TlsHash::Sha384.hash_len(), 48);
        assert_eq!(TlsHash::Sha512.hash_len(), 64);
    }

    #[test]
    fn test_md5_digest() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let result = TlsHash::Md5.digest(b"");
        let expected = vec![
            0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8,
            0x42, 0x7e,
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_sha1_digest() {
        // SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
        let result = TlsHash::Sha1.digest(b"");
        assert_eq!(result.len(), 20);
        assert_eq!(result[0], 0xda);
        assert_eq!(result[1], 0x39);
    }

    #[test]
    fn test_sha256_digest() {
        // SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let result = TlsHash::Sha256.digest(b"");
        assert_eq!(result.len(), 32);
        assert_eq!(result[0], 0xe3);
        assert_eq!(result[1], 0xb0);
    }

    #[test]
    fn test_from_name() {
        assert_eq!(TlsHash::from_name("SHA256"), Some(TlsHash::Sha256));
        assert_eq!(TlsHash::from_name("sha"), Some(TlsHash::Sha1));
        assert_eq!(TlsHash::from_name("md5"), Some(TlsHash::Md5));
        assert_eq!(TlsHash::from_name("unknown"), None);
    }
}
