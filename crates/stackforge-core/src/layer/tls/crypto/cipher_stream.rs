//! Stream cipher implementations for TLS.
//!
//! Provides `Cipher_NULL` and optionally RC4 (behind `tls-weak-crypto` feature).

/// Stream cipher trait for TLS.
pub trait StreamCipher: Send + Sync {
    /// Encrypt data in place and return ciphertext.
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8>;
    /// Decrypt data in place and return plaintext.
    fn decrypt(&mut self, data: &[u8]) -> Vec<u8>;
    /// Key length in bytes.
    fn key_len(&self) -> usize;
    /// Name of this cipher.
    fn name(&self) -> &'static str;
}

/// NULL cipher - no encryption.
#[derive(Debug, Clone, Default)]
pub struct CipherNull;

impl CipherNull {
    #[must_use]
    pub fn new(_key: &[u8]) -> Self {
        Self
    }
}

impl StreamCipher for CipherNull {
    fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
        data.to_vec()
    }

    fn key_len(&self) -> usize {
        0
    }

    fn name(&self) -> &'static str {
        "NULL"
    }
}

/// RC4 stream cipher (feature-gated: tls-weak-crypto).
#[cfg(feature = "tls-weak-crypto")]
pub mod rc4 {
    use super::StreamCipher;
    use rc4::{KeyInit, StreamCipher as Rc4StreamCipher};

    /// RC4-128 stream cipher.
    #[derive(Debug)]
    pub struct CipherRc4_128 {
        enc: rc4::Rc4<rc4::consts::U16>,
        dec: rc4::Rc4<rc4::consts::U16>,
    }

    impl CipherRc4_128 {
        pub fn new(key: &[u8]) -> Self {
            assert!(key.len() >= 16, "RC4-128 requires 16-byte key");
            let enc = rc4::Rc4::<rc4::consts::U16>::new_from_slice(&key[..16]).unwrap();
            let dec = rc4::Rc4::<rc4::consts::U16>::new_from_slice(&key[..16]).unwrap();
            Self { enc, dec }
        }
    }

    impl StreamCipher for CipherRc4_128 {
        fn encrypt(&mut self, data: &[u8]) -> Vec<u8> {
            let mut buf = data.to_vec();
            self.enc.apply_keystream(&mut buf);
            buf
        }

        fn decrypt(&mut self, data: &[u8]) -> Vec<u8> {
            let mut buf = data.to_vec();
            self.dec.apply_keystream(&mut buf);
            buf
        }

        fn key_len(&self) -> usize {
            16
        }

        fn name(&self) -> &'static str {
            "RC4_128"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_null() {
        let mut cipher = CipherNull::new(&[]);
        let plaintext = b"Hello, TLS!";
        let ciphertext = cipher.encrypt(plaintext);
        assert_eq!(&ciphertext, plaintext);
        let decrypted = cipher.decrypt(&ciphertext);
        assert_eq!(&decrypted, plaintext);
    }
}
