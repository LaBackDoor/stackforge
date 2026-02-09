//! AEAD cipher implementations for TLS.
//!
//! Provides AES-GCM and ChaCha20-Poly1305 for TLS 1.2 and TLS 1.3.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce as AesGcmNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChachaNonce};

/// Error for AEAD operations.
#[derive(Debug, Clone)]
pub enum AeadError {
    /// Authentication tag verification failed.
    AuthenticationFailed,
    /// Invalid key length.
    InvalidKeyLength,
    /// Invalid nonce length.
    InvalidNonceLength,
    /// Encryption failed.
    EncryptionFailed,
}

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AuthenticationFailed => write!(f, "AEAD authentication failed"),
            Self::InvalidKeyLength => write!(f, "invalid key length"),
            Self::InvalidNonceLength => write!(f, "invalid nonce length"),
            Self::EncryptionFailed => write!(f, "encryption failed"),
        }
    }
}

/// AEAD cipher trait for TLS.
pub trait AeadCipher: Send + Sync {
    /// Authenticated encryption.
    ///
    /// Returns ciphertext with appended authentication tag.
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AeadError>;

    /// Authenticated decryption.
    ///
    /// Input should be ciphertext with appended authentication tag.
    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError>;

    /// Key length in bytes.
    fn key_len(&self) -> usize;

    /// Nonce/IV length in bytes.
    fn nonce_len(&self) -> usize;

    /// Authentication tag length in bytes.
    fn tag_len(&self) -> usize;

    /// Name of this cipher.
    fn name(&self) -> &'static str;
}

/// TLS 1.2 AEAD nonce construction.
///
/// nonce = fixed_iv (4 bytes) + explicit_nonce (8 bytes from record)
pub fn tls12_nonce(fixed_iv: &[u8], explicit_nonce: &[u8]) -> Vec<u8> {
    let mut nonce = Vec::with_capacity(fixed_iv.len() + explicit_nonce.len());
    nonce.extend_from_slice(fixed_iv);
    nonce.extend_from_slice(explicit_nonce);
    nonce
}

/// TLS 1.3 AEAD nonce construction.
///
/// nonce = iv XOR padded_seq_num
pub fn tls13_nonce(iv: &[u8], seq_num: u64) -> Vec<u8> {
    let mut nonce = iv.to_vec();
    let seq_bytes = seq_num.to_be_bytes();
    let offset = nonce.len() - 8;
    for i in 0..8 {
        nonce[offset + i] ^= seq_bytes[i];
    }
    nonce
}

/// AES-128-GCM cipher.
pub struct CipherAes128Gcm {
    cipher: Aes128Gcm,
}

impl CipherAes128Gcm {
    pub fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != 16 {
            return Err(AeadError::InvalidKeyLength);
        }
        let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength)?;
        Ok(Self { cipher })
    }
}

impl AeadCipher for CipherAes128Gcm {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        if nonce.len() != 12 {
            return Err(AeadError::InvalidNonceLength);
        }
        let n = AesGcmNonce::from_slice(nonce);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(n, payload)
            .map_err(|_| AeadError::EncryptionFailed)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if nonce.len() != 12 {
            return Err(AeadError::InvalidNonceLength);
        }
        let n = AesGcmNonce::from_slice(nonce);
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext_with_tag,
            aad,
        };
        self.cipher
            .decrypt(n, payload)
            .map_err(|_| AeadError::AuthenticationFailed)
    }

    fn key_len(&self) -> usize {
        16
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn name(&self) -> &'static str {
        "AES_128_GCM"
    }
}

/// AES-256-GCM cipher.
pub struct CipherAes256Gcm {
    cipher: Aes256Gcm,
}

impl CipherAes256Gcm {
    pub fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != 32 {
            return Err(AeadError::InvalidKeyLength);
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength)?;
        Ok(Self { cipher })
    }
}

impl AeadCipher for CipherAes256Gcm {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        if nonce.len() != 12 {
            return Err(AeadError::InvalidNonceLength);
        }
        let n = AesGcmNonce::from_slice(nonce);
        let payload = aes_gcm::aead::Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(n, payload)
            .map_err(|_| AeadError::EncryptionFailed)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if nonce.len() != 12 {
            return Err(AeadError::InvalidNonceLength);
        }
        let n = AesGcmNonce::from_slice(nonce);
        let payload = aes_gcm::aead::Payload {
            msg: ciphertext_with_tag,
            aad,
        };
        self.cipher
            .decrypt(n, payload)
            .map_err(|_| AeadError::AuthenticationFailed)
    }

    fn key_len(&self) -> usize {
        32
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn name(&self) -> &'static str {
        "AES_256_GCM"
    }
}

/// ChaCha20-Poly1305 cipher.
pub struct CipherChaCha20Poly1305 {
    cipher: ChaCha20Poly1305,
}

impl CipherChaCha20Poly1305 {
    pub fn new(key: &[u8]) -> Result<Self, AeadError> {
        if key.len() != 32 {
            return Err(AeadError::InvalidKeyLength);
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError::InvalidKeyLength)?;
        Ok(Self { cipher })
    }
}

impl AeadCipher for CipherChaCha20Poly1305 {
    fn encrypt(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, AeadError> {
        if nonce.len() != 12 {
            return Err(AeadError::InvalidNonceLength);
        }
        let n = ChachaNonce::from_slice(nonce);
        let payload = chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad,
        };
        self.cipher
            .encrypt(n, payload)
            .map_err(|_| AeadError::EncryptionFailed)
    }

    fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
    ) -> Result<Vec<u8>, AeadError> {
        if nonce.len() != 12 {
            return Err(AeadError::InvalidNonceLength);
        }
        let n = ChachaNonce::from_slice(nonce);
        let payload = chacha20poly1305::aead::Payload {
            msg: ciphertext_with_tag,
            aad,
        };
        self.cipher
            .decrypt(n, payload)
            .map_err(|_| AeadError::AuthenticationFailed)
    }

    fn key_len(&self) -> usize {
        32
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn name(&self) -> &'static str {
        "CHACHA20_POLY1305"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes128_gcm_roundtrip() {
        let key = vec![0x42; 16];
        let nonce = vec![0x00; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, AEAD!";

        let cipher = CipherAes128Gcm::new(&key).unwrap();
        let ciphertext = cipher.encrypt(&nonce, aad, plaintext).unwrap();
        // Ciphertext is plaintext.len() + 16 (tag)
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = cipher.decrypt(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aes256_gcm_roundtrip() {
        let key = vec![0x42; 32];
        let nonce = vec![0x00; 12];
        let aad = b"test aad";
        let plaintext = b"Hello, AES-256-GCM!";

        let cipher = CipherAes256Gcm::new(&key).unwrap();
        let ciphertext = cipher.encrypt(&nonce, aad, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_chacha20_poly1305_roundtrip() {
        let key = vec![0x42; 32];
        let nonce = vec![0x00; 12];
        let aad = b"test aad";
        let plaintext = b"Hello, ChaCha20!";

        let cipher = CipherChaCha20Poly1305::new(&key).unwrap();
        let ciphertext = cipher.encrypt(&nonce, aad, plaintext).unwrap();
        let decrypted = cipher.decrypt(&nonce, aad, &ciphertext).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aead_auth_failure() {
        let key = vec![0x42; 16];
        let nonce = vec![0x00; 12];
        let aad = b"correct aad";
        let plaintext = b"test data";

        let cipher = CipherAes128Gcm::new(&key).unwrap();
        let ciphertext = cipher.encrypt(&nonce, aad, plaintext).unwrap();

        // Try decrypting with wrong AAD
        let result = cipher.decrypt(&nonce, b"wrong aad", &ciphertext);
        assert!(result.is_err());
    }

    #[test]
    fn test_tls12_nonce() {
        let fixed_iv = vec![0x01, 0x02, 0x03, 0x04];
        let explicit = vec![0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c];
        let nonce = tls12_nonce(&fixed_iv, &explicit);
        assert_eq!(nonce.len(), 12);
        assert_eq!(&nonce[..4], &fixed_iv);
        assert_eq!(&nonce[4..], &explicit);
    }

    #[test]
    fn test_tls13_nonce() {
        let iv = vec![0x00; 12];
        let nonce = tls13_nonce(&iv, 1);
        assert_eq!(nonce.len(), 12);
        // Last byte should be 1 (XOR with seq_num=1)
        assert_eq!(nonce[11], 0x01);
    }

    #[test]
    fn test_tls13_nonce_xor() {
        let iv = vec![0xff; 12];
        let nonce = tls13_nonce(&iv, 0);
        // XOR with 0 should keep iv unchanged
        assert_eq!(&nonce, &iv);

        let nonce = tls13_nonce(&iv, 1);
        assert_eq!(nonce[11], 0xfe); // 0xff ^ 0x01
    }
}
