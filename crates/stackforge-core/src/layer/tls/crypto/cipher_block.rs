//! Block cipher implementations for TLS.
//!
//! Provides AES-CBC (and optionally 3DES-CBC behind `tls-weak-crypto`).

use cbc::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

/// Error type for block cipher operations.
#[derive(Debug, Clone)]
pub enum BlockCipherError {
    /// Invalid padding.
    BadPadding,
    /// Buffer too short.
    BufferTooShort,
    /// Invalid key or IV length.
    InvalidKeyOrIv,
}

impl std::fmt::Display for BlockCipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadPadding => write!(f, "bad padding"),
            Self::BufferTooShort => write!(f, "buffer too short"),
            Self::InvalidKeyOrIv => write!(f, "invalid key or IV length"),
        }
    }
}

/// Block cipher trait for TLS.
pub trait BlockCipher: Send + Sync {
    /// Encrypt with CBC mode. Returns ciphertext.
    fn encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockCipherError>;
    /// Decrypt with CBC mode.
    fn decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockCipherError>;
    /// Key length in bytes.
    fn key_len(&self) -> usize;
    /// Block size in bytes.
    fn block_size(&self) -> usize;
    /// Name of this cipher.
    fn name(&self) -> &'static str;
}

/// Add TLS CBC padding.
#[must_use]
pub fn add_tls_padding(data: &[u8], block_size: usize) -> Vec<u8> {
    let padding_len = block_size - (data.len() % block_size);
    let pad_byte = (padding_len - 1) as u8;
    let mut result = Vec::with_capacity(data.len() + padding_len);
    result.extend_from_slice(data);
    result.extend(std::iter::repeat_n(pad_byte, padding_len));
    result
}

/// Remove and verify TLS CBC padding.
pub fn remove_tls_padding(data: &[u8]) -> Result<&[u8], BlockCipherError> {
    if data.is_empty() {
        return Err(BlockCipherError::BadPadding);
    }
    let pad_byte = data[data.len() - 1] as usize;
    let pad_len = pad_byte + 1;
    if pad_len > data.len() {
        return Err(BlockCipherError::BadPadding);
    }
    for &b in &data[data.len() - pad_len..] {
        if b as usize != pad_byte {
            return Err(BlockCipherError::BadPadding);
        }
    }
    Ok(&data[..data.len() - pad_len])
}

/// Generic CBC encrypt using the cbc crate with `NoPadding`.
fn cbc_encrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, BlockCipherError>
where
    C: cbc::cipher::BlockEncrypt + cbc::cipher::BlockCipher + cbc::cipher::KeyInit,
{
    let enc = cbc::Encryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| BlockCipherError::InvalidKeyOrIv)?;
    // Data must already be padded to block size
    let mut buf = data.to_vec();
    // encrypt_padded_mut with NoPadding expects exact block alignment
    let result = enc
        .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf, data.len())
        .map_err(|_| BlockCipherError::BufferTooShort)?;
    Ok(result.to_vec())
}

/// Generic CBC decrypt using the cbc crate with `NoPadding`.
fn cbc_decrypt<C>(key: &[u8], iv: &[u8], data: &[u8]) -> Result<Vec<u8>, BlockCipherError>
where
    C: cbc::cipher::BlockDecrypt + cbc::cipher::BlockCipher + cbc::cipher::KeyInit,
{
    let dec = cbc::Decryptor::<C>::new_from_slices(key, iv)
        .map_err(|_| BlockCipherError::InvalidKeyOrIv)?;
    let mut buf = data.to_vec();
    let result = dec
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .map_err(|_| BlockCipherError::BadPadding)?;
    Ok(result.to_vec())
}

/// AES-128-CBC cipher.
#[derive(Debug, Clone)]
pub struct CipherAes128Cbc {
    key: Vec<u8>,
}

impl CipherAes128Cbc {
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if key.len() != 16 {
            return Err(BlockCipherError::InvalidKeyOrIv);
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl BlockCipher for CipherAes128Cbc {
    fn encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockCipherError> {
        if iv.len() != 16 {
            return Err(BlockCipherError::InvalidKeyOrIv);
        }
        let padded = add_tls_padding(data, 16);
        cbc_encrypt::<aes::Aes128>(&self.key, iv, &padded)
    }

    fn decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockCipherError> {
        if iv.len() != 16 {
            return Err(BlockCipherError::InvalidKeyOrIv);
        }
        if !data.len().is_multiple_of(16) {
            return Err(BlockCipherError::BufferTooShort);
        }
        cbc_decrypt::<aes::Aes128>(&self.key, iv, data)
    }

    fn key_len(&self) -> usize {
        16
    }

    fn block_size(&self) -> usize {
        16
    }

    fn name(&self) -> &'static str {
        "AES_128_CBC"
    }
}

/// AES-256-CBC cipher.
#[derive(Debug, Clone)]
pub struct CipherAes256Cbc {
    key: Vec<u8>,
}

impl CipherAes256Cbc {
    pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
        if key.len() != 32 {
            return Err(BlockCipherError::InvalidKeyOrIv);
        }
        Ok(Self { key: key.to_vec() })
    }
}

impl BlockCipher for CipherAes256Cbc {
    fn encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockCipherError> {
        if iv.len() != 16 {
            return Err(BlockCipherError::InvalidKeyOrIv);
        }
        let padded = add_tls_padding(data, 16);
        cbc_encrypt::<aes::Aes256>(&self.key, iv, &padded)
    }

    fn decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockCipherError> {
        if iv.len() != 16 {
            return Err(BlockCipherError::InvalidKeyOrIv);
        }
        if !data.len().is_multiple_of(16) {
            return Err(BlockCipherError::BufferTooShort);
        }
        cbc_decrypt::<aes::Aes256>(&self.key, iv, data)
    }

    fn key_len(&self) -> usize {
        32
    }

    fn block_size(&self) -> usize {
        16
    }

    fn name(&self) -> &'static str {
        "AES_256_CBC"
    }
}

/// 3DES-EDE-CBC cipher (feature-gated: tls-weak-crypto).
#[cfg(feature = "tls-weak-crypto")]
pub mod triple_des {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct Cipher3DesCbc {
        key: Vec<u8>,
    }

    impl Cipher3DesCbc {
        pub fn new(key: &[u8]) -> Result<Self, BlockCipherError> {
            if key.len() != 24 {
                return Err(BlockCipherError::InvalidKeyOrIv);
            }
            Ok(Self { key: key.to_vec() })
        }
    }

    impl BlockCipher for Cipher3DesCbc {
        fn encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockCipherError> {
            if iv.len() != 8 {
                return Err(BlockCipherError::InvalidKeyOrIv);
            }
            let padded = add_tls_padding(data, 8);
            cbc_encrypt::<des::TdesEde3>(&self.key, iv, &padded)
        }

        fn decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, BlockCipherError> {
            if iv.len() != 8 {
                return Err(BlockCipherError::InvalidKeyOrIv);
            }
            if data.len() % 8 != 0 {
                return Err(BlockCipherError::BufferTooShort);
            }
            cbc_decrypt::<des::TdesEde3>(&self.key, iv, data)
        }

        fn key_len(&self) -> usize {
            24
        }

        fn block_size(&self) -> usize {
            8
        }

        fn name(&self) -> &'static str {
            "3DES_EDE_CBC"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_padding() {
        let data = vec![0x41; 13];
        let padded = add_tls_padding(&data, 16);
        assert_eq!(padded.len(), 16);
        assert_eq!(padded[13], 0x02);
        assert_eq!(padded[14], 0x02);
        assert_eq!(padded[15], 0x02);

        let unpadded = remove_tls_padding(&padded).unwrap();
        assert_eq!(unpadded, &data[..]);
    }

    #[test]
    fn test_tls_padding_full_block() {
        let data = vec![0x41; 16];
        let padded = add_tls_padding(&data, 16);
        assert_eq!(padded.len(), 32);
        assert_eq!(padded[31], 0x0f);
    }

    #[test]
    fn test_bad_padding() {
        let data = vec![0x41, 0x42, 0x43, 0x05];
        assert!(remove_tls_padding(&data).is_err());
    }

    #[test]
    fn test_aes128_cbc_roundtrip() {
        let key = vec![0x42; 16];
        let iv = vec![0x00; 16];
        let plaintext = b"Hello, AES-128!";

        let cipher = CipherAes128Cbc::new(&key).unwrap();
        let ciphertext = cipher.encrypt(plaintext, &iv).unwrap();
        assert_ne!(&ciphertext[..], plaintext);

        let decrypted = cipher.decrypt(&ciphertext, &iv).unwrap();
        let unpadded = remove_tls_padding(&decrypted).unwrap();
        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_aes256_cbc_roundtrip() {
        let key = vec![0x42; 32];
        let iv = vec![0x00; 16];
        let plaintext = b"Hello, AES-256!";

        let cipher = CipherAes256Cbc::new(&key).unwrap();
        let ciphertext = cipher.encrypt(plaintext, &iv).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &iv).unwrap();
        let unpadded = remove_tls_padding(&decrypted).unwrap();
        assert_eq!(unpadded, plaintext);
    }

    #[test]
    fn test_aes128_invalid_key() {
        assert!(CipherAes128Cbc::new(&[0; 15]).is_err());
        assert!(CipherAes128Cbc::new(&[0; 17]).is_err());
    }
}
