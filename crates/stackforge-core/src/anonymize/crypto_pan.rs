//! Crypto-PAn prefix-preserving IP address anonymization.
//!
//! Implements the algorithm by Xu, Fan, Ammar & Moon (2002) using AES-128
//! as the underlying block cipher. Two addresses sharing a *k*-bit network
//! prefix are guaranteed to share a *k*-bit prefix after anonymization.
//!
//! # Key format
//!
//! The 32-byte key is split into:
//! - bytes `[0..16]`: AES-128 encryption key
//! - bytes `[16..32]`: padding material used as the initial cipher input

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};

/// Crypto-PAn anonymizer backed by AES-128.
pub struct CryptoPan {
    cipher: Aes128,
    pad: [u8; 16],
    /// Cache mapping original IPs to their anonymized counterparts.
    cache: HashMap<IpAddr, IpAddr>,
}

impl std::fmt::Debug for CryptoPan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CryptoPan")
            .field("cache_size", &self.cache.len())
            .finish_non_exhaustive()
    }
}

impl CryptoPan {
    /// Create a new Crypto-PAn instance from a 32-byte key.
    ///
    /// - `key[0..16]` is the AES-128 key.
    /// - `key[16..32]` is the padding material.
    #[must_use]
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = Aes128::new(GenericArray::from_slice(&key[..16]));
        let mut pad = [0u8; 16];
        pad.copy_from_slice(&key[16..32]);
        Self {
            cipher,
            pad,
            cache: HashMap::new(),
        }
    }

    /// Encrypt a single 128-bit block in-place.
    fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut ga = GenericArray::clone_from_slice(block);
        self.cipher.encrypt_block(&mut ga);
        block.copy_from_slice(ga.as_slice());
    }

    /// Anonymize an IPv4 address (prefix-preserving).
    #[must_use]
    pub fn anonymize_ipv4(&self, addr: Ipv4Addr) -> Ipv4Addr {
        let orig = u32::from(addr);
        let mut result: u32 = 0;

        // Base input block: start with pad, replace first 4 bytes as we go
        let mut input = self.pad;

        let pad_first4 = u32::from_be_bytes([self.pad[0], self.pad[1], self.pad[2], self.pad[3]]);

        for pos in 0..32u32 {
            // Build input: first `pos` bits from original address, rest from pad
            let first4 = if pos == 0 {
                pad_first4
            } else {
                let mask = 0xFFFF_FFFFu32.wrapping_shl(32 - pos);
                (orig & mask) | (pad_first4 & !mask)
            };

            input[0] = (first4 >> 24) as u8;
            input[1] = (first4 >> 16) as u8;
            input[2] = (first4 >> 8) as u8;
            input[3] = first4 as u8;
            // input[4..16] stays as pad[4..16]

            let mut output = input;
            self.encrypt_block(&mut output);

            // Use the MSB of the encrypted output
            let bit = u32::from(output[0] >> 7);
            result |= bit << (31 - pos);
        }

        Ipv4Addr::from(result ^ orig)
    }

    /// Anonymize an IPv6 address (prefix-preserving).
    #[must_use]
    pub fn anonymize_ipv6(&self, addr: Ipv6Addr) -> Ipv6Addr {
        let orig = u128::from(addr);
        let mut result: u128 = 0;

        let pad128 =
            u128::from_be_bytes(self.pad);

        for pos in 0..128u32 {
            // Build input: first `pos` bits from original, rest from pad
            let combined = if pos == 0 {
                pad128
            } else {
                let mask = u128::MAX.wrapping_shl(128 - pos);
                (orig & mask) | (pad128 & !mask)
            };

            let mut input = combined.to_be_bytes();
            self.encrypt_block(&mut input);

            let bit = u128::from(input[0] >> 7);
            result |= bit << (127 - pos);
        }

        Ipv6Addr::from(result ^ orig)
    }

    /// Anonymize an IP address, using the cache for repeated lookups.
    pub fn anonymize_ip(&mut self, addr: IpAddr) -> IpAddr {
        if let Some(&cached) = self.cache.get(&addr) {
            return cached;
        }
        let anon = match addr {
            IpAddr::V4(v4) => IpAddr::V4(self.anonymize_ipv4(v4)),
            IpAddr::V6(v6) => IpAddr::V6(self.anonymize_ipv6(v6)),
        };
        self.cache.insert(addr, anon);
        anon
    }

    /// Number of cached address mappings.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        key
    }

    #[test]
    fn test_deterministic() {
        let key = test_key();
        let c1 = CryptoPan::new(&key);
        let c2 = CryptoPan::new(&key);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        assert_eq!(c1.anonymize_ipv4(addr), c2.anonymize_ipv4(addr));
    }

    #[test]
    fn test_different_from_original() {
        let key = test_key();
        let cp = CryptoPan::new(&key);
        let addr = Ipv4Addr::new(192, 168, 1, 100);
        let anon = cp.anonymize_ipv4(addr);
        // Extremely unlikely to map to itself
        assert_ne!(addr, anon);
    }

    #[test]
    fn test_prefix_preservation_ipv4() {
        let key = test_key();
        let cp = CryptoPan::new(&key);

        // Two addresses on the same /24 subnet
        let a1 = Ipv4Addr::new(10, 0, 1, 1);
        let a2 = Ipv4Addr::new(10, 0, 1, 2);
        let anon1 = u32::from(cp.anonymize_ipv4(a1));
        let anon2 = u32::from(cp.anonymize_ipv4(a2));

        // They originally share a 30-bit prefix (differ only in last 2 bits).
        // After Crypto-PAn, they must share at least a 30-bit prefix.
        let orig1 = u32::from(a1);
        let orig2 = u32::from(a2);
        let shared_bits = (orig1 ^ orig2).leading_zeros();

        let anon_shared = (anon1 ^ anon2).leading_zeros();
        assert!(
            anon_shared >= shared_bits,
            "Expected at least {shared_bits} shared prefix bits, got {anon_shared}"
        );
    }

    #[test]
    fn test_prefix_preservation_different_subnets() {
        let key = test_key();
        let cp = CryptoPan::new(&key);

        // Two addresses on different /16 subnets
        let a1 = Ipv4Addr::new(10, 1, 0, 1);
        let a2 = Ipv4Addr::new(10, 2, 0, 1);
        let anon1 = u32::from(cp.anonymize_ipv4(a1));
        let anon2 = u32::from(cp.anonymize_ipv4(a2));

        let orig_shared = (u32::from(a1) ^ u32::from(a2)).leading_zeros();
        let anon_shared = (anon1 ^ anon2).leading_zeros();
        assert!(anon_shared >= orig_shared);
    }

    #[test]
    fn test_ipv6_deterministic() {
        let key = test_key();
        let c1 = CryptoPan::new(&key);
        let c2 = CryptoPan::new(&key);
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        assert_eq!(c1.anonymize_ipv6(addr), c2.anonymize_ipv6(addr));
    }

    #[test]
    fn test_ipv6_prefix_preservation() {
        let key = test_key();
        let cp = CryptoPan::new(&key);

        let a1 = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 1);
        let a2 = Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 2);
        let anon1 = u128::from(cp.anonymize_ipv6(a1));
        let anon2 = u128::from(cp.anonymize_ipv6(a2));

        let orig_shared = (u128::from(a1) ^ u128::from(a2)).leading_zeros();
        let anon_shared = (anon1 ^ anon2).leading_zeros();
        assert!(anon_shared >= orig_shared);
    }

    #[test]
    fn test_cache() {
        let key = test_key();
        let mut cp = CryptoPan::new(&key);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let first = cp.anonymize_ip(addr);
        assert_eq!(cp.cache_size(), 1);

        let second = cp.anonymize_ip(addr);
        assert_eq!(first, second);
        assert_eq!(cp.cache_size(), 1);
    }

    #[test]
    fn test_different_keys_different_results() {
        let key1 = test_key();
        let mut key2 = test_key();
        key2[0] = 0xFF;

        let c1 = CryptoPan::new(&key1);
        let c2 = CryptoPan::new(&key2);

        let addr = Ipv4Addr::new(10, 0, 0, 1);
        assert_ne!(c1.anonymize_ipv4(addr), c2.anonymize_ipv4(addr));
    }
}
