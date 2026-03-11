//! Salted consistent hashing for identifiers.
//!
//! Provides deterministic hashing of MAC addresses, QUIC Connection IDs,
//! and other byte-string identifiers using a session-specific salt.
//! The same salt + identifier always produces the same output within a
//! session, allowing ML models to track entities over time.

use std::hash::{Hash, Hasher};

/// Consistent salted hasher for identifiers.
#[derive(Debug, Clone)]
pub struct SaltedHasher {
    salt: [u8; 32],
}

impl SaltedHasher {
    /// Create a new hasher with the given 32-byte salt.
    #[must_use]
    pub fn new(salt: [u8; 32]) -> Self {
        Self { salt }
    }

    /// Hash a MAC address (6 bytes) to a pseudonymous 6-byte MAC.
    ///
    /// Uses SipHash-1-3 (Rust's `DefaultHasher`) keyed with the salt.
    /// The 64-bit hash output is truncated to 48 bits.
    #[must_use]
    pub fn hash_mac(&self, mac: &[u8; 6]) -> [u8; 6] {
        let h = self.hash_bytes(mac);
        let bytes = h.to_le_bytes();
        [bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]]
    }

    /// Hash a MAC address preserving the OUI (first 3 bytes).
    ///
    /// This allows ML models to identify device manufacturers while
    /// still anonymizing the NIC-specific portion.
    #[must_use]
    pub fn hash_mac_preserve_oui(&self, mac: &[u8; 6]) -> [u8; 6] {
        let hashed = self.hash_mac(mac);
        [mac[0], mac[1], mac[2], hashed[3], hashed[4], hashed[5]]
    }

    /// Hash an arbitrary byte slice to a 64-bit value.
    #[must_use]
    pub fn hash_bytes(&self, data: &[u8]) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        self.salt.hash(&mut hasher);
        data.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        for (i, b) in salt.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        salt
    }

    #[test]
    fn test_mac_hash_deterministic() {
        let h = SaltedHasher::new(test_salt());
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(h.hash_mac(&mac), h.hash_mac(&mac));
    }

    #[test]
    fn test_mac_hash_changes_output() {
        let h = SaltedHasher::new(test_salt());
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let hashed = h.hash_mac(&mac);
        // Extremely unlikely to be identical
        assert_ne!(mac, hashed);
    }

    #[test]
    fn test_different_salt_different_output() {
        let mut salt2 = test_salt();
        salt2[0] = 0xFF;
        let h1 = SaltedHasher::new(test_salt());
        let h2 = SaltedHasher::new(salt2);
        let mac = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        assert_ne!(h1.hash_mac(&mac), h2.hash_mac(&mac));
    }

    #[test]
    fn test_preserve_oui() {
        let h = SaltedHasher::new(test_salt());
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let hashed = h.hash_mac_preserve_oui(&mac);
        // OUI preserved
        assert_eq!(hashed[0], 0xAA);
        assert_eq!(hashed[1], 0xBB);
        assert_eq!(hashed[2], 0xCC);
    }

    #[test]
    fn test_hash_bytes_consistent() {
        let h = SaltedHasher::new(test_salt());
        let data = b"test-connection-id";
        assert_eq!(h.hash_bytes(data), h.hash_bytes(data));
    }

    #[test]
    fn test_different_inputs_different_hashes() {
        let h = SaltedHasher::new(test_salt());
        let mac1 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mac2 = [0x00, 0x11, 0x22, 0x33, 0x44, 0x56];
        assert_ne!(h.hash_mac(&mac1), h.hash_mac(&mac2));
    }
}
