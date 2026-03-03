//! ECDHE key exchange implementations.
//!
//! Supports P-256 (secp256r1) and X25519 key exchanges for TLS 1.2 and 1.3.

use super::KeyExchange;

// ─── X25519 ────────────────────────────────────────────────────────────────────

/// X25519 key exchange (Curve25519 ECDH).
pub struct X25519Kx {
    secret_key: Option<x25519_dalek::StaticSecret>,
    public_key: Option<x25519_dalek::PublicKey>,
}

impl X25519Kx {
    /// Create a new X25519 key exchange instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secret_key: None,
            public_key: None,
        }
    }

    /// Create from an existing secret key (for testing/replay).
    #[must_use]
    pub fn from_secret(secret_bytes: [u8; 32]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(secret_bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self {
            secret_key: Some(secret),
            public_key: Some(public),
        }
    }
}

impl Default for X25519Kx {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyExchange for X25519Kx {
    fn generate(&mut self) -> Vec<u8> {
        let secret = x25519_dalek::StaticSecret::random();
        let public = x25519_dalek::PublicKey::from(&secret);
        let pub_bytes = public.as_bytes().to_vec();
        self.secret_key = Some(secret);
        self.public_key = Some(public);
        pub_bytes
    }

    fn compute_shared_secret(&self, peer_public: &[u8]) -> Option<Vec<u8>> {
        let secret = self.secret_key.as_ref()?;
        if peer_public.len() != 32 {
            return None;
        }
        let mut peer_bytes = [0u8; 32];
        peer_bytes.copy_from_slice(peer_public);
        let peer_public = x25519_dalek::PublicKey::from(peer_bytes);
        let shared = secret.diffie_hellman(&peer_public);

        // Check for all-zero shared secret (low-order point)
        if shared.as_bytes().iter().all(|&b| b == 0) {
            return None;
        }

        Some(shared.as_bytes().to_vec())
    }

    fn group_id(&self) -> u16 {
        0x001D // x25519
    }
}

// ─── P-256 (secp256r1) ─────────────────────────────────────────────────────────

/// P-256 (secp256r1) key exchange.
///
/// Uses `p256::SecretKey` internally so we can store it (unlike `EphemeralSecret`
/// which is consumed on `diffie_hellman`). The shared secret is computed via
/// the ECDH primitive.
pub struct P256Kx {
    secret_key: Option<p256::SecretKey>,
    public_key: Option<p256::PublicKey>,
}

impl P256Kx {
    /// Create a new P-256 key exchange instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            secret_key: None,
            public_key: None,
        }
    }
}

impl Default for P256Kx {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyExchange for P256Kx {
    fn generate(&mut self) -> Vec<u8> {
        let secret = p256::SecretKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        let public = secret.public_key();
        // Encode as uncompressed point (0x04 || x || y), 65 bytes
        let encoded = p256::EncodedPoint::from(public);
        let pub_bytes = encoded.as_bytes().to_vec();
        self.public_key = Some(public);
        self.secret_key = Some(secret);
        pub_bytes
    }

    fn compute_shared_secret(&self, peer_public: &[u8]) -> Option<Vec<u8>> {
        let secret = self.secret_key.as_ref()?;

        // Parse the peer's public key from SEC1 encoding
        let peer_key = p256::PublicKey::from_sec1_bytes(peer_public).ok()?;

        // Compute ECDH shared secret
        let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), peer_key.as_affine());
        Some(shared.raw_secret_bytes().to_vec())
    }

    fn group_id(&self) -> u16 {
        0x0017 // secp256r1
    }
}

/// Create a key exchange instance for the given named group ID.
#[must_use]
pub fn kx_for_group(group_id: u16) -> Option<Box<dyn KeyExchange>> {
    match group_id {
        0x001D => Some(Box::new(X25519Kx::new())),
        0x0017 => Some(Box::new(P256Kx::new())),
        _ => None,
    }
}

/// Build a TLS 1.3 `KeyShareEntry` (group:2 + length:2 + `key_exchange`).
#[must_use]
pub fn build_key_share_entry(group_id: u16, public_key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + public_key.len());
    buf.extend_from_slice(&group_id.to_be_bytes());
    buf.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    buf.extend_from_slice(public_key);
    buf
}

/// Parse a TLS 1.3 `KeyShareEntry`, returning (`group_id`, `key_exchange_bytes`).
#[must_use]
pub fn parse_key_share_entry(data: &[u8]) -> Option<(u16, Vec<u8>)> {
    if data.len() < 4 {
        return None;
    }
    let group_id = u16::from_be_bytes([data[0], data[1]]);
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + len {
        return None;
    }
    Some((group_id, data[4..4 + len].to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_key_exchange() {
        let mut client = X25519Kx::new();
        let mut server = X25519Kx::new();

        let client_pub = client.generate();
        let server_pub = server.generate();

        assert_eq!(client_pub.len(), 32);
        assert_eq!(server_pub.len(), 32);
        assert_eq!(client.group_id(), 0x001D);

        let client_shared = client.compute_shared_secret(&server_pub).unwrap();
        let server_shared = server.compute_shared_secret(&client_pub).unwrap();

        assert_eq!(client_shared, server_shared);
        assert_eq!(client_shared.len(), 32);
    }

    #[test]
    fn test_x25519_from_known_secret() {
        // RFC 7748 test vector
        let alice_secret: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_secret: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];

        let alice = X25519Kx::from_secret(alice_secret);
        let bob = X25519Kx::from_secret(bob_secret);

        let alice_pub = alice.public_key.as_ref().unwrap().as_bytes().to_vec();
        let bob_pub = bob.public_key.as_ref().unwrap().as_bytes().to_vec();

        let alice_shared = alice.compute_shared_secret(&bob_pub).unwrap();
        let bob_shared = bob.compute_shared_secret(&alice_pub).unwrap();

        assert_eq!(alice_shared, bob_shared);

        // Expected shared secret from RFC 7748
        let expected: Vec<u8> = vec![
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        assert_eq!(alice_shared, expected);
    }

    #[test]
    fn test_x25519_invalid_peer_key() {
        let mut kx = X25519Kx::new();
        kx.generate();

        // Wrong length
        assert!(kx.compute_shared_secret(&[0u8; 31]).is_none());
        assert!(kx.compute_shared_secret(&[0u8; 33]).is_none());
    }

    #[test]
    fn test_p256_key_exchange() {
        let mut client = P256Kx::new();
        let mut server = P256Kx::new();

        let client_pub = client.generate();
        let server_pub = server.generate();

        assert_eq!(client_pub.len(), 65); // Uncompressed point
        assert_eq!(client_pub[0], 0x04); // Uncompressed marker
        assert_eq!(client.group_id(), 0x0017);

        let client_shared = client.compute_shared_secret(&server_pub).unwrap();
        let server_shared = server.compute_shared_secret(&client_pub).unwrap();

        assert_eq!(client_shared, server_shared);
        assert_eq!(client_shared.len(), 32); // P-256 shared secret is 32 bytes
    }

    #[test]
    fn test_p256_invalid_peer_key() {
        let mut kx = P256Kx::new();
        kx.generate();

        // Invalid point (all zeros except prefix)
        let mut bad_point = vec![0x04];
        bad_point.extend_from_slice(&[0u8; 64]);
        assert!(kx.compute_shared_secret(&bad_point).is_none());

        // Wrong length
        assert!(kx.compute_shared_secret(&[0u8; 10]).is_none());
    }

    #[test]
    fn test_kx_for_group() {
        let x25519 = kx_for_group(0x001D);
        assert!(x25519.is_some());

        let p256 = kx_for_group(0x0017);
        assert!(p256.is_some());

        let unknown = kx_for_group(0x9999);
        assert!(unknown.is_none());
    }

    #[test]
    fn test_kx_for_group_full_exchange() {
        for group_id in &[0x001D, 0x0017] {
            let mut client = kx_for_group(*group_id).unwrap();
            let mut server = kx_for_group(*group_id).unwrap();

            let client_pub = client.generate();
            let server_pub = server.generate();

            let client_shared = client.compute_shared_secret(&server_pub).unwrap();
            let server_shared = server.compute_shared_secret(&client_pub).unwrap();

            assert_eq!(
                client_shared, server_shared,
                "Failed for group 0x{:04x}",
                group_id
            );
        }
    }

    #[test]
    fn test_build_parse_key_share_entry() {
        let group_id = 0x001D;
        let pub_key = vec![0x01, 0x02, 0x03, 0x04];

        let entry = build_key_share_entry(group_id, &pub_key);
        assert_eq!(entry.len(), 8); // 2 + 2 + 4

        let (parsed_group, parsed_key) = parse_key_share_entry(&entry).unwrap();
        assert_eq!(parsed_group, group_id);
        assert_eq!(parsed_key, pub_key);
    }

    #[test]
    fn test_parse_key_share_entry_too_short() {
        assert!(parse_key_share_entry(&[0x00, 0x1D, 0x00]).is_none());
        assert!(parse_key_share_entry(&[]).is_none());
    }

    #[test]
    fn test_x25519_no_generate_returns_none() {
        let kx = X25519Kx::new();
        assert!(kx.compute_shared_secret(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_p256_no_generate_returns_none() {
        let kx = P256Kx::new();
        assert!(kx.compute_shared_secret(&[0x04; 65]).is_none());
    }
}
