//! TLS Key Exchange implementations.
//!
//! Provides ECDHE (P-256, X25519) and DHE key exchange for TLS handshakes.
//! Each key exchange generates an ephemeral keypair and computes a shared secret.

#[cfg(feature = "tls")]
pub mod ecdhe;

/// Key exchange algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KxAlgorithm {
    /// RSA key exchange (pre-master secret encrypted with server's RSA key).
    Rsa,
    /// Diffie-Hellman Ephemeral.
    Dhe,
    /// Elliptic Curve Diffie-Hellman Ephemeral (P-256).
    EcdheSecp256r1,
    /// Elliptic Curve Diffie-Hellman Ephemeral (X25519).
    EcdheX25519,
}

/// Result of a key exchange operation.
#[derive(Debug, Clone)]
pub struct KxResult {
    /// Our public key to send to the peer.
    pub public_key: Vec<u8>,
    /// The shared secret (pre-master secret for TLS 1.2, or raw ECDH output for TLS 1.3).
    pub shared_secret: Vec<u8>,
}

/// Key exchange group trait.
#[cfg(feature = "tls")]
pub trait KeyExchange: Send {
    /// Generate an ephemeral keypair.
    /// Returns the public key bytes to send in KeyShare/ClientKeyExchange.
    fn generate(&mut self) -> Vec<u8>;

    /// Compute the shared secret from the peer's public key.
    /// Returns None if the peer's key is invalid.
    fn compute_shared_secret(&self, peer_public: &[u8]) -> Option<Vec<u8>>;

    /// Get the named group ID for this key exchange.
    fn group_id(&self) -> u16;
}
