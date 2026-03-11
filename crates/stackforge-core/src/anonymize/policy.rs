//! Anonymization policy configuration.
//!
//! Defines the strategies applied to each protocol field during flow
//! anonymization. Users construct an [`AnonymizationPolicy`] describing
//! the desired privacy-utility trade-off, and pass it to the
//! [`AnonymizationEngine`](super::engine::AnonymizationEngine).

/// How to anonymize IPv4/IPv6 addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpAnonymizationMode {
    /// No anonymization -- IPs pass through unchanged.
    None,
    /// Prefix-preserving anonymization via Crypto-PAn (AES-128).
    ///
    /// Two addresses sharing a *k*-bit prefix will still share a *k*-bit
    /// prefix after anonymization, preserving subnet topology for ML models.
    CryptoPan,
}

/// How to anonymize MAC addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAnonymizationMode {
    /// No anonymization.
    None,
    /// Full salted hash (all 6 bytes). Destroys OUI information.
    SaltedHash,
    /// Preserve the OUI (first 3 bytes) and hash only the NIC-specific
    /// portion. Allows ML models to identify device manufacturers.
    SaltedHashPreserveOui,
}

/// How to anonymize transport ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortAnonymizationMode {
    /// No anonymization.
    None,
    /// Preserve well-known destination ports (0-1023) for service
    /// identification; generalize source/ephemeral ports to category
    /// sentinels (0 = well-known, 1024 = registered, 49152 = ephemeral).
    PreserveWellKnown,
    /// Generalize all ports to category sentinels.
    Categorize,
}

/// How to anonymize timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampAnonymizationMode {
    /// No anonymization.
    None,
    /// Shift all timestamps by a random epoch offset (preserves perfect
    /// ordering and all relative durations). The offset is generated once
    /// per engine session.
    EpochShift,
    /// Epoch shift plus bounded per-timestamp jitter. The `jitter_ms`
    /// value is the maximum uniform noise added to each timestamp.
    ///
    /// **Warning**: jitter may invert ordering of very close timestamps.
    /// Use small values (1-10 ms) for safety.
    EpochShiftWithJitter {
        /// Maximum jitter in milliseconds.
        jitter_ms: u32,
    },
}

/// How to handle TCP sequence/acknowledgment numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSeqAnonymizationMode {
    /// No anonymization.
    None,
    /// Add a random per-flow offset to all sequence and acknowledgment
    /// numbers. Preserves relative differences (bytes in flight,
    /// retransmission detection) while hiding absolute values.
    RandomOffset,
}

/// How to handle reassembled payload data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadAnonymizationMode {
    /// No anonymization -- full payload retained.
    None,
    /// Remove all reassembled payload data.
    TruncateAll,
    /// Keep only the first *n* bytes of each direction's reassembled stream.
    TruncateTo(usize),
}

/// Master anonymization policy.
///
/// Controls which cryptographic primitives and strategies are applied to
/// each protocol field category during flow export.
///
/// # Example
///
/// ```rust
/// use stackforge_core::anonymize::AnonymizationPolicy;
///
/// // ML-optimized defaults: prefix-preserving IPs, hashed MACs,
/// // well-known ports preserved, epoch-shifted timestamps, payload stripped.
/// let policy = AnonymizationPolicy::ml_optimized();
/// ```
#[derive(Debug, Clone)]
pub struct AnonymizationPolicy {
    /// IP address anonymization strategy.
    pub ip_mode: IpAnonymizationMode,
    /// MAC address anonymization strategy (applied if MAC data is
    /// present in flow metadata -- currently informational for future
    /// packet-level anonymization).
    pub mac_mode: MacAnonymizationMode,
    /// Transport port anonymization strategy.
    pub port_mode: PortAnonymizationMode,
    /// Timestamp anonymization strategy.
    pub timestamp_mode: TimestampAnonymizationMode,
    /// TCP sequence number anonymization strategy.
    pub tcp_seq_mode: TcpSeqAnonymizationMode,
    /// Reassembled payload handling.
    pub payload_mode: PayloadAnonymizationMode,
    /// 32-byte key for Crypto-PAn. First 16 bytes = AES-128 key,
    /// last 16 bytes = padding material.
    ///
    /// If `None` and `ip_mode` is `CryptoPan`, a random key is generated.
    pub crypto_pan_key: Option<[u8; 32]>,
    /// 32-byte salt for consistent hashing (MAC addresses, connection IDs).
    ///
    /// If `None`, a random salt is generated per engine session.
    pub hash_salt: Option<[u8; 32]>,
}

impl Default for AnonymizationPolicy {
    /// Default policy: no anonymization.
    fn default() -> Self {
        Self {
            ip_mode: IpAnonymizationMode::None,
            mac_mode: MacAnonymizationMode::None,
            port_mode: PortAnonymizationMode::None,
            timestamp_mode: TimestampAnonymizationMode::None,
            tcp_seq_mode: TcpSeqAnonymizationMode::None,
            payload_mode: PayloadAnonymizationMode::None,
            crypto_pan_key: None,
            hash_salt: None,
        }
    }
}

impl AnonymizationPolicy {
    /// Policy optimized for machine learning on network flows.
    ///
    /// - IPs: Crypto-PAn (preserves subnet topology)
    /// - Ports: well-known destination ports preserved
    /// - Timestamps: epoch shift (perfect ordering)
    /// - TCP seq: random per-flow offset
    /// - Payloads: fully truncated
    #[must_use]
    pub fn ml_optimized() -> Self {
        Self {
            ip_mode: IpAnonymizationMode::CryptoPan,
            mac_mode: MacAnonymizationMode::SaltedHash,
            port_mode: PortAnonymizationMode::PreserveWellKnown,
            timestamp_mode: TimestampAnonymizationMode::EpochShift,
            tcp_seq_mode: TcpSeqAnonymizationMode::RandomOffset,
            payload_mode: PayloadAnonymizationMode::TruncateAll,
            crypto_pan_key: None,
            hash_salt: None,
        }
    }

    /// Maximum privacy policy. Generalizes all ports, hashes all MACs,
    /// and strips payloads.
    #[must_use]
    pub fn maximum_privacy() -> Self {
        Self {
            ip_mode: IpAnonymizationMode::CryptoPan,
            mac_mode: MacAnonymizationMode::SaltedHash,
            port_mode: PortAnonymizationMode::Categorize,
            timestamp_mode: TimestampAnonymizationMode::EpochShiftWithJitter { jitter_ms: 5 },
            tcp_seq_mode: TcpSeqAnonymizationMode::RandomOffset,
            payload_mode: PayloadAnonymizationMode::TruncateAll,
            crypto_pan_key: None,
            hash_salt: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_noop() {
        let p = AnonymizationPolicy::default();
        assert_eq!(p.ip_mode, IpAnonymizationMode::None);
        assert_eq!(p.port_mode, PortAnonymizationMode::None);
        assert_eq!(p.payload_mode, PayloadAnonymizationMode::None);
    }

    #[test]
    fn test_ml_optimized_preset() {
        let p = AnonymizationPolicy::ml_optimized();
        assert_eq!(p.ip_mode, IpAnonymizationMode::CryptoPan);
        assert_eq!(p.port_mode, PortAnonymizationMode::PreserveWellKnown);
        assert_eq!(p.payload_mode, PayloadAnonymizationMode::TruncateAll);
    }

    #[test]
    fn test_maximum_privacy_preset() {
        let p = AnonymizationPolicy::maximum_privacy();
        assert_eq!(p.port_mode, PortAnonymizationMode::Categorize);
        assert!(matches!(
            p.timestamp_mode,
            TimestampAnonymizationMode::EpochShiftWithJitter { jitter_ms: 5 }
        ));
    }
}
