//! Anonymization engine — session-scoped orchestrator.
//!
//! [`AnonymizationEngine`] holds the cryptographic state (Crypto-PAn
//! instance, salted hasher, RNG) for a single anonymization session and
//! exposes methods to anonymize individual flow fields or entire
//! [`ConversationState`] batches.

use rand::Rng;
use rand::SeedableRng;
use rand::rngs::StdRng;

use super::crypto_pan::CryptoPan;
use super::hash::SaltedHasher;
use super::policy::{
    AnonymizationPolicy, IpAnonymizationMode, PayloadAnonymizationMode,
    PortAnonymizationMode, TcpSeqAnonymizationMode, TimestampAnonymizationMode,
};
use super::port::generalize_port;
use super::timestamp::TimestampAnonymizer;
use crate::flow::state::{ConversationState, ProtocolState};
use crate::flow::tcp_reassembly::TcpReassembler;

/// Session-scoped anonymization engine.
///
/// Holds all cryptographic state and caches for a single anonymization
/// run. Create one engine per dataset export; reusing the same engine
/// ensures consistent mappings across all flows.
#[derive(Debug)]
pub struct AnonymizationEngine {
    policy: AnonymizationPolicy,
    crypto_pan: Option<CryptoPan>,
    hasher: SaltedHasher,
    timestamp_anon: Option<TimestampAnonymizer>,
    rng: StdRng,
}

impl AnonymizationEngine {
    /// Create a new engine from the given policy.
    ///
    /// Any unspecified keys/salts in the policy are generated randomly.
    #[must_use]
    pub fn new(policy: AnonymizationPolicy) -> Self {
        let mut rng = StdRng::from_os_rng();

        // Initialize Crypto-PAn if needed
        let crypto_pan = if policy.ip_mode == IpAnonymizationMode::CryptoPan {
            let key = policy.crypto_pan_key.unwrap_or_else(|| {
                let mut k = [0u8; 32];
                rng.fill(&mut k);
                k
            });
            Some(CryptoPan::new(&key))
        } else {
            None
        };

        // Initialize salted hasher
        let salt = policy.hash_salt.unwrap_or_else(|| {
            let mut s = [0u8; 32];
            rng.fill(&mut s);
            s
        });
        let hasher = SaltedHasher::new(salt);

        // Initialize timestamp anonymizer
        let timestamp_anon = match policy.timestamp_mode {
            TimestampAnonymizationMode::None => None,
            TimestampAnonymizationMode::EpochShift => {
                Some(TimestampAnonymizer::epoch_shift_only(&mut rng))
            },
            TimestampAnonymizationMode::EpochShiftWithJitter { jitter_ms } => {
                Some(TimestampAnonymizer::with_jitter(jitter_ms, &mut rng))
            },
        };

        Self {
            policy,
            crypto_pan,
            hasher,
            timestamp_anon,
            rng,
        }
    }

    /// Anonymize a batch of conversations in place.
    pub fn anonymize_conversations(&mut self, conversations: &mut [ConversationState]) {
        for conv in conversations.iter_mut() {
            self.anonymize_conversation(conv);
        }
    }

    /// Anonymize a single conversation in place.
    pub fn anonymize_conversation(&mut self, conv: &mut ConversationState) {
        self.anonymize_ips(conv);
        self.anonymize_ports(conv);
        self.anonymize_timestamps(conv);
        self.anonymize_tcp_seq(conv);
        self.anonymize_payload(conv);
    }

    /// The underlying policy.
    #[must_use]
    pub fn policy(&self) -> &AnonymizationPolicy {
        &self.policy
    }

    /// The salted hasher (for packet-level anonymization of MACs, etc.).
    #[must_use]
    pub fn hasher(&self) -> &SaltedHasher {
        &self.hasher
    }

    // ---- private helpers ----

    fn anonymize_ips(&mut self, conv: &mut ConversationState) {
        if let Some(ref mut cp) = self.crypto_pan {
            conv.key.addr_a = cp.anonymize_ip(conv.key.addr_a);
            conv.key.addr_b = cp.anonymize_ip(conv.key.addr_b);
        }
    }

    fn anonymize_ports(&self, conv: &mut ConversationState) {
        match self.policy.port_mode {
            PortAnonymizationMode::None => {},
            PortAnonymizationMode::PreserveWellKnown => {
                // Determine which side is the "destination" (lower port = server heuristic).
                // In the canonical key, addr_a < addr_b. We use port_b as the
                // "likely server" if it is in the well-known range.
                let (is_a_dst, is_b_dst) = server_heuristic(conv.key.port_a, conv.key.port_b);
                conv.key.port_a = generalize_port(conv.key.port_a, true, is_a_dst);
                conv.key.port_b = generalize_port(conv.key.port_b, true, is_b_dst);
            },
            PortAnonymizationMode::Categorize => {
                conv.key.port_a = generalize_port(conv.key.port_a, false, false);
                conv.key.port_b = generalize_port(conv.key.port_b, false, false);
            },
        }
    }

    fn anonymize_timestamps(&mut self, conv: &mut ConversationState) {
        if let Some(ref mut ts_anon) = self.timestamp_anon {
            conv.start_time = ts_anon.anonymize(conv.start_time);
            conv.last_seen = ts_anon.anonymize(conv.last_seen);
            conv.forward.first_seen = ts_anon.anonymize(conv.forward.first_seen);
            conv.forward.last_seen = ts_anon.anonymize(conv.forward.last_seen);
            conv.reverse.first_seen = ts_anon.anonymize(conv.reverse.first_seen);
            conv.reverse.last_seen = ts_anon.anonymize(conv.reverse.last_seen);
        }
    }

    fn anonymize_tcp_seq(&mut self, conv: &mut ConversationState) {
        if self.policy.tcp_seq_mode == TcpSeqAnonymizationMode::None {
            return;
        }
        if let ProtocolState::Tcp(ref mut tcp) = conv.protocol_state {
            // Generate per-flow random offsets for forward and reverse
            let fwd_offset: u32 = self.rng.random();
            let rev_offset: u32 = self.rng.random();

            // Offset initial sequence numbers
            tcp.forward_endpoint.initial_seq = tcp
                .forward_endpoint
                .initial_seq
                .map(|s| s.wrapping_add(fwd_offset));
            tcp.reverse_endpoint.initial_seq = tcp
                .reverse_endpoint
                .initial_seq
                .map(|s| s.wrapping_add(rev_offset));

            // Offset next_expected_seq and last_ack
            tcp.forward_endpoint.next_expected_seq = tcp
                .forward_endpoint
                .next_expected_seq
                .wrapping_add(fwd_offset);
            tcp.forward_endpoint.last_ack = tcp
                .forward_endpoint
                .last_ack
                .wrapping_add(rev_offset);

            tcp.reverse_endpoint.next_expected_seq = tcp
                .reverse_endpoint
                .next_expected_seq
                .wrapping_add(rev_offset);
            tcp.reverse_endpoint.last_ack = tcp
                .reverse_endpoint
                .last_ack
                .wrapping_add(fwd_offset);
        }
    }

    fn anonymize_payload(&self, conv: &mut ConversationState) {
        if let ProtocolState::Tcp(ref mut tcp) = conv.protocol_state {
            match self.policy.payload_mode {
                PayloadAnonymizationMode::None => {},
                PayloadAnonymizationMode::TruncateAll => {
                    tcp.reassembler_fwd = TcpReassembler::new();
                    tcp.reassembler_rev = TcpReassembler::new();
                },
                PayloadAnonymizationMode::TruncateTo(n) => {
                    tcp.reassembler_fwd.truncate_reassembled(n);
                    tcp.reassembler_rev.truncate_reassembled(n);
                },
            }
        }
    }
}

/// Heuristic: the lower port is more likely the server/destination.
///
/// Returns `(is_port_a_dst, is_port_b_dst)`.
fn server_heuristic(port_a: u16, port_b: u16) -> (bool, bool) {
    if port_a <= 1023 && port_b > 1023 {
        (true, false)
    } else if port_b <= 1023 && port_a > 1023 {
        (false, true)
    } else if port_a < port_b {
        // Both well-known or both high: treat lower as server
        (true, false)
    } else {
        (false, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::key::{CanonicalKey, TransportProtocol};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn make_test_conv() -> ConversationState {
        let (key, _) = CanonicalKey::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            54321,
            443,
            TransportProtocol::Tcp,
            None,
        );
        let mut conv = ConversationState::new(key, Duration::from_secs(100));
        conv.last_seen = Duration::from_secs(200);
        conv.forward.first_seen = Duration::from_secs(100);
        conv.forward.last_seen = Duration::from_secs(150);
        conv.reverse.first_seen = Duration::from_secs(101);
        conv.reverse.last_seen = Duration::from_secs(200);
        conv
    }

    #[test]
    fn test_noop_policy() {
        let mut conv = make_test_conv();
        let orig_a = conv.key.addr_a;
        let orig_b = conv.key.addr_b;
        let orig_start = conv.start_time;

        let mut engine = AnonymizationEngine::new(AnonymizationPolicy::default());
        engine.anonymize_conversation(&mut conv);

        assert_eq!(conv.key.addr_a, orig_a);
        assert_eq!(conv.key.addr_b, orig_b);
        assert_eq!(conv.start_time, orig_start);
    }

    #[test]
    fn test_crypto_pan_changes_ips() {
        let mut conv = make_test_conv();
        let orig_a = conv.key.addr_a;
        let orig_b = conv.key.addr_b;

        let mut policy = AnonymizationPolicy::default();
        policy.ip_mode = IpAnonymizationMode::CryptoPan;

        let mut engine = AnonymizationEngine::new(policy);
        engine.anonymize_conversation(&mut conv);

        assert_ne!(conv.key.addr_a, orig_a);
        assert_ne!(conv.key.addr_b, orig_b);
    }

    #[test]
    fn test_port_preserve_well_known() {
        let mut conv = make_test_conv();

        let mut policy = AnonymizationPolicy::default();
        policy.port_mode = PortAnonymizationMode::PreserveWellKnown;

        let mut engine = AnonymizationEngine::new(policy);
        engine.anonymize_conversation(&mut conv);

        // The well-known port (443) should be preserved on the dst side
        // The ephemeral port (54321) should be generalized
        let has_443 = conv.key.port_a == 443 || conv.key.port_b == 443;
        assert!(has_443, "Well-known port 443 should be preserved");
    }

    #[test]
    fn test_timestamp_shift() {
        let mut conv = make_test_conv();
        let orig_start = conv.start_time;

        let mut policy = AnonymizationPolicy::default();
        policy.timestamp_mode = TimestampAnonymizationMode::EpochShift;

        let mut engine = AnonymizationEngine::new(policy);
        engine.anonymize_conversation(&mut conv);

        assert!(conv.start_time > orig_start);
        // Offset should be at least 30 days
        assert!(conv.start_time - orig_start >= Duration::from_secs(30 * 86400));
    }

    #[test]
    fn test_payload_truncate_all() {
        let mut conv = make_test_conv();

        let mut policy = AnonymizationPolicy::default();
        policy.payload_mode = PayloadAnonymizationMode::TruncateAll;

        let mut engine = AnonymizationEngine::new(policy);
        engine.anonymize_conversation(&mut conv);

        if let ProtocolState::Tcp(ref tcp) = conv.protocol_state {
            assert_eq!(tcp.reassembler_fwd.reassembled_len(), 0);
            assert_eq!(tcp.reassembler_rev.reassembled_len(), 0);
        }
    }

    #[test]
    fn test_ml_optimized_full_pipeline() {
        let mut conv = make_test_conv();
        let orig_a = conv.key.addr_a;

        let mut engine = AnonymizationEngine::new(AnonymizationPolicy::ml_optimized());
        engine.anonymize_conversation(&mut conv);

        // IPs changed
        assert_ne!(conv.key.addr_a, orig_a);
        // Timestamps shifted
        assert!(conv.start_time > Duration::from_secs(100));
    }

    #[test]
    fn test_batch_anonymization() {
        let mut convs = vec![make_test_conv(), make_test_conv()];
        let orig_a0 = convs[0].key.addr_a;

        let mut engine = AnonymizationEngine::new(AnonymizationPolicy::ml_optimized());
        engine.anonymize_conversations(&mut convs);

        // Both changed
        assert_ne!(convs[0].key.addr_a, orig_a0);
        // Same original IP should map to same anonymized IP
        assert_eq!(convs[0].key.addr_a, convs[1].key.addr_a);
    }

    #[test]
    fn test_server_heuristic() {
        // Well-known vs ephemeral
        assert_eq!(server_heuristic(443, 54321), (true, false));
        assert_eq!(server_heuristic(54321, 80), (false, true));
        // Both high: lower = server
        assert_eq!(server_heuristic(8080, 54321), (true, false));
    }
}
