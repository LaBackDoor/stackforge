use std::time::Duration;

use crate::Packet;

use super::config::FlowConfig;
use super::state::ConversationStatus;

/// ICMP/ICMPv6 conversation state.
///
/// Tracks ICMP-specific metadata for echo request/reply pairs and other ICMP types.
/// Echo requests and replies are correlated using the ICMP identifier field.
#[derive(Debug, Clone)]
pub struct IcmpFlowState {
    /// ICMP type (e.g., 8 for Echo Request, 0 for Echo Reply).
    pub icmp_type: u8,
    /// ICMP code.
    pub icmp_code: u8,
    /// ICMP identifier (for echo, timestamp, and other types that use it).
    pub identifier: Option<u16>,
    /// Number of echo requests (type 8 for ICMP, 128 for ICMPv6).
    pub request_count: u64,
    /// Number of echo replies (type 0 for ICMP, 129 for ICMPv6).
    pub reply_count: u64,
    /// Last sequence number seen in an echo packet.
    pub last_seq: Option<u16>,
    /// Conversation status.
    pub status: ConversationStatus,
}

impl IcmpFlowState {
    #[must_use]
    pub fn new(icmp_type: u8, icmp_code: u8) -> Self {
        Self {
            icmp_type,
            icmp_code,
            identifier: None,
            request_count: 0,
            reply_count: 0,
            last_seq: None,
            status: ConversationStatus::Active,
        }
    }

    /// Update state when a new ICMP packet is received.
    ///
    /// Increments request or reply count based on ICMP type, and updates
    /// the identifier and sequence number fields if present.
    pub fn process_packet(&mut self, packet: &Packet, buf: &[u8], icmp_type: u8, icmp_code: u8) {
        // Update type/code on every packet (they should be consistent)
        self.icmp_type = icmp_type;
        self.icmp_code = icmp_code;

        // Get ICMP layer bounds to extract fields
        if let Some(icmp_layer) = crate::layer::LayerKind::Icmp
            .try_into()
            .ok()
            .and_then(|kind| packet.get_layer(kind))
        {
            let icmp_start = icmp_layer.start;

            // Extract identifier (bytes 4-5) if present
            if buf.len() >= icmp_start + 6 {
                self.identifier = Some(u16::from_be_bytes([
                    buf[icmp_start + 4],
                    buf[icmp_start + 5],
                ]));
            }

            // Extract sequence number (bytes 6-7) if present
            if buf.len() >= icmp_start + 8 {
                self.last_seq = Some(u16::from_be_bytes([
                    buf[icmp_start + 6],
                    buf[icmp_start + 7],
                ]));
            }

            // Count requests and replies based on ICMP type
            match icmp_type {
                8 => {
                    // ICMP Echo Request
                    self.request_count += 1;
                },
                0 => {
                    // ICMP Echo Reply
                    self.reply_count += 1;
                },
                128 => {
                    // ICMPv6 Echo Request
                    self.request_count += 1;
                },
                129 => {
                    // ICMPv6 Echo Reply
                    self.reply_count += 1;
                },
                _ => {
                    // Other ICMP types: no counting
                },
            }
        }

        self.status = ConversationStatus::Active;
    }

    /// Check whether this flow has timed out.
    #[must_use]
    pub fn check_timeout(&self, last_seen: Duration, now: Duration, config: &FlowConfig) -> bool {
        // ICMP uses UDP timeout
        now.saturating_sub(last_seen) > config.udp_timeout
    }
}

impl Default for IcmpFlowState {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_state_new() {
        let state = IcmpFlowState::new(8, 0);
        assert_eq!(state.icmp_type, 8);
        assert_eq!(state.icmp_code, 0);
        assert_eq!(state.request_count, 0);
        assert_eq!(state.reply_count, 0);
        assert_eq!(state.identifier, None);
        assert_eq!(state.last_seq, None);
    }

    #[test]
    fn test_icmp_timeout() {
        let config = FlowConfig::default(); // 120s UDP timeout
        let state = IcmpFlowState::new(8, 0);

        // Not timed out
        assert!(!state.check_timeout(Duration::from_secs(100), Duration::from_secs(200), &config));

        // Timed out
        assert!(state.check_timeout(Duration::from_secs(100), Duration::from_secs(300), &config));
    }
}
