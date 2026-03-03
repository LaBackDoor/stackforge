use std::time::Duration;

use super::config::FlowConfig;
use super::state::ConversationStatus;

/// UDP pseudo-conversation state.
///
/// UDP is connectionless, so conversations are tracked purely via
/// timeout heuristics. A conversation is considered active as long as
/// packets continue arriving within the configured timeout window.
#[derive(Debug, Clone)]
pub struct UdpFlowState {
    pub status: ConversationStatus,
}

impl UdpFlowState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            status: ConversationStatus::Active,
        }
    }

    /// Update state when a new packet is received.
    pub fn process_packet(&mut self) {
        self.status = ConversationStatus::Active;
    }

    /// Check whether this flow has timed out.
    #[must_use]
    pub fn check_timeout(&self, last_seen: Duration, now: Duration, config: &FlowConfig) -> bool {
        now.saturating_sub(last_seen) > config.udp_timeout
    }
}

impl Default for UdpFlowState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_state_new() {
        let state = UdpFlowState::new();
        assert_eq!(state.status, ConversationStatus::Active);
    }

    #[test]
    fn test_udp_timeout_check() {
        let config = FlowConfig::default(); // 120s UDP timeout
        let state = UdpFlowState::new();

        // Not timed out
        assert!(!state.check_timeout(Duration::from_secs(100), Duration::from_secs(200), &config));

        // Timed out
        assert!(state.check_timeout(Duration::from_secs(100), Duration::from_secs(300), &config));
    }

    #[test]
    fn test_udp_process_packet() {
        let mut state = UdpFlowState::new();
        state.status = ConversationStatus::TimedOut;
        state.process_packet();
        assert_eq!(state.status, ConversationStatus::Active);
    }
}
