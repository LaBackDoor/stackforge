use std::time::Duration;

/// Configuration for the flow extraction engine.
///
/// Controls timeouts, buffer limits, and eviction thresholds for
/// conversation tracking and TCP stream reassembly.
#[derive(Debug, Clone)]
pub struct FlowConfig {
    /// Timeout for established TCP connections (default: 86400s / 24h).
    pub tcp_established_timeout: Duration,
    /// Timeout for half-open TCP connections (SYN sent, no ACK) (default: 5s).
    pub tcp_half_open_timeout: Duration,
    /// Timeout for TCP `TIME_WAIT` state (default: 120s).
    pub tcp_time_wait_timeout: Duration,
    /// Timeout for UDP pseudo-conversations (default: 120s).
    pub udp_timeout: Duration,
    /// Maximum reassembly buffer size per direction per flow (default: 16 MB).
    pub max_reassembly_buffer: usize,
    /// Maximum number of out-of-order fragments per direction (default: 100).
    pub max_ooo_fragments: usize,
    /// Interval between idle conversation eviction sweeps (default: 30s).
    pub eviction_interval: Duration,
    /// Track maximum packet length per direction (default: false).
    pub track_max_packet_len: bool,
    /// Track maximum flow length per direction (default: false).
    pub track_max_flow_len: bool,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            tcp_established_timeout: Duration::from_secs(86_400),
            tcp_half_open_timeout: Duration::from_secs(5),
            tcp_time_wait_timeout: Duration::from_secs(120),
            udp_timeout: Duration::from_secs(120),
            max_reassembly_buffer: 16 * 1024 * 1024, // 16 MB
            max_ooo_fragments: 100,
            eviction_interval: Duration::from_secs(30),
            track_max_packet_len: false,
            track_max_flow_len: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = FlowConfig::default();
        assert_eq!(config.tcp_established_timeout, Duration::from_secs(86_400));
        assert_eq!(config.tcp_half_open_timeout, Duration::from_secs(5));
        assert_eq!(config.tcp_time_wait_timeout, Duration::from_secs(120));
        assert_eq!(config.udp_timeout, Duration::from_secs(120));
        assert_eq!(config.max_reassembly_buffer, 16 * 1024 * 1024);
        assert_eq!(config.max_ooo_fragments, 100);
        assert_eq!(config.eviction_interval, Duration::from_secs(30));
        assert!(!config.track_max_packet_len);
        assert!(!config.track_max_flow_len);
    }
}
