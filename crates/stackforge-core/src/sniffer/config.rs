use std::time::Duration;

/// Configuration for a packet capture session.
#[derive(Debug, Clone)]
pub struct SnifferConfig {
    /// Network interface name (e.g., "en0", "eth0", "lo0").
    pub iface: String,
    /// BPF filter string (e.g., "tcp port 80").
    pub filter: Option<String>,
    /// Maximum number of packets to capture. 0 means unlimited.
    pub count: usize,
    /// Capture timeout. `None` means no timeout.
    pub timeout: Option<Duration>,
    /// Snapshot length — max bytes captured per packet.
    pub snaplen: i32,
    /// Whether to enable promiscuous mode.
    pub promisc: bool,
    /// Channel buffer capacity (number of packets).
    pub channel_capacity: usize,
}

impl Default for SnifferConfig {
    fn default() -> Self {
        Self {
            iface: default_iface(),
            filter: None,
            count: 0,
            timeout: None,
            snaplen: 65535,
            promisc: true,
            channel_capacity: 4096,
        }
    }
}

impl SnifferConfig {
    #[must_use]
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn filter(mut self, filter: impl Into<String>) -> Self {
        self.filter = Some(filter.into());
        self
    }

    #[must_use]
    pub fn count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }

    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    #[must_use]
    pub fn snaplen(mut self, snaplen: i32) -> Self {
        self.snaplen = snaplen;
        self
    }

    #[must_use]
    pub fn promisc(mut self, promisc: bool) -> Self {
        self.promisc = promisc;
        self
    }

    #[must_use]
    pub fn channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
    }
}

/// Returns a sensible default interface name for the current platform.
fn default_iface() -> String {
    // Try to find the default network interface
    if let Some(iface) = default_net::get_default_interface().ok() {
        return iface.name;
    }

    // Fallback based on platform
    if cfg!(target_os = "macos") {
        "en0".to_string()
    } else if cfg!(target_os = "linux") {
        "eth0".to_string()
    } else {
        "lo".to_string()
    }
}
