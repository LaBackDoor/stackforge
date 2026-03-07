/// Configuration for an automaton runtime.
#[derive(Debug, Clone)]
pub struct AutomatonConfig {
    /// Network interface name.
    pub iface: String,
    /// BPF filter string.
    pub bpf_filter: Option<String>,
    /// Snapshot length for capture.
    pub snaplen: i32,
    /// Enable promiscuous mode.
    pub promisc: bool,
}

impl Default for AutomatonConfig {
    fn default() -> Self {
        let iface = default_net::get_default_interface()
            .map(|i| i.name)
            .unwrap_or_else(|_| {
                if cfg!(target_os = "macos") {
                    "en0".to_string()
                } else {
                    "eth0".to_string()
                }
            });

        Self {
            iface,
            bpf_filter: None,
            snaplen: 65535,
            promisc: true,
        }
    }
}

impl AutomatonConfig {
    #[must_use]
    pub fn new(iface: impl Into<String>) -> Self {
        Self {
            iface: iface.into(),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn bpf_filter(mut self, filter: impl Into<String>) -> Self {
        self.bpf_filter = Some(filter.into());
        self
    }

    #[must_use]
    pub fn promisc(mut self, promisc: bool) -> Self {
        self.promisc = promisc;
        self
    }
}
