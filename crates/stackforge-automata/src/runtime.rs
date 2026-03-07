use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use stackforge_core::Packet;
use stackforge_core::sniffer::{SnifferConfig, SnifferHandle};

use crate::config::AutomatonConfig;
use crate::error::AutomatonError;
use crate::traits::Automaton;

/// Manages the lifecycle of an automaton — sniffer thread, sender, and event loop.
pub struct AutomatonRuntime {
    stop_flag: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl AutomatonRuntime {
    /// Start an automaton with the given configuration.
    ///
    /// This spawns a dedicated thread that:
    /// 1. Opens a pcap capture for both sniffing and sending
    /// 2. Runs a tokio runtime internally for async timers
    /// 3. Calls `is_request()` / `make_reply()` on each captured packet
    /// 4. Sends reply packets via `pcap::sendpacket()`
    /// 5. Optionally runs periodic `on_tick()` actions
    pub fn start<A: Automaton>(
        mut automaton: A,
        config: AutomatonConfig,
    ) -> Result<Self, AutomatonError> {
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_flag);

        // Build sniffer config, preferring the automaton's BPF filter
        let bpf = automaton.bpf_filter().or(config.bpf_filter.clone());
        let mut sniffer_config = SnifferConfig::new(&config.iface)
            .snaplen(config.snaplen)
            .promisc(config.promisc);
        if let Some(ref f) = bpf {
            sniffer_config = sniffer_config.filter(f);
        }

        // Start the sniffer (validates interface/filter on this thread)
        let sniffer = SnifferHandle::start(sniffer_config)?;

        // Open a separate pcap handle for sending
        let send_device = pcap::Device::list()
            .map_err(AutomatonError::Pcap)?
            .into_iter()
            .find(|d| d.name == config.iface)
            .ok_or_else(|| {
                AutomatonError::Config(format!("interface not found: {}", config.iface))
            })?;

        let mut sender = pcap::Capture::from_device(send_device)
            .map_err(AutomatonError::Pcap)?
            .snaplen(config.snaplen)
            .promisc(config.promisc)
            .timeout(100)
            .open()
            .map_err(AutomatonError::Pcap)?;

        let thread = thread::Builder::new()
            .name("automaton-runtime".to_string())
            .spawn(move || {
                automaton.on_start();
                run_loop(&mut automaton, &sniffer, &mut sender, &thread_stop);
                automaton.on_stop();
                sniffer.stop();
            })
            .map_err(|e| AutomatonError::Runtime(format!("failed to spawn thread: {e}")))?;

        Ok(Self {
            stop_flag,
            thread: Some(thread),
        })
    }

    /// Signal the automaton to stop.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Check if the automaton is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.thread.as_ref().is_some_and(|t| !t.is_finished())
    }

    /// Stop and wait for the automaton thread to finish.
    pub fn join(mut self) {
        self.stop();
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for AutomatonRuntime {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// The main event loop running on a dedicated thread.
///
/// Uses a tokio single-threaded runtime for timer support (tick intervals).
fn run_loop<A: Automaton>(
    automaton: &mut A,
    sniffer: &SnifferHandle,
    sender: &mut pcap::Capture<pcap::Active>,
    stop_flag: &AtomicBool,
) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(async {
        let tick_interval = automaton.tick_interval();
        let mut ticker = tick_interval.map(|d| tokio::time::interval(d));

        // If there's a ticker, skip the first immediate tick
        if let Some(ref mut t) = ticker {
            t.tick().await;
        }

        loop {
            if stop_flag.load(Ordering::Relaxed) {
                break;
            }

            // Try to receive a packet (non-blocking)
            if let Some(raw) = sniffer.try_recv() {
                let mut pkt = Packet::from_bytes(raw.data.to_vec());
                if pkt.parse().is_ok() && automaton.is_request(&pkt) {
                    if let Some(reply_bytes) = automaton.make_reply(&pkt) {
                        let _ = sender.sendpacket(reply_bytes.as_slice());
                    }
                }
            }

            // Check tick
            if let Some(ref mut t) = ticker {
                // Use poll-style check: if tick is ready, handle it
                if let Ok(_) =
                    tokio::time::timeout(std::time::Duration::from_millis(1), t.tick()).await
                {
                    if let Some(packets) = automaton.on_tick() {
                        for pkt_bytes in &packets {
                            let _ = sender.sendpacket(pkt_bytes.as_slice());
                        }
                    }
                }
            } else {
                // No ticker — small sleep to avoid busy-loop when no packets
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        }
    });
}
