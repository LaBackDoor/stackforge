use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Instant;

use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender, bounded};

use super::capture::{RawPacket, open_capture};
use super::config::SnifferConfig;
use super::error::SnifferError;

/// Capture statistics from libpcap.
#[derive(Debug, Clone, Default)]
pub struct CaptureStats {
    pub packets_received: u32,
    pub packets_dropped: u32,
    pub packets_if_dropped: u32,
}

/// A threaded packet sniffer that pushes captured packets into a channel.
///
/// The capture runs on a dedicated OS thread. Consumers read packets from
/// the receiver end of a bounded crossbeam channel.
pub struct SnifferHandle {
    receiver: Receiver<RawPacket>,
    stop_flag: Arc<AtomicBool>,
    thread: Option<JoinHandle<CaptureStats>>,
}

impl SnifferHandle {
    /// Start a new sniffer with the given configuration.
    pub fn start(config: SnifferConfig) -> Result<Self, SnifferError> {
        let (sender, receiver) = bounded(config.channel_capacity);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop_flag);

        // Open capture on the main thread so errors propagate immediately
        let mut capture = open_capture(&config)?;

        let count = config.count;
        let timeout = config.timeout;

        let thread = thread::Builder::new()
            .name(format!("sniffer-{}", config.iface))
            .spawn(move || {
                capture_loop(&mut capture, &sender, &thread_stop, count, timeout)
            })
            .map_err(|e| SnifferError::CaptureError(format!("failed to spawn thread: {e}")))?;

        Ok(Self {
            receiver,
            stop_flag,
            thread: Some(thread),
        })
    }

    /// Receive the next captured packet, blocking until one is available.
    ///
    /// Returns `None` when the capture has ended (count/timeout reached or stopped).
    pub fn recv(&self) -> Option<RawPacket> {
        self.receiver.recv().ok()
    }

    /// Try to receive a packet without blocking.
    pub fn try_recv(&self) -> Option<RawPacket> {
        self.receiver.try_recv().ok()
    }

    /// Signal the capture thread to stop.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Check if the sniffer has been signaled to stop.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Relaxed)
    }

    /// Wait for the capture thread to finish and return stats.
    pub fn join(mut self) -> CaptureStats {
        self.stop();
        if let Some(handle) = self.thread.take() {
            handle.join().unwrap_or_default()
        } else {
            CaptureStats::default()
        }
    }

    /// Get a reference to the receiver for use with `select!` or direct iteration.
    #[must_use]
    pub fn receiver(&self) -> &Receiver<RawPacket> {
        &self.receiver
    }
}

impl Drop for SnifferHandle {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take() {
            let _ = handle.join();
        }
    }
}

/// The main capture loop running on a dedicated thread.
fn capture_loop(
    capture: &mut pcap::Capture<pcap::Active>,
    sender: &Sender<RawPacket>,
    stop_flag: &AtomicBool,
    count: usize,
    timeout: Option<std::time::Duration>,
) -> CaptureStats {
    let start = Instant::now();
    let mut captured = 0usize;

    loop {
        // Check stop conditions
        if stop_flag.load(Ordering::Relaxed) {
            break;
        }
        if count > 0 && captured >= count {
            break;
        }
        if let Some(t) = timeout {
            if start.elapsed() >= t {
                break;
            }
        }

        // Read next packet (with the 100ms read timeout from open_capture)
        match capture.next_packet() {
            Ok(packet) => {
                let raw = RawPacket {
                    data: Bytes::copy_from_slice(packet.data),
                    timestamp_us: packet.header.ts.tv_sec * 1_000_000
                        + i64::from(packet.header.ts.tv_usec),
                };
                // If the channel is full or closed, stop
                if sender.send(raw).is_err() {
                    break;
                }
                captured += 1;
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Read timeout — just loop and check stop conditions
                continue;
            }
            Err(_) => {
                // Other errors — stop the capture
                break;
            }
        }
    }

    // Collect stats before we're done
    let stats = capture.stats().unwrap_or(pcap::Stat {
        received: 0,
        dropped: 0,
        if_dropped: 0,
    });

    CaptureStats {
        packets_received: stats.received,
        packets_dropped: stats.dropped,
        packets_if_dropped: stats.if_dropped,
    }
}
