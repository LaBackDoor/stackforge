//! Multi-queue worker pool for high-bandwidth packet sniffing.
//!
//! This module provides a worker pool that distributes captured packets
//! across multiple worker threads for parallel parsing and processing.
//!
//! Architecture:
//! ```text
//! [Capture Thread] --packets--> [Channel] --fan-out--> [Worker 1] --parsed--> [Output Channel]
//!                                                      [Worker 2] --parsed-->
//!                                                      [Worker N] --parsed-->
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use crossbeam_channel::{Receiver, Sender, bounded};

use super::capture::{RawPacket, open_capture};
use super::config::SnifferConfig;
use super::error::SnifferError;
use crate::packet::Packet;

/// A parsed packet with its original timestamp.
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// The parsed packet.
    pub packet: Packet,
    /// Capture timestamp in microseconds since epoch.
    pub timestamp_us: i64,
}

/// Configuration for the worker pool.
#[derive(Debug, Clone)]
pub struct WorkerPoolConfig {
    /// Number of worker threads for parsing.
    pub num_workers: usize,
    /// Capacity of the raw packet channel (capture → workers).
    pub input_capacity: usize,
    /// Capacity of the parsed packet channel (workers → consumer).
    pub output_capacity: usize,
}

impl Default for WorkerPoolConfig {
    fn default() -> Self {
        let cpus = thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4);
        Self {
            // Leave 1 core for capture, 1 for the consumer
            num_workers: cpus.saturating_sub(2).max(1),
            input_capacity: 8192,
            output_capacity: 8192,
        }
    }
}

impl WorkerPoolConfig {
    #[must_use]
    pub fn num_workers(mut self, n: usize) -> Self {
        self.num_workers = n.max(1);
        self
    }

    #[must_use]
    pub fn input_capacity(mut self, cap: usize) -> Self {
        self.input_capacity = cap;
        self
    }

    #[must_use]
    pub fn output_capacity(mut self, cap: usize) -> Self {
        self.output_capacity = cap;
        self
    }
}

/// A multi-threaded sniffer with a worker pool for parallel packet parsing.
///
/// The pool consists of:
/// - 1 capture thread (reads from libpcap)
/// - N worker threads (parse raw packets in parallel)
/// - Output channel for the consumer to read parsed packets
pub struct WorkerPoolSniffer {
    output_rx: Receiver<ParsedPacket>,
    stop_flag: Arc<AtomicBool>,
    capture_thread: Option<JoinHandle<()>>,
    worker_threads: Vec<JoinHandle<()>>,
}

impl WorkerPoolSniffer {
    /// Start the worker pool sniffer.
    pub fn start(
        sniffer_config: SnifferConfig,
        pool_config: WorkerPoolConfig,
    ) -> Result<Self, SnifferError> {
        let stop_flag = Arc::new(AtomicBool::new(false));

        // Open capture on main thread for immediate error reporting
        let mut capture = open_capture(&sniffer_config)?;

        // Channels
        let (raw_tx, raw_rx) = bounded::<RawPacket>(pool_config.input_capacity);
        let (parsed_tx, parsed_rx) = bounded::<ParsedPacket>(pool_config.output_capacity);

        // Spawn capture thread
        let capture_stop = Arc::clone(&stop_flag);
        let count = sniffer_config.count;
        let timeout = sniffer_config.timeout;
        let iface = sniffer_config.iface.clone();

        let capture_thread = thread::Builder::new()
            .name(format!("capture-{iface}"))
            .spawn(move || {
                capture_loop(&mut capture, &raw_tx, &capture_stop, count, timeout);
            })
            .map_err(|e| SnifferError::CaptureError(format!("spawn capture thread: {e}")))?;

        // Spawn worker threads
        let mut worker_threads = Vec::with_capacity(pool_config.num_workers);
        for i in 0..pool_config.num_workers {
            let rx = raw_rx.clone();
            let tx = parsed_tx.clone();
            let worker_stop = Arc::clone(&stop_flag);

            let handle = thread::Builder::new()
                .name(format!("worker-{i}"))
                .spawn(move || {
                    worker_loop(&rx, &tx, &worker_stop);
                })
                .map_err(|e| {
                    SnifferError::CaptureError(format!("spawn worker thread {i}: {e}"))
                })?;

            worker_threads.push(handle);
        }

        // Drop our copies of the channel ends so they close when threads finish
        drop(raw_rx);
        drop(parsed_tx);

        Ok(Self {
            output_rx: parsed_rx,
            stop_flag,
            capture_thread: Some(capture_thread),
            worker_threads,
        })
    }

    /// Receive the next parsed packet, blocking until available.
    pub fn recv(&self) -> Option<ParsedPacket> {
        self.output_rx.recv().ok()
    }

    /// Try to receive a parsed packet without blocking.
    pub fn try_recv(&self) -> Option<ParsedPacket> {
        self.output_rx.try_recv().ok()
    }

    /// Get a reference to the output receiver for use with `select!`.
    #[must_use]
    pub fn receiver(&self) -> &Receiver<ParsedPacket> {
        &self.output_rx
    }

    /// Signal all threads to stop.
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Check if the pool has been signaled to stop.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stop_flag.load(Ordering::Relaxed)
    }

    /// Stop and wait for all threads to finish.
    pub fn join(mut self) {
        self.stop();
        if let Some(h) = self.capture_thread.take() {
            let _ = h.join();
        }
        for h in self.worker_threads.drain(..) {
            let _ = h.join();
        }
    }

    /// Get the number of worker threads.
    #[must_use]
    pub fn num_workers(&self) -> usize {
        self.worker_threads.len()
    }
}

impl Drop for WorkerPoolSniffer {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
        if let Some(h) = self.capture_thread.take() {
            let _ = h.join();
        }
        for h in self.worker_threads.drain(..) {
            let _ = h.join();
        }
    }
}

/// Capture loop: reads packets from libpcap and sends to worker channel.
fn capture_loop(
    capture: &mut pcap::Capture<pcap::Active>,
    sender: &Sender<RawPacket>,
    stop_flag: &AtomicBool,
    count: usize,
    timeout: Option<std::time::Duration>,
) {
    let start = std::time::Instant::now();
    let mut captured = 0usize;

    loop {
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

        match capture.next_packet() {
            Ok(packet) => {
                let raw = RawPacket {
                    data: bytes::Bytes::copy_from_slice(packet.data),
                    timestamp_us: packet.header.ts.tv_sec * 1_000_000
                        + i64::from(packet.header.ts.tv_usec),
                };
                if sender.send(raw).is_err() {
                    break;
                }
                captured += 1;
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(_) => break,
        }
    }
}

/// Worker loop: receives raw packets, parses them, sends to output.
fn worker_loop(
    input: &Receiver<RawPacket>,
    output: &Sender<ParsedPacket>,
    stop_flag: &AtomicBool,
) {
    while !stop_flag.load(Ordering::Relaxed) {
        match input.recv_timeout(std::time::Duration::from_millis(50)) {
            Ok(raw) => {
                let mut packet = Packet::from_bytes(raw.data);
                let _ = packet.parse();

                let parsed = ParsedPacket {
                    packet,
                    timestamp_us: raw.timestamp_us,
                };

                if output.send(parsed).is_err() {
                    break;
                }
            }
            Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
            Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_pool_config_defaults() {
        let config = WorkerPoolConfig::default();
        assert!(config.num_workers >= 1);
        assert!(config.input_capacity > 0);
        assert!(config.output_capacity > 0);
    }

    #[test]
    fn test_worker_pool_config_builder() {
        let config = WorkerPoolConfig::default()
            .num_workers(4)
            .input_capacity(1024)
            .output_capacity(2048);
        assert_eq!(config.num_workers, 4);
        assert_eq!(config.input_capacity, 1024);
        assert_eq!(config.output_capacity, 2048);
    }

    #[test]
    fn test_worker_pool_config_min_workers() {
        let config = WorkerPoolConfig::default().num_workers(0);
        assert_eq!(config.num_workers, 1); // minimum 1
    }
}
