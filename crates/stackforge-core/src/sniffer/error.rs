use thiserror::Error;

/// Errors that can occur during packet capture.
#[derive(Debug, Error)]
pub enum SnifferError {
    #[error("interface not found: {0}")]
    InterfaceNotFound(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("invalid BPF filter: {0}")]
    InvalidFilter(String),

    #[error("capture error: {0}")]
    CaptureError(String),

    #[error("channel closed")]
    ChannelClosed,

    #[error("sniffer already stopped")]
    AlreadyStopped,

    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),
}
