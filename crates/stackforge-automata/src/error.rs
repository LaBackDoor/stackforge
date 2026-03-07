use thiserror::Error;

/// Errors that can occur in the automaton framework.
#[derive(Debug, Error)]
pub enum AutomatonError {
    #[error("sniffer error: {0}")]
    Sniffer(#[from] stackforge_core::SnifferError),

    #[error("send error: {0}")]
    Send(String),

    #[error("runtime error: {0}")]
    Runtime(String),

    #[error("already running")]
    AlreadyRunning,

    #[error("not running")]
    NotRunning,

    #[error("pcap error: {0}")]
    Pcap(#[from] pcap::Error),

    #[error("configuration error: {0}")]
    Config(String),
}
