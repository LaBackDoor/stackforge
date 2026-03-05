use thiserror::Error;

use crate::error::PacketError;

/// Errors that can occur during flow extraction and conversation tracking.
#[derive(Debug, Error)]
pub enum FlowError {
    #[error("packet is not parsed (call .parse() first)")]
    PacketNotParsed,

    #[error("no IP layer found in packet")]
    NoIpLayer,

    #[error("no transport layer found in packet")]
    NoTransportLayer,

    #[error("reassembly buffer exceeded limit ({limit} bytes)")]
    ReassemblyBufferFull { limit: usize },

    #[error("too many discontinuous fragments ({count}, limit {limit})")]
    TooManyFragments { count: usize, limit: usize },

    #[error("disk spill I/O error: {0}")]
    SpillError(String),

    #[error(transparent)]
    PacketError(#[from] PacketError),
}
