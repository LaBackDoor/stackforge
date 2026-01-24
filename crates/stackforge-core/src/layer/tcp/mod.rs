//! TCP (Transmission Control Protocol) layer module.
//!
//! This module implements the TCP protocol (RFC 793), providing packet parsing (via `TcpLayer`),
//! construction (via `TcpBuilder`), options handling, and checksum verification.
//!
//! # Features
//!
//! - Zero-copy parsing with lazy field access
//! - Complete TCP options support (MSS, Window Scale, SACK, Timestamps, etc.)
//! - TCP-AO (Authentication Option) support per RFC 5925
//! - Checksum calculation with IPv4/IPv6 pseudo-header
//! - Service name resolution for well-known ports
//! - Builder pattern for packet construction
//!
//! # Example
//!
//! ```rust
//! use stackforge_core::layer::tcp::{TcpBuilder, TcpFlags};
//!
//! // Build a SYN packet
//! let packet = TcpBuilder::new()
//!     .src_port(12345)
//!     .dst_port(80)
//!     .seq(1000)
//!     .syn()
//!     .window(65535)
//!     .mss(1460)
//!     .build();
//! ```

// Submodules
pub mod builder;
pub mod checksum;
pub mod flags;
pub mod header;
pub mod options;
pub mod services;

// Re-export primary types for easier access
pub use builder::TcpBuilder;
pub use checksum::{tcp_checksum, tcp_checksum_ipv4, verify_tcp_checksum};
pub use flags::TcpFlags;
pub use header::{
    FIELDS as TCP_FIELDS, TCP_MAX_HEADER_LEN, TCP_MIN_HEADER_LEN, TcpLayer, offsets as tcp_offsets,
};
pub use options::{
    TcpAoValue, TcpOption, TcpOptionKind, TcpOptions, TcpOptionsBuilder, TcpSackBlock, TcpTimestamp,
};
pub use services::{TCP_SERVICES, service_name, service_port};
