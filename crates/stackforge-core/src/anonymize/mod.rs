//! ML-optimized network flow anonymization.
//!
//! This module provides an inline anonymization pipeline for the Stackforge
//! flow extraction engine, enabling privacy-preserving machine learning on
//! network traffic data.
//!
//! # Architecture
//!
//! Anonymization is applied **at flow output** — the flow tracking engine
//! uses real identifiers internally for correctness, and the
//! [`AnonymizationEngine`] transforms the exported [`ConversationState`]
//! structs before they reach the user.
//!
//! # Cryptographic primitives
//!
//! | Field category    | Algorithm                  | ML impact                           |
//! |-------------------|----------------------------|-------------------------------------|
//! | IPv4/IPv6         | Crypto-PAn (AES-128)       | Subnet topology preserved           |
//! | MAC addresses     | Salted SipHash (48-bit)    | Device tracking preserved           |
//! | Transport ports   | Category generalization    | Service identification preserved    |
//! | Timestamps        | Epoch shift ± bounded jitter | Ordering & durations preserved   |
//! | TCP seq/ack       | Per-flow random offset     | Retransmission detection preserved  |
//! | Payloads          | Truncation                 | Removes PII from reassembled data   |
//!
//! # Example
//!
//! ```rust,no_run
//! use stackforge_core::anonymize::{AnonymizationEngine, AnonymizationPolicy};
//! use stackforge_core::flow::{extract_flows_with_config, FlowConfig};
//! use stackforge_core::pcap::rdpcap;
//!
//! let packets = rdpcap("capture.pcap").unwrap();
//! let mut conversations = extract_flows_with_config(&packets, FlowConfig::default()).unwrap();
//!
//! let mut engine = AnonymizationEngine::new(AnonymizationPolicy::ml_optimized());
//! engine.anonymize_conversations(&mut conversations);
//!
//! for conv in &conversations {
//!     // IPs are now prefix-preserving pseudonyms
//!     println!("{} -> {}", conv.key.addr_a, conv.key.addr_b);
//! }
//! ```

pub mod crypto_pan;
pub mod engine;
pub mod hash;
pub mod policy;
pub mod port;
pub mod timestamp;

// Re-exports for convenience
pub use engine::AnonymizationEngine;
pub use hash::SaltedHasher;
pub use policy::{
    AnonymizationPolicy, IpAnonymizationMode, MacAnonymizationMode, PayloadAnonymizationMode,
    PortAnonymizationMode, TcpSeqAnonymizationMode, TimestampAnonymizationMode,
};
pub use port::{PortCategory, categorize_port, generalize_port};
