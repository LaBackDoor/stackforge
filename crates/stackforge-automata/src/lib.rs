//! # Stackforge Automata
//!
//! Async state machine framework for network automation tasks.
//!
//! This crate provides the infrastructure for implementing "Answering Machines"
//! and other stateful network automation patterns. It uses tokio internally
//! for timer support while exposing a synchronous API.
//!
//! ## Architecture
//!
//! - `Automaton` trait: define `is_request()` and `make_reply()` for packet-driven automata
//! - `AutomatonRuntime`: manages the sniffer, sender, and event loop on a dedicated thread
//! - `CallbackAutomaton`: closure-based automaton for simple use cases and Python bindings
//! - Built-in automata: `ArpSpoofer`, `DhcpServer`

pub mod arp_spoof;
pub mod config;
pub mod dhcp;
pub mod error;
pub mod forwarder;
pub mod runtime;
pub mod traits;

pub use config::AutomatonConfig;
pub use error::AutomatonError;
pub use runtime::AutomatonRuntime;
pub use traits::{Automaton, CallbackAutomaton};

// Re-export core types for convenience
pub use stackforge_core::{LayerKind, Packet};
