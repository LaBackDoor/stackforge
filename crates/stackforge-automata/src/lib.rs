//! # Stackforge Automata
//!
//! Async state machine framework for network automation tasks.
//!
//! This crate provides the infrastructure for implementing "Answering Machines"
//! and other stateful network automation patterns using Rust's async/await.
//!
//! ## Planned Features
//!
//! - Automaton trait for defining state machines
//! - ARP spoofer implementation
//! - DHCP server framework
//! - Generic request/response matchers
//!
//! This module will be implemented in Phase 3 (Months 7-9) of the roadmap.

#![warn(missing_docs)]

// Re-export core types for convenience
pub use stackforge_core::{LayerKind, Packet};

/// Placeholder for the Automaton trait.
///
/// This will be fully implemented in Phase 3.
pub trait Automaton {
    /// The type of event this automaton processes.
    type Event;

    /// The type of action this automaton can take.
    type Action;

    /// Process an event and return an action.
    fn process(&mut self, event: Self::Event) -> Option<Self::Action>;
}
