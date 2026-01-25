# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Stackforge is a high-performance networking stack and automata framework written in Rust with Python bindings via PyO3/maturin. It provides Scapy-like packet manipulation with native Rust performance.

## Build & Development Commands

```bash
# Install dependencies and set up virtual environment
uv sync

# Build Rust extension and install in editable mode (required after Rust changes)
uv run maturin develop

# Run all Rust tests
cargo test

# Run a specific Rust test
cargo test test_name

# Run Python tests
uv run pytest tests/python

# Lint and format
cargo fmt
cargo clippy
uv run ruff check .
```

## Architecture

### Crate Structure

- **`stackforge` (root)** - PyO3 bindings that expose Rust functionality to Python. Compiles to a `cdylib`.
- **`stackforge-core`** - Core networking primitives implementing the "Lazy Zero-Copy View" architecture.
- **`stackforge-automata`** - Async state machine framework for network automation (placeholder, planned for future).

### Lazy Zero-Copy View Architecture

The core design pattern in `stackforge-core`:

1. **Zero-Copy Buffers**: Packets stored as `bytes::Bytes` (reference-counted, clone-on-write)
2. **Index-Only Parsing**: `Packet::parse()` only identifies layer boundaries (start/end offsets), not field values
3. **On-Demand Field Access**: Fields read directly from buffer when accessed (e.g., `eth.ethertype(buf)`)
4. **Copy-on-Write Mutation**: `Packet::with_data_mut()` clones buffer only when shared

### Key Types

- `Packet` (`packet.rs`) - Main packet container with `Bytes` buffer and `SmallVec<LayerIndex>`
- `LayerKind` - Enum identifying protocol types (Ethernet, ARP, IPv4, TCP, etc.)
- `LayerIndex` - Lightweight struct storing `kind`, `start`, `end` offsets
- `Layer` trait - Interface for protocol layers with `summary()`, `header_len()`, `hashret()`, `answers()`
- Protocol layers (`EthernetLayer`, `ArpLayer`, `Ipv4Layer`, `TcpLayer`) - Views into packet buffer

### Layer Module Organization

`crates/stackforge-core/src/layer/`:
- `mod.rs` - `LayerKind`, `LayerIndex`, `Layer` trait, `LayerEnum` dispatch
- `field.rs` - Field abstraction with `MacAddress`, `BytesField`, `FieldValue`
- `bindings.rs` - Protocol relationships (e.g., Ethernet type 0x0806 → ARP)
- `ethernet.rs`, `arp.rs`, `ipv4/`, `tcp/` - Protocol-specific implementations
- `neighbor.rs` - ARP/NDP cache implementations

### Python Bindings

- `src/lib.rs` - PyO3 module exposing `Packet`, `LayerKind`, `LayerIndex`
- `python/stackforge/__init__.py` - Re-exports from compiled extension
- Python source configured via `tool.maturin.python-source = "python"` in pyproject.toml

## Testing

- Rust unit tests: inline in source files and `crates/stackforge-core/src/lib.rs`
- Rust integration tests: `tests/integration/`
- Python tests: `tests/python/test_core.py`
