# Contributing to Stackforge

Thank you for your interest in contributing! We welcome bug reports, feature requests, and pull requests.

## Prerequisites

- **Rust:** Stable toolchain — install via [rustup](https://rustup.rs/)
- **Python:** 3.13 or higher
- **uv:** Fast Python package manager — install via [astral.sh/uv](https://docs.astral.sh/uv/)
- **cog:** Conventional commit tool — install via `cargo install cocogitto`

## Setting Up the Environment

```bash
# 1. Clone the repository
git clone https://github.com/LaBackDoor/stackforge.git
cd stackforge

# 2. Sync Python dependencies
uv sync

# 3. Compile the Rust extension and install in editable mode
uv run maturin develop
```

> Re-run `uv run maturin develop` any time you change Rust code.

## Project Structure

```
stackforge/
├── crates/
│   ├── stackforge-core/        # Core Rust library (published to crates.io)
│   │   └── src/
│   │       ├── layer/          # Protocol implementations
│   │       │   ├── mod.rs      # LayerKind enum, Layer trait, LayerEnum dispatch
│   │       │   ├── bindings.rs # Protocol detection rules (ethertype, port → layer)
│   │       │   ├── field.rs    # Field abstractions (MacAddress, BytesField, etc.)
│   │       │   ├── ethernet.rs
│   │       │   ├── arp.rs
│   │       │   ├── ipv4/
│   │       │   ├── ipv6/
│   │       │   ├── tcp/
│   │       │   ├── udp/
│   │       │   ├── icmp/
│   │       │   ├── icmpv6/
│   │       │   ├── dns/
│   │       │   ├── http/
│   │       │   ├── http2/
│   │       │   ├── quic/
│   │       │   ├── l2tp/
│   │       │   ├── ssh/
│   │       │   ├── tls/
│   │       │   ├── dot11/      # 802.11 Wi-Fi
│   │       │   ├── dot15d4/    # 802.15.4 Zigbee
│   │       │   └── generic/    # Runtime custom protocols
│   │       ├── packet.rs
│   │       └── lib.rs
│   └── stackforge-automata/    # Async state machine framework (planned)
├── src/
│   └── lib.rs                  # PyO3 bindings
├── python/
│   └── stackforge/
│       ├── __init__.py         # Python re-exports
│       └── custom.py           # CustomLayer + typed fields
└── tests/
    ├── integration/            # Rust integration tests
    ├── python/                 # Python tests (pytest)
    │   └── scapy_compat/       # Scapy behavioural compatibility tests
    ├── uts/                    # UTS regression test suites (Scapy-format)
    └── sample_pcap/            # PCAP fixtures
```

## Running Tests

### Rust tests

```bash
# All unit + integration tests
cargo test

# Single test by name
cargo test test_name

# Single integration file
cargo test --test integration dns
```

### Python tests

```bash
# All Python tests
uv run pytest tests/python

# Single file
uv run pytest tests/python/test_dns.py

# Single test
uv run pytest tests/python/test_dns.py::test_dns_query_build

# Scapy compatibility tests only
uv run pytest tests/python/scapy_compat

# Verbose output
uv run pytest -v tests/python
```

### UTS regression tests

UTS files in `tests/uts/` are Scapy-format regression suites run via the Python test suite:

```bash
uv run pytest tests/python/scapy_compat/test_uts_integration.py
```

## Linting and Formatting

All of the following must pass before submitting a PR:

```bash
# Rust
cargo fmt
cargo clippy

# Python
uv run ruff check .
```

## Adding a New Protocol Layer

Follow the existing pattern used by layers like `dns`, `http`, or `quic`.

### 1. Create the layer module

```
crates/stackforge-core/src/layer/<proto>/
├── mod.rs        # Layer struct, parse(), fields, Layer trait impl
└── builder.rs    # (optional) Builder for constructing packets
```

The layer struct holds `start`/`end` offsets into a shared `Bytes` buffer — it does **not** copy field values on parse. Fields are read on demand:

```rust
pub struct MyProtoLayer {
    start: usize,
    end: usize,
}

impl MyProtoLayer {
    pub fn my_field<'a>(&self, buf: &'a [u8]) -> u16 {
        u16::from_be_bytes(buf[self.start..self.start + 2].try_into().unwrap())
    }
}
```

### 2. Register the `LayerKind` variant

In `crates/stackforge-core/src/layer/mod.rs`, add a variant to the `LayerKind` enum and handle it in `LayerEnum`.

### 3. Add detection rules

In `crates/stackforge-core/src/layer/bindings.rs`, register how the new layer is detected (e.g., from an ethertype, IP protocol number, or TCP/UDP port).

### 4. Expose via PyO3

If the layer needs Python-accessible fields, add them to the `PyO3` bindings in `src/lib.rs`.

### 5. Write tests

- **Rust:** Add `tests/integration/<proto>.rs` with parse and build tests.
- **Python:** Add `tests/python/test_<proto>.py` covering field access, builders, and edge cases.
- **UTS (optional):** Add `tests/uts/<proto>.uts` for Scapy-format regression tests.

## Architecture Notes

- **Lazy Zero-Copy View** — `Packet::parse()` only records layer boundaries (offsets). Field values are read directly from the buffer when accessed, with no upfront copying.
- **Copy-on-Write Mutation** — The underlying `Bytes` buffer is only cloned when a mutation occurs on a shared packet.
- **`Packet(raw)` is unparsed** — always call `.parse()` before accessing layers or fields.
- **`Packet::parse()` assumes Ethernet first** — Dot11 and Dot15d4 frames require a dedicated parse entry point.

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/) enforced by [cocogitto](https://docs.cocogitto.io/) (`cog`). All commits must follow the format:

```
<type>(<scope>): <description>

[optional body]
```

Common types:

| Type | When to use |
|------|-------------|
| `feat` | New feature or protocol |
| `fix` | Bug fix |
| `chore` | Maintenance, dependency updates, CI |
| `docs` | Documentation only |
| `test` | Adding or fixing tests |
| `refactor` | Code restructuring with no behaviour change |
| `perf` | Performance improvement |

Use `cog commit` instead of `git commit` to get an interactive prompt that validates the format:

```bash
cog commit feat "add OSPF layer"
cog commit fix  "correct DNS name compression offset"
```

Breaking changes must include a `!` after the type or a `BREAKING CHANGE:` footer:

```bash
cog commit feat! "redesign Layer trait interface"
```

## Versioning and Changelog

Versions and the changelog are managed by `cog`. Maintainers cut releases with:

```bash
# Bump version automatically based on commit history (patch / minor / major)
cog bump --auto

# Or bump explicitly
cog bump --patch
cog bump --minor
cog bump --major
```

`cog bump` runs `pre_bump_hooks` (updates `Cargo.toml` version), tags the commit, and regenerates `CHANGELOG.md` from the commit history. Contributors do not need to edit `CHANGELOG.md` manually.

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Add tests for any new behaviour — both Rust and Python.
3. Ensure all tests pass: `cargo test` and `uv run pytest tests/python`.
4. Ensure linting passes: `cargo fmt && cargo clippy && uv run ruff check .`
5. Open a pull request with a clear description of what changed and why.
