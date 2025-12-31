# Contributing to Stackforge

Thank you for your interest in contributing! We welcome bug reports, feature requests, and pull requests.

## Prerequisites

* **Rust:** Stable toolchain (install via [rustup](https://rustup.rs/)).
* **Python:** Version 3.13 or higher.
* **uv:** Fast Python package manager (install via [astral.sh/uv](https://docs.astral.sh/uv/)).

## Setting Up the Environment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/LaBackDoor/stackforge.git
   cd stackforge
   ```

2. **Sync dependencies:** This will set up the virtual environment and install dependencies.

   ```bash
   uv sync
   ```

3. **Build and install in editable mode:** This compiles the Rust extension and installs it into the local environment.

   ```bash
   uv run maturin develop
   ```

## Running Tests

We use cargo for Rust tests and pytest for Python tests.

```bash
# Run Rust unit tests
cargo test

# Run Python integration tests
uv run pytest tests/python
```

## Linting and Formatting

Please ensure your code is formatted and linted before submitting a PR.

```bash
# Rust
cargo fmt
cargo clippy

# Python
# If you have ruff or black configured:
# uv run ruff check .
```

## Pull Request Process

1. Fork the repo and create your branch from main.
2. If you've added code that should be tested, add tests.
3. Ensure the test suite passes.
4. Make sure your code lints.
5. Issue that pull request!
