# Contributing

Rust stable is required. Please run `cargo fmt --all`, `cargo test --all-targets`, and `cargo clippy --all-targets` before opening a pull request.

Include tests for any change affecting serialization, cryptography, file replacement, or command behavior. Keep command-line output stable and document any encrypted envelope changes in `docs/FORMAT.md`. Do not commit credentials or real configuration files.
