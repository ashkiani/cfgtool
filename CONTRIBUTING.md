# Contributing

Rust stable is required. Please run `cargo fmt --all -- --check`, `cargo clippy --all-targets --locked -- -D warnings`, and `cargo test --release --all-targets --locked` before opening a pull request.

Include tests for any change affecting serialization, cryptography, file replacement, or command behavior. Keep command-line output stable and document any encrypted envelope changes in `docs/FORMAT.md`. Do not commit credentials or real configuration files.
