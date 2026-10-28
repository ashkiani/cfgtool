# cfgtool

A small, cross-platform command-line utility to read, write, edit, convert, and optionally encrypt key/value configuration files. Built with Rust. No service or runtime installation is needed to run the compiled binary.

## Features

- Plaintext **JSON**, **XML**, and **`.env`** files.
- Password-encrypted files using **AES-256-GCM** (default), **AES-256-CBC + HMAC-SHA256**, or **XChaCha20-Poly1305**.
- **Argon2id** (default), **PBKDF2-SHA256**, and **scrypt** password derivation.
- Create, get, set, remove, list keys, inspect file metadata, convert formats, and change passwords.
- Automatic recognition of files written by cfgtool; no cipher selection is needed when reading them.
- Atomic file replacement, no-clobber writes by default, authenticated encryption, input-size limits, and bounded password-derivation parameters.
- JSON request/response mode over standard input/output (`rpc`).
- Windows and Linux builds and automated tests.

## Build

Install the stable Rust toolchain from https://rustup.rs/ (on Windows, install the required C++ build tools if rustup asks).

```sh
cargo build --release
```

The executable is at `target/release/cfgtool` on Linux or `target\\release\\cfgtool.exe` on Windows.

Run all tests and check code formatting:

```sh
cargo test --all-targets
cargo fmt --all -- --check
```

If rustfmt reports formatting differences, run `cargo fmt --all` and then rerun the check. To check additional compiler lints: `cargo clippy --all-targets` (requires `rustup component add clippy`).

Commit the generated `Cargo.lock` when you perform the first successful build, and use `cargo build --release --locked` for subsequent reproducible dependency resolution.

## Quick start

Replace `cfgtool` with `.\\target\\release\\cfgtool.exe` on Windows, or `./target/release/cfgtool` on Linux.

```sh
# Create JSON with an empty object
cfgtool create settings.json

# Add values. Keys use JSON Pointer syntax.
cfgtool set settings.json /database/host localhost
cfgtool set settings.json /database/port 27017 --value-type json
cfgtool set settings.json /enabled true --value-type json

cfgtool get settings.json /database/host
cfgtool list settings.json
cfgtool inspect settings.json

# Change or remove keys
cfgtool set settings.json /enabled false --value-type json
cfgtool remove settings.json /enabled

# Convert to typed XML (does not change the input file)
cfgtool convert settings.json --output settings.xml --format xml

# Create a simple .env configuration
cfgtool create settings.env --format env
cfgtool set settings.env /API_HOST localhost

# Create a password-encrypted file; prompts for and confirms password
cfgtool create settings.cfg --encrypted
cfgtool set settings.cfg /database/host localhost
cfgtool get settings.cfg /database/host
cfgtool inspect settings.cfg

# Choose another cipher and KDF when creating an encrypted file
cfgtool create another.cfg --encrypted --cipher xchacha20-poly1305 --kdf scrypt

# Change the password on an encrypted file
cfgtool rekey settings.cfg

# Explicitly decrypt to a new plaintext file
cfgtool convert settings.cfg --output settings-open.json --allow-plaintext

# Encrypt an existing plaintext file
cfgtool convert settings.json --output encrypted.cfg --encrypted
```

Use `cfgtool --help` and `cfgtool <command> --help` for the complete option list. Note that `--cipher` selects an algorithm **only for new encryption**; it does not import unrelated encrypted-file layouts.

## Reading files

The tool detects its own encrypted JSON envelope, ordinary JSON objects, typed XML files, and flat `.env` files by content. A password is requested only for encrypted input.

For key paths, use [JSON Pointer](https://www.rfc-editor.org/rfc/rfc6901). For instance, `/database/host` addresses nested key `host` inside `database`. Escape `/` as `~1` and `~` as `~0` in key names. `set` creates missing intermediate objects. `get` and `remove` fail if the path is missing.

**JSON/XML values:** strings, numbers, booleans, null, arrays, and nested objects. **`.env` values:** flat strings only; keys use `[A-Za-z_][A-Za-z0-9_]*`. Converting nested/non-string values to `.env` fails rather than discarding information. XML uses a strict reversible typed mapping, **not an arbitrary XML schema**; see [docs/FORMAT.md](docs/FORMAT.md).

## Passwords and secret values

By default, encryption commands prompt for the password without echoing it. For non-interactive commands, `--password-stdin` reads one password line; `rekey --password-stdin` expects the old and new passwords on two separate lines.

Avoid passing secrets as positional arguments (process argument lists and shell history may reveal them). To set a secret value from standard input, use `set ... --value-stdin`. To supply both a password and a secret value programmatically, use `rpc`. **Decrypted values returned to stdout are sensitive**—do not log or persist the response accidentally.

Passwords protect encrypted files at rest. Applications reading decrypted data are responsible for their own memory, logging, and access controls. Plaintext configuration files provide no confidentiality. Do not commit actual credentials.

## Machine interface

Run `cfgtool rpc` with **one JSON request on stdin**. It returns one JSON response on stdout and exits. Supported operations are `read`, `write`, and `inspect`.

Example request:

```json
{"op":"write","file":"settings.cfg","encrypted":true,"password":"example-only","data":{"server":"localhost","port":8080}}
```

Example response:

```json
{"ok":true}
```

See [docs/PROTOCOL.md](docs/PROTOCOL.md) for the complete request format, security considerations, and error behavior. The Rust library exposes the same core read/write functions.

## Important limitations

- The tool supports three standard ciphers **inside its own documented file envelope**. Other programs can use the same ciphers with different salts, nonces, authentication layouts, or file formats; their files are **not automatically compatible**. No implicit import of arbitrary encrypted file formats is attempted.
- Encryption parameters in v1 use documented, bounded presets; this prevents malicious headers from forcing excessive resource use. AES-256-CBC is always used with Encrypt-then-MAC, never without authentication.
- File size is limited to 8 MiB, including the encrypted envelope. This utility is intended for configuration data, not large documents.
- Writes use a temporary file in the same directory before replacement. As with any tool, retain independent backups of valuable configuration files.

## Project files

- `src/lib.rs` – configuration API
- `src/main.rs` – CLI and RPC
- `src/formats.rs` – JSON, XML, `.env`
- `src/crypto.rs` – encryption and password derivation
- `src/storage.rs` – bounded file IO and safe replacement
- `tests/integration.rs` – end-to-end tests
- `docs/` – format, security, and machine-interface specifications
- `.github/workflows/ci.yml` – build and tests on Windows and Linux

Licensed under MIT. Contributions and bug reports are welcome.
