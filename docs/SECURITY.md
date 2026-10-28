# Security notes

- Modern authenticated encryption: AES-256-GCM and XChaCha20-Poly1305. CBC is supported only with independent encrypt-then-MAC HMAC-SHA256 authentication.
- Fresh random salt and nonce on every encrypted write; authenticated header; constant-time MAC verification in CBC mode.
- Strong password derivation with bounded Argon2id, PBKDF2-HMAC-SHA256, and scrypt presets. Prefer Argon2id and a strong passphrase for new files.
- The password is requested through a hidden terminal prompt or piped through standard input; there is no password command-line argument.
- Existing files are never overwritten by create/convert unless explicitly allowed. Replacement uses a temporary file in the destination directory, flush, file sync, and an atomic persist operation where supported by the filesystem.
- The maximum input file size is 8 MiB and the maximum tree nesting depth is 64.
- XML parsing rejects DTDs and limits parser nodes. `.env` never interpolates variables or evaluates code.
- Password strings and decrypted byte buffers are zeroized where practical. A separate process cannot guarantee that operating-system swap, caller memory, or captured stdout are secure. Use appropriate local permissions and avoid logging secrets.
- Decrypting into plaintext requires an explicit flag in the CLI. RPC rejects accidental replacement of encrypted files with plaintext unless `allow_plaintext:true` is provided.
- File encryption does not prevent file deletion, rollback to an older valid file, or unauthorized reads of configuration already loaded into a running application.
- Concurrent updates are **not serialized**: different writers can overwrite each other's changes (last completed writer wins). Callers must coordinate concurrent modifications and avoid editing the same file concurrently.
- File replacement uses the destination filesystem's behavior and permissions; on Windows it can fail if another process holds an incompatible file handle. Replacing a file may not retain the old file's access control metadata. Always apply appropriate directory/file permissions.
- The encrypted file format is a password-protected data format, **not** a guarantee that the executable itself is authentic. Verify executables separately (see [RELEASE.md](RELEASE.md)).

Security-sensitive use should follow a successful build, complete automated test run, and platform-specific smoke testing. No formal security audit is claimed.
