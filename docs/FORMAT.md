# File formats (v1)

## Plaintext

A configuration is a JSON object whose values may be strings, numbers, booleans, null, objects, or arrays. A maximum nesting depth of 64 applies.

`json` is ordinary UTF-8 JSON. `env` is a documented flat string-only subset of dotenv syntax: blank lines, `#` comments, optional `export ` prefix, unquoted values, single-quoted values, and JSON-escaped double-quoted values. Keys must match `[A-Za-z_][A-Za-z0-9_]*`. Duplicate keys are errors; interpolation is not performed. `\n` within a double-quoted value represents a newline; literal multiline values are not accepted.

`xml` uses the following **typed format** (not arbitrary user-supplied XML):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<config version="1"><entry key="server" type="string">localhost</entry><entry key="port" type="number">8080</entry><entry key="secure" type="boolean">true</entry></config>
```

Objects use nested `<entry key="..." type="object">` elements; arrays use `<item type="...">`. Supported value types are `object`, `array`, `string`, `number`, `boolean`, and `null`. DTDs and unsupported nodes, types, or attributes are rejected. Duplicate keys are errors.

Conversion to `.env` requires flat strings; conversions that would lose types or hierarchy are rejected.

## Encrypted envelope

Encrypted files use UTF-8 JSON containing these fields:

```json
{
  "format": "cfgtool-encrypted-config",
  "version": 1,
  "payload_format": "json",
  "cipher": "aes-256-gcm",
  "kdf": {
    "name": "argon2id",
    "salt": "BASE64",
    "memory_kib": 65536,
    "iterations": 3,
    "parallelism": 1
  },
  "nonce": "BASE64",
  "ciphertext": "BASE64",
  "tag": "BASE64"
}
```

This example shows **field structure, not valid encrypted content**.

`payload_format` may be `json`, `xml`, or `env`. `cipher` may be `aes-256-gcm`, `aes-256-cbc+hmac-sha256`, or `xchacha20-poly1305`. `kdf.name` may be `argon2id`, `pbkdf2-sha256`, or `scrypt`. Salt and nonce are randomly generated for every write. Password-derived keys are 32 bytes for AEAD ciphers and 64 bytes (32 encryption + 32 MAC) for CBC+HMAC. All Base64 fields use standard padded Base64.

### KDF presets

- Argon2id: 16-byte salt, 64 MiB memory, 3 iterations, parallelism 1, version 0x13.
- PBKDF2-HMAC-SHA256: 16-byte salt, 200,000 iterations.
- scrypt: 16-byte salt, N=32768, r=8, p=1.

Other parameters are rejected in version 1, including arbitrarily expensive values provided by an untrusted header.

### Header authentication

The canonical AAD is the UTF-8 bytes `cfgtool:v1:header:` followed by compact JSON serialization of the header fields in this precise order:

```
format, version, payload_format, cipher, kdf, nonce
```

`kdf` fields use this order when present: `name, salt, memory_kib, iterations, parallelism, n, r, p` (with absent optional fields omitted).

For AES-256-GCM and XChaCha20-Poly1305, this AAD is passed to the AEAD encrypt/decrypt call. For AES-256-CBC, calculate HMAC-SHA256 over `AAD || ciphertext` with the 32-byte MAC key, and verify the tag in constant time **before** decrypting CBC. CBC uses PKCS#7 padding. Nonces are 12 bytes for GCM, 16 for CBC, 24 for XChaCha20; AEAD tags are 16 bytes and HMAC tags are 32 bytes.

Any modification to authenticated header fields or ciphertext causes decryption failure. A malicious deletion/replacement of an entire file is outside the scope of password-based file encryption.
