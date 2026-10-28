# JSON request/response interface

Call `cfgtool rpc`. Send **one UTF-8 JSON request** on standard input; then close input. Read **one UTF-8 JSON response** from standard output. The process exits with status 0 on success and nonzero on errors. The request limit is 8 MiB.

## Read

```json
{"op":"read","file":"settings.cfg","password":"example-only"}
```

Successful response:

```json
{"ok":true,"data":{"server":"localhost"},"format":"json","encrypted":true,"origin":"cfgtool-v1"}
```

`password` is omitted for unencrypted input. A read returns the entire configuration object.

## Write

```json
{"op":"write","file":"settings.cfg","encrypted":true,"cipher":"aes-256-gcm","kdf":"argon2id","format":"json","password":"example-only","data":{"server":"localhost"},"overwrite":false}
```

Omit `encrypted` or set it to `false` for plaintext. `cipher` and `kdf` default to AES-256-GCM and Argon2id. `format` defaults to JSON. `overwrite` defaults to `false`. Replacing an encrypted file with plaintext requires both `overwrite:true` and `allow_plaintext:true`.

Successful response: `{"ok":true}`.

## Inspect

```json
{"op":"inspect","file":"settings.cfg"}
```

Returns `{ "ok": true, "metadata": { ... } }` containing format/cipher/KDF names but no decrypted values. A password is not needed.

## Errors

An error response has this structure:

```json
{"ok":false,"error":"authentication failed (wrong password or modified file)"}
```

No decrypted values appear in error responses. Consumers should check both exit status and the `ok` field. Avoid logging raw requests/responses as they can contain passwords and sensitive settings. For CLI operations requiring interactive passwords, use ordinary commands rather than RPC.
