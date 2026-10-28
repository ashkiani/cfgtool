//! Small, reusable key/value configuration engine.
mod crypto;
mod formats;
mod storage;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fmt, path::Path};

pub use crypto::{decrypt_new, encrypt_new, KdfParams};
pub use storage::write_atomic;

pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Invalid(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("authentication failed (wrong password or modified file)")]
    Authentication,
    #[error("password is required for encrypted configuration")]
    PasswordRequired,
}
pub type Result<T> = std::result::Result<T, Error>;
pub fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum DataFormat {
    Json,
    Xml,
    Env,
}
impl fmt::Display for DataFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Json => "json",
                Self::Xml => "xml",
                Self::Env => "env",
            }
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum Cipher {
    #[serde(rename = "aes-256-gcm")]
    #[value(name = "aes-256-gcm")]
    Aes256Gcm,
    #[serde(rename = "aes-256-cbc+hmac-sha256")]
    #[value(name = "aes-256-cbc+hmac-sha256")]
    Aes256CbcHmac,
    #[serde(rename = "xchacha20-poly1305")]
    #[value(name = "xchacha20-poly1305")]
    Xchacha20Poly1305,
}
impl Cipher {
    pub fn nonce_size(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::Aes256CbcHmac => 16,
            Self::Xchacha20Poly1305 => 24,
        }
    }
    pub fn tag_size(self) -> usize {
        if self == Self::Aes256CbcHmac {
            32
        } else {
            16
        }
    }
    pub fn key_size(self) -> usize {
        if self == Self::Aes256CbcHmac {
            64
        } else {
            32
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum Kdf {
    #[serde(rename = "argon2id")]
    #[value(name = "argon2id")]
    Argon2id,
    #[serde(rename = "pbkdf2-sha256")]
    #[value(name = "pbkdf2-sha256")]
    Pbkdf2Sha256,
    #[serde(rename = "scrypt")]
    #[value(name = "scrypt")]
    Scrypt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Plain,
    Encrypted,
}
impl Origin {
    pub fn name(self) -> &'static str {
        match self {
            Self::Plain => "plaintext",
            Self::Encrypted => "cfgtool-v1",
        }
    }
}

#[derive(Debug)]
pub struct Document {
    pub data: Value,
    pub format: DataFormat,
    pub cipher: Option<Cipher>,
    pub kdf: Option<Kdf>,
    pub origin: Origin,
}

pub fn read(path: &Path, password: Option<&str>) -> Result<Document> {
    let bytes = storage::read_limited(path)?;
    let input = std::str::from_utf8(&bytes).map_err(|_| invalid("configuration must be UTF-8"))?;
    let trimmed = input.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') {
        let v: Value = serde_json::from_str(trimmed)?;
        let marker = v.get("format").and_then(Value::as_str);
        if marker == Some("cfgtool-encrypted-config") {
            let pw = password.ok_or(Error::PasswordRequired)?;
            let (data, format, cipher, kdf) = crypto::decrypt_new(&v, pw)?;
            return Ok(Document {
                data,
                format,
                cipher: Some(cipher),
                kdf: Some(kdf),
                origin: Origin::Encrypted,
            });
        }
        formats::validate_root(&v)?;
        return Ok(Document {
            data: v,
            format: DataFormat::Json,
            cipher: None,
            kdf: None,
            origin: Origin::Plain,
        });
    }
    let format = if trimmed.starts_with('<') {
        DataFormat::Xml
    } else {
        DataFormat::Env
    };
    let data = formats::parse(trimmed, format)?;
    Ok(Document {
        data,
        format,
        cipher: None,
        kdf: None,
        origin: Origin::Plain,
    })
}

pub fn write(
    path: &Path,
    data: &Value,
    format: DataFormat,
    encryption: Option<(Cipher, Kdf, &str)>,
    overwrite: bool,
) -> Result<()> {
    formats::validate_root(data)?;
    let bytes = formats::serialize(data, format)?;
    let output = if let Some((cipher, kdf, password)) = encryption {
        crypto::encrypt_new(&bytes, format, cipher, kdf, password)?
    } else {
        bytes
    };
    storage::write_atomic(path, &output, overwrite)
}

pub fn get<'a>(data: &'a Value, pointer: &str) -> Result<&'a Value> {
    if pointer.is_empty() {
        return Ok(data);
    }
    if !pointer.starts_with('/') {
        return Err(invalid(
            "key must be an RFC 6901 JSON Pointer (e.g., /database/host)",
        ));
    }
    data.pointer(pointer)
        .ok_or_else(|| invalid("key not found"))
}

pub fn set(data: &mut Value, pointer: &str, value: Value) -> Result<()> {
    let parts = pointer_parts(pointer)?;
    if parts.is_empty() {
        return Err(invalid("cannot replace the root; use write/rpc instead"));
    }
    let mut cursor = data;
    for key in &parts[..parts.len() - 1] {
        let map = cursor
            .as_object_mut()
            .ok_or_else(|| invalid("parent is not an object"))?;
        cursor = map
            .entry(key.clone())
            .or_insert_with(|| serde_json::json!({}));
    }
    let map = cursor
        .as_object_mut()
        .ok_or_else(|| invalid("parent is not an object"))?;
    map.insert(parts.last().expect("nonempty").clone(), value);
    Ok(())
}
pub fn remove(data: &mut Value, pointer: &str) -> Result<()> {
    let parts = pointer_parts(pointer)?;
    if parts.is_empty() {
        return Err(invalid("cannot remove the root"));
    }
    let parent_path = if parts.len() == 1 {
        String::new()
    } else {
        format!(
            "/{}",
            parts[..parts.len() - 1]
                .iter()
                .map(|s| s.replace('~', "~0").replace('/', "~1"))
                .collect::<Vec<_>>()
                .join("/")
        )
    };
    let parent = data
        .pointer_mut(&parent_path)
        .ok_or_else(|| invalid("parent key not found"))?;
    let map = parent
        .as_object_mut()
        .ok_or_else(|| invalid("parent is not an object"))?;
    if map.remove(parts.last().expect("nonempty")).is_none() {
        return Err(invalid("key not found"));
    }
    Ok(())
}
fn pointer_parts(pointer: &str) -> Result<Vec<String>> {
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    if !pointer.starts_with('/') {
        return Err(invalid("key must start with '/'"));
    }
    let components: Vec<_> = pointer[1..].split('/').collect();
    if components.len() > 64 {
        return Err(invalid("key nesting is too deep"));
    }
    components
        .into_iter()
        .map(|segment| {
            let mut out = String::new();
            let mut chars = segment.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    match chars.next() {
                        Some('0') => out.push('~'),
                        Some('1') => out.push('/'),
                        _ => return Err(invalid("invalid JSON Pointer escape")),
                    }
                } else {
                    out.push(ch)
                }
            }
            Ok(out)
        })
        .collect()
}

pub fn inspect(path: &Path) -> Result<Value> {
    let bytes = storage::read_limited(path)?;
    let s = std::str::from_utf8(&bytes)
        .map_err(|_| invalid("configuration must be UTF-8"))?
        .trim_start_matches('\u{feff}')
        .trim_start();
    if s.starts_with('{') {
        let v: Value = serde_json::from_str(s)?;
        if v.get("format").and_then(Value::as_str) == Some("cfgtool-encrypted-config") {
            let e: crypto::Envelope = serde_json::from_value(v)?;
            crypto::validate_header(&e)?;
            return Ok(
                serde_json::json!({"origin":"cfgtool-v1","encrypted":true,"format":e.payload_format,"cipher":e.cipher,"kdf":e.kdf.name}),
            );
        }
        formats::validate_root(&v)?;
        return Ok(serde_json::json!({"origin":"plaintext","encrypted":false,"format":"json"}));
    }
    let format = if s.starts_with('<') {
        DataFormat::Xml
    } else {
        DataFormat::Env
    };
    formats::parse(s, format)?;
    Ok(serde_json::json!({"origin":"plaintext","encrypted":false,"format":format}))
}
