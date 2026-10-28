//! Authenticated, versioned encryption envelope. The complete header is AAD/MAC input.
use crate::{formats, invalid, Cipher, DataFormat, Error, Kdf, Result};
use aes::Aes256;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params as ArgonParams, Version};
use base64::{engine::general_purpose::STANDARD, Engine};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use zeroize::Zeroizing;

const FORMAT: &str = "cfgtool-encrypted-config";
const AAD_PREFIX: &[u8] = b"cfgtool:v1:header:";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfParams {
    pub name: Kdf,
    pub salt: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_kib: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p: Option<u32>,
}
impl KdfParams {
    fn new(name: Kdf) -> Self {
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        let mut v = Self {
            name,
            salt: STANDARD.encode(salt),
            memory_kib: None,
            iterations: None,
            parallelism: None,
            n: None,
            r: None,
            p: None,
        };
        match name {
            Kdf::Argon2id => {
                v.memory_kib = Some(65536);
                v.iterations = Some(3);
                v.parallelism = Some(1);
            }
            Kdf::Pbkdf2Sha256 => v.iterations = Some(200_000),
            Kdf::Scrypt => {
                v.n = Some(32768);
                v.r = Some(8);
                v.p = Some(1);
            }
        }
        v
    }
    fn salt_bytes(&self) -> Result<Vec<u8>> {
        let salt = STANDARD
            .decode(&self.salt)
            .map_err(|_| invalid("invalid KDF salt encoding"))?;
        if salt.len() != 16 {
            return Err(invalid("KDF salt must be 16 bytes"));
        }
        Ok(salt)
    }
    fn validate(&self) -> Result<()> {
        self.salt_bytes()?;
        let supported = match self.name {
            Kdf::Argon2id => {
                self.memory_kib == Some(65536)
                    && self.iterations == Some(3)
                    && self.parallelism == Some(1)
                    && self.n.is_none()
                    && self.r.is_none()
                    && self.p.is_none()
            }
            Kdf::Pbkdf2Sha256 => {
                self.iterations == Some(200_000)
                    && self.memory_kib.is_none()
                    && self.parallelism.is_none()
                    && self.n.is_none()
                    && self.r.is_none()
                    && self.p.is_none()
            }
            Kdf::Scrypt => {
                self.n == Some(32768)
                    && self.r == Some(8)
                    && self.p == Some(1)
                    && self.memory_kib.is_none()
                    && self.iterations.is_none()
                    && self.parallelism.is_none()
            }
        };
        if !supported {
            return Err(invalid(
                "unsupported KDF parameters (only bounded v1 presets are accepted)",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub version: u32,
    pub payload_format: DataFormat,
    pub cipher: Cipher,
    pub kdf: KdfParams,
    pub nonce: String,
    pub ciphertext: String,
    pub tag: String,
}

#[derive(Serialize)]
struct Header<'a> {
    format: &'a str,
    version: u32,
    payload_format: DataFormat,
    cipher: Cipher,
    kdf: &'a KdfParams,
    nonce: &'a str,
}
fn aad(e: &Envelope) -> Result<Vec<u8>> {
    let header = Header {
        format: &e.format,
        version: e.version,
        payload_format: e.payload_format,
        cipher: e.cipher,
        kdf: &e.kdf,
        nonce: &e.nonce,
    };
    let mut out = AAD_PREFIX.to_vec();
    out.extend(serde_json::to_vec(&header)?);
    Ok(out)
}
fn kdf_key(password: &str, params: &KdfParams, length: usize) -> Result<Zeroizing<Vec<u8>>> {
    if password.is_empty() {
        return Err(invalid("password cannot be empty"));
    }
    params.validate()?;
    if length != 32 && length != 64 {
        return Err(invalid("invalid key length"));
    }
    let salt = params.salt_bytes()?;
    let mut key = Zeroizing::new(vec![0u8; length]);
    match params.name {
        Kdf::Argon2id => {
            let cfg = ArgonParams::new(65536, 3, 1, Some(length))
                .map_err(|_| invalid("invalid Argon2 parameters"))?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, cfg)
                .hash_password_into(password.as_bytes(), &salt, &mut key[..])
                .map_err(|_| invalid("Argon2 key derivation failed"))?;
        }
        Kdf::Pbkdf2Sha256 => {
            pbkdf2::pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, 200_000, &mut key[..])
        }
        Kdf::Scrypt => {
            let p = scrypt::Params::new(15, 8, 1, length)
                .map_err(|_| invalid("invalid scrypt parameters"))?;
            scrypt::scrypt(password.as_bytes(), &salt, &p, &mut key[..])
                .map_err(|_| invalid("scrypt key derivation failed"))?;
        }
    }
    Ok(key)
}

pub fn validate_header(e: &Envelope) -> Result<()> {
    if e.format != FORMAT || e.version != 1 {
        return Err(invalid("unknown encrypted envelope/version"));
    }
    e.kdf.validate()?;
    let nonce = STANDARD
        .decode(&e.nonce)
        .map_err(|_| invalid("invalid nonce base64"))?;
    if nonce.len() != e.cipher.nonce_size() {
        return Err(invalid("invalid nonce size"));
    }
    let tag = STANDARD
        .decode(&e.tag)
        .map_err(|_| invalid("invalid tag base64"))?;
    if tag.len() != e.cipher.tag_size() {
        return Err(invalid("invalid authentication tag size"));
    }
    let ct = STANDARD
        .decode(&e.ciphertext)
        .map_err(|_| invalid("invalid ciphertext base64"))?;
    if ct.is_empty() {
        return Err(invalid("empty ciphertext"));
    }
    if e.cipher == Cipher::Aes256CbcHmac && ct.len() % 16 != 0 {
        return Err(invalid("invalid AES-CBC ciphertext length"));
    }
    Ok(())
}

pub fn encrypt_new(
    plaintext: &[u8],
    format: DataFormat,
    cipher: Cipher,
    kdf: Kdf,
    password: &str,
) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Err(invalid("password cannot be empty"));
    }
    let mut nonce = vec![0u8; cipher.nonce_size()];
    OsRng.fill_bytes(&mut nonce);
    let mut e = Envelope {
        format: FORMAT.to_string(),
        version: 1,
        payload_format: format,
        cipher,
        kdf: KdfParams::new(kdf),
        nonce: STANDARD.encode(&nonce),
        ciphertext: String::new(),
        tag: String::new(),
    };
    let aad = aad(&e)?;
    let key = kdf_key(password, &e.kdf, cipher.key_size())?;
    let (ct, tag) = match cipher {
        Cipher::Aes256Gcm => {
            let c =
                Aes256Gcm::new_from_slice(&key).map_err(|_| invalid("invalid encryption key"))?;
            let combined = c
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| invalid("encryption failed"))?;
            split_tag(combined, 16)?
        }
        Cipher::Xchacha20Poly1305 => {
            let c = XChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| invalid("invalid encryption key"))?;
            let combined = c
                .encrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| invalid("encryption failed"))?;
            split_tag(combined, 16)?
        }
        Cipher::Aes256CbcHmac => {
            let ct = cbc::Encryptor::<Aes256>::new_from_slices(&key[..32], &nonce)
                .map_err(|_| invalid("invalid CBC key/iv"))?
                .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
            let tag = mac_cbc(&key[32..], &aad, &ct)?;
            (ct, tag)
        }
    };
    e.ciphertext = STANDARD.encode(ct);
    e.tag = STANDARD.encode(tag);
    let mut bytes = serde_json::to_vec_pretty(&e)?;
    bytes.push(b'\n');
    Ok(bytes)
}
fn split_tag(mut combined: Vec<u8>, size: usize) -> Result<(Vec<u8>, Vec<u8>)> {
    if combined.len() < size {
        return Err(invalid("cipher output too short"));
    }
    let tag = combined.split_off(combined.len() - size);
    Ok((combined, tag))
}
fn mac_cbc(key: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| invalid("invalid HMAC key"))?;
    mac.update(aad);
    mac.update(ciphertext);
    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn decrypt_new(value: &Value, password: &str) -> Result<(Value, DataFormat, Cipher, Kdf)> {
    let e: Envelope = serde_json::from_value(value.clone())?;
    validate_header(&e)?;
    let nonce = STANDARD
        .decode(&e.nonce)
        .map_err(|_| invalid("invalid nonce"))?;
    let ct = STANDARD
        .decode(&e.ciphertext)
        .map_err(|_| invalid("invalid ciphertext"))?;
    let tag = STANDARD
        .decode(&e.tag)
        .map_err(|_| invalid("invalid authentication tag"))?;
    let aad = aad(&e)?;
    let key = kdf_key(password, &e.kdf, e.cipher.key_size())?;
    let plaintext = match e.cipher {
        Cipher::Aes256Gcm => {
            let cipher =
                Aes256Gcm::new_from_slice(&key).map_err(|_| invalid("invalid encryption key"))?;
            let mut combined = ct;
            combined.extend(tag);
            cipher
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &combined,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Authentication)?
        }
        Cipher::Xchacha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| invalid("invalid encryption key"))?;
            let mut combined = ct;
            combined.extend(tag);
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &combined,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::Authentication)?
        }
        Cipher::Aes256CbcHmac => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[32..])
                .map_err(|_| invalid("invalid HMAC key"))?;
            mac.update(&aad);
            mac.update(&ct);
            mac.verify_slice(&tag).map_err(|_| Error::Authentication)?;
            cbc::Decryptor::<Aes256>::new_from_slices(&key[..32], &nonce)
                .map_err(|_| invalid("invalid CBC key/iv"))?
                .decrypt_padded_vec_mut::<Pkcs7>(&ct)
                .map_err(|_| Error::Authentication)?
        }
    };
    let bytes = Zeroizing::new(plaintext);
    let text =
        std::str::from_utf8(&bytes).map_err(|_| invalid("decrypted payload is not UTF-8"))?;
    let data = formats::parse(text, e.payload_format)?;
    Ok((data, e.payload_format, e.cipher, e.kdf.name))
}
