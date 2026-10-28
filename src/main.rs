use cfgtool::{Cipher, DataFormat, Document, Error, Kdf, Origin, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{io::{self, BufRead, Read}, path::{Path, PathBuf}};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name="cfgtool", version, about="Fast, portable key/value configuration management with optional authenticated encryption")]
struct Cli { #[command(subcommand)] command: Command }

#[derive(Subcommand)]
enum Command {
    /// Create an empty configuration file.
    Create {
        file: PathBuf,
        #[arg(long, value_enum, default_value_t=DataFormat::Json)] format: DataFormat,
        #[arg(long)] encrypted: bool,
        #[arg(long, value_enum, default_value_t=Cipher::Aes256Gcm)] cipher: Cipher,
        #[arg(long, value_enum, default_value_t=Kdf::Argon2id)] kdf: Kdf,
        #[arg(long)] password_stdin: bool,
    },
    /// Read a value by RFC 6901 JSON Pointer (e.g., /database/host).
    Get { file: PathBuf, key: String, #[arg(long)] raw: bool, #[arg(long)] password_stdin: bool },
    /// Set a key. Use --value-stdin for secret values (not command-line arguments).
    Set {
        file: PathBuf, key: String, value: Option<String>,
        #[arg(long, value_enum, default_value_t=ValueKind::String)] value_type: ValueKind,
        #[arg(long)] value_stdin: bool,
        #[arg(long)] password_stdin: bool,
    },
    /// Remove a key.
    Remove { file: PathBuf, key: String, #[arg(long)] password_stdin: bool },
    /// List top-level key names (never prints values).
    List { file: PathBuf, #[arg(long)] password_stdin: bool },
    /// Inspect format/cipher without decrypting or exposing secrets.
    Inspect { file: PathBuf },
    /// Convert to another file/format; never modifies the input.
    Convert {
        file: PathBuf,
        #[arg(long)] output: PathBuf,
        #[arg(long, value_enum)] format: Option<DataFormat>,
        #[arg(long)] encrypted: bool,
        #[arg(long)] allow_plaintext: bool,
        #[arg(long, value_enum, default_value_t=Cipher::Aes256Gcm)] cipher: Cipher,
        #[arg(long, value_enum, default_value_t=Kdf::Argon2id)] kdf: Kdf,
        #[arg(long)] overwrite: bool,
        #[arg(long)] password_stdin: bool,
    },
    /// Change password for an encrypted configuration.
    Rekey { file: PathBuf, #[arg(long)] password_stdin: bool },
    /// One structured JSON request in stdin, one JSON response in stdout.
    Rpc,
}
#[derive(Clone, Copy, ValueEnum)]
enum ValueKind { String, Json }

fn password(stdin: bool, prompt: &str) -> Result<Zeroizing<String>> {
    let s = if stdin {
        let mut s = String::new();
        let n = io::stdin().lock().take(4097).read_line(&mut s)?;
        if n == 0 || n > 4096 { return Err(cfgtool::invalid("invalid password input length")); }
        while s.ends_with('\n') || s.ends_with('\r') { s.pop(); }
        s
    } else { rpassword::prompt_password(prompt)? };
    if s.is_empty() { return Err(cfgtool::invalid("password cannot be empty")); }
    Ok(Zeroizing::new(s))
}
fn password_if_required(path: &Path, from_stdin: bool) -> Result<(Document,Option<Zeroizing<String>>)> {
    if from_stdin {
        let pw = password(true, "")?;
        let doc = cfgtool::read(path,Some(&pw))?;
        return Ok((doc,Some(pw)));
    }
    match cfgtool::read(path,None) {
        Ok(doc) => Ok((doc,None)),
        Err(Error::PasswordRequired) => {
            let pw = password(false,"Configuration password: ")?;
            let doc = cfgtool::read(path,Some(&pw))?;
            Ok((doc,Some(pw)))
        }
        Err(e) => Err(e)
    }
}
fn secure_create_pw(from_stdin: bool) -> Result<Zeroizing<String>> {
    let pw = password(from_stdin,"New password: ")?;
    if !from_stdin {
        let confirm = password(false,"Confirm password: ")?;
        if pw.as_str() != confirm.as_str() { return Err(cfgtool::invalid("password confirmation did not match")); }
    }
    Ok(pw)
}
fn write_modified(path: &Path, doc: &Document, value: &Value, pw: Option<&str>) -> Result<()> {
    let encryption = match (doc.cipher,doc.kdf) {
        (Some(c),Some(k)) => Some((c,k,pw.ok_or(Error::PasswordRequired)?)),
        (None,None) => None,
        _ => return Err(cfgtool::invalid("invalid document encryption metadata")),
    };
    cfgtool::write(path,value,doc.format,encryption,true)
}
fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Create { file,format,encrypted,cipher,kdf,password_stdin } => {
            let pw = if encrypted { Some(secure_create_pw(password_stdin)?) } else { None };
            let encryption = pw.as_ref().map(|p| (cipher,kdf,p.as_str()));
            cfgtool::write(&file,&json!({}),format,encryption,false)?;
            println!("Created {}",file.display());
        }
        Command::Get { file,key,raw,password_stdin } => {
            let (doc,_pw) = password_if_required(&file,password_stdin)?;
            let v = cfgtool::get(&doc.data,&key)?;
            if raw {
                println!("{}",v.as_str().ok_or_else(|| cfgtool::invalid("--raw requires a string value"))?);
            } else { println!("{}",serde_json::to_string_pretty(v)?); }
        }
        Command::Set { file,key,value,value_type,value_stdin,password_stdin } => {
            if value_stdin && (value.is_some() || password_stdin) { return Err(cfgtool::invalid("--value-stdin conflicts with positional value and --password-stdin; use rpc for both secrets")); }
            let input = if value_stdin {
                let mut s=String::new(); io::stdin().lock().take(1024*1024+1).read_to_string(&mut s)?;
                if s.len() > 1024*1024 { return Err(cfgtool::invalid("value exceeds 1 MiB")); }
                s.trim_end_matches(|c| c == '\r' || c == '\n').to_owned()
            } else { value.ok_or_else(|| cfgtool::invalid("provide VALUE or --value-stdin"))? };
            let v = match value_type { ValueKind::String => Value::String(input), ValueKind::Json => serde_json::from_str(&input)? };
            let (mut doc,pw) = password_if_required(&file,password_stdin)?;
            cfgtool::set(&mut doc.data,&key,v)?;
            write_modified(&file,&doc,&doc.data,pw.as_ref().map(|p|p.as_str()))?;
            println!("Updated {}",file.display());
        }
        Command::Remove { file,key,password_stdin } => {
            let (mut doc,pw) = password_if_required(&file,password_stdin)?;
            cfgtool::remove(&mut doc.data,&key)?;
            write_modified(&file,&doc,&doc.data,pw.as_ref().map(|p|p.as_str()))?;
            println!("Updated {}",file.display());
        }
        Command::List { file,password_stdin } => {
            let (doc,_pw) = password_if_required(&file,password_stdin)?;
            for k in doc.data.as_object().expect("validated root").keys() { println!("{k}"); }
        }
        Command::Inspect { file } => println!("{}",serde_json::to_string_pretty(&cfgtool::inspect(&file)?)?),
        Command::Convert { file,output,format,encrypted,allow_plaintext,cipher,kdf,overwrite,password_stdin } => {
            if file.canonicalize().ok().is_some_and(|src| output.canonicalize().ok().is_some_and(|dst|src==dst)) {
                return Err(cfgtool::invalid("input and output must be different files"));
            }
            let (doc,pw_old) = password_if_required(&file,password_stdin)?;
            let target_format = format.unwrap_or(doc.format);
            if !encrypted && doc.origin != Origin::Plain && !allow_plaintext { return Err(cfgtool::invalid("output would be plaintext; explicitly add --allow-plaintext")); }
            let new_pw = if encrypted { match pw_old { Some(p) => Some(p), None => Some(secure_create_pw(false)?) } } else { None };
            let encryption = new_pw.as_ref().map(|p| (cipher,kdf,p.as_str()));
            cfgtool::write(&output,&doc.data,target_format,encryption,overwrite)?;
            println!("Converted to {}",output.display());
        }
        Command::Rekey { file,password_stdin } => {
            let old_pw = password(password_stdin,"Current password: ")?;
            let doc = cfgtool::read(&file,Some(&old_pw))?;
            let cipher = doc.cipher.ok_or_else(|| cfgtool::invalid("file is not encrypted"))?;
            let kdf = doc.kdf.ok_or_else(|| cfgtool::invalid("missing KDF"))?;
            let new_pw = secure_create_pw(password_stdin)?;
            cfgtool::write(&file,&doc.data,doc.format,Some((cipher,kdf,&new_pw)),true)?;
            println!("Password updated for {}",file.display());
        }
        Command::Rpc => return run_rpc(),
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    op: String,
    file: PathBuf,
    password: Option<String>,
    data: Option<Value>,
    format: Option<DataFormat>,
    encrypted: Option<bool>,
    cipher: Option<Cipher>,
    kdf: Option<Kdf>,
    overwrite: Option<bool>,
    allow_plaintext: Option<bool>,
}
fn perform_rpc(mut req: Request) -> Result<Value> {
    let pw = req.password.take().map(Zeroizing::new);
    match req.op.as_str() {
        "read" => {
            let doc = cfgtool::read(&req.file,pw.as_deref().map(String::as_str))?;
            Ok(json!({"ok":true,"data":doc.data,"format":doc.format,"encrypted":doc.cipher.is_some(),"origin":doc.origin.name()}))
        }
        "inspect" => Ok(json!({"ok":true,"metadata":cfgtool::inspect(&req.file)?})),
        "write" => {
            let data = req.data.ok_or_else(|| cfgtool::invalid("write requires data"))?;
            let encrypted = req.encrypted.unwrap_or(false);
            if !encrypted && pw.is_some() { return Err(cfgtool::invalid("password supplied for plaintext write; specify encrypted:true")); }
            let encryption = if encrypted { Some((req.cipher.unwrap_or(Cipher::Aes256Gcm),req.kdf.unwrap_or(Kdf::Argon2id),pw.as_ref().ok_or(Error::PasswordRequired)?.as_str())) } else { None };
            // Never silently replace an encrypted file with plaintext.
            if !encrypted && req.overwrite.unwrap_or(false) && req.file.exists() {
                let existing = cfgtool::inspect(&req.file)?;
                if existing["encrypted"].as_bool() == Some(true) && req.allow_plaintext != Some(true) {
                    return Err(cfgtool::invalid("replacing encrypted data with plaintext requires allow_plaintext:true"));
                }
            }
            cfgtool::write(&req.file,&data,req.format.unwrap_or(DataFormat::Json),encryption,req.overwrite.unwrap_or(false))?;
            Ok(json!({"ok":true}))
        }
        _ => Err(cfgtool::invalid("unsupported rpc operation (read, write, inspect)")),
    }
}
fn run_rpc() -> Result<()> {
    // Limit machine requests to avoid unbounded memory consumption.
    let mut buf = Zeroizing::new(Vec::new());
    io::stdin().take(cfgtool::MAX_FILE_BYTES+1).read_to_end(&mut buf)?;
    let outcome = if buf.len() as u64 > cfgtool::MAX_FILE_BYTES { Err(cfgtool::invalid("rpc request exceeds 8 MiB")) }
        else { serde_json::from_slice::<Request>(&buf).map_err(Error::from).and_then(perform_rpc) };
    match outcome {
        Ok(response) => { println!("{}",serde_json::to_string(&response)?); Ok(()) }
        Err(e) => {
            println!("{}",serde_json::to_string(&json!({"ok":false,"error":e.to_string()}))?);
            Err(cfgtool::invalid("rpc request failed"))
        }
    }
}
fn main() {
    let is_rpc = std::env::args().nth(1).as_deref() == Some("rpc");
    if let Err(error) = run(Cli::parse()) {
        if !is_rpc { eprintln!("Error: {error}"); }
        std::process::exit(1);
    }
}
