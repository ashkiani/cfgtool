use cfgtool::{Cipher, DataFormat, Kdf, Origin};
use serde_json::{json, Value};
use std::{fs, io::Write, process::{Command,Stdio}};

#[test]
fn plaintext_formats_round_trip_and_keys() {
    let dir=tempfile::tempdir().unwrap();
    let mut data=json!({"database":{"host":"localhost","port":27017},"active":true,"items":[1,2]});
    assert_eq!(cfgtool::get(&data,"/database/port").unwrap(),&json!(27017));
    cfgtool::set(&mut data,"/database/path~1name",json!("x")).unwrap();
    assert_eq!(cfgtool::get(&data,"/database/path~1name").unwrap(),&json!("x"));
    cfgtool::remove(&mut data,"/database/path~1name").unwrap();
    for format in [DataFormat::Json,DataFormat::Xml] {
        let file=dir.path().join(format!("data.{format}"));
        cfgtool::write(&file,&data,format,None,false).unwrap();
        let restored=cfgtool::read(&file,None).unwrap();
        assert_eq!(restored.data,data);
        assert_eq!(restored.format,format);
        assert_eq!(restored.origin,Origin::Plain);
    }
    let env=json!({"HOST":"localhost","PASSWORD":"quote=\"# test"});
    let file=dir.path().join("data.env");
    cfgtool::write(&file,&env,DataFormat::Env,None,false).unwrap();
    assert_eq!(cfgtool::read(&file,None).unwrap().data,env);
    assert!(cfgtool::write(&dir.path().join("bad.env"),&data,DataFormat::Env,None,false).is_err());
}

#[test]
fn all_ciphers_and_kdfs_authenticate_and_reencrypt() {
    let dir=tempfile::tempdir().unwrap();
    let value=json!({"password":"<test only>","nested":{"enabled":true}});
    for cipher in [Cipher::Aes256Gcm,Cipher::Aes256CbcHmac,Cipher::Xchacha20Poly1305] {
        for kdf in [Kdf::Argon2id,Kdf::Pbkdf2Sha256,Kdf::Scrypt] {
            let file=dir.path().join(format!("{:?}-{:?}.cfg",cipher,kdf));
            cfgtool::write(&file,&value,DataFormat::Json,Some((cipher,kdf,"fixture-password")),false).unwrap();
            let original=fs::read(&file).unwrap();
            assert_eq!(cfgtool::read(&file,Some("fixture-password")).unwrap().data,value);
            assert!(cfgtool::read(&file,Some("incorrect")).is_err());
            let mut altered:Value=serde_json::from_slice(&original).unwrap();
            altered["payload_format"]=json!("xml");
            fs::write(&file,serde_json::to_vec(&altered).unwrap()).unwrap();
            assert!(cfgtool::read(&file,Some("fixture-password")).is_err());
            cfgtool::write(&file,&value,DataFormat::Json,Some((cipher,kdf,"fixture-password")),true).unwrap();
            assert_ne!(fs::read(&file).unwrap(),original); // fresh salt and nonce
        }
    }
}

#[test]
fn refuses_overwrite_and_preserves_existing_data_on_failed_write() {
    let dir=tempfile::tempdir().unwrap();
    let file=dir.path().join("app.json");
    cfgtool::write(&file,&json!({"ok":true}),DataFormat::Json,None,false).unwrap();
    let old=fs::read(&file).unwrap();
    assert!(cfgtool::write(&file,&json!({"x":123}),DataFormat::Json,None,false).is_err());
    assert_eq!(fs::read(&file).unwrap(),old);
    assert!(cfgtool::write(&file,&json!({"x":123}),DataFormat::Env,None,true).is_err());
    assert_eq!(fs::read(&file).unwrap(),old);
}

fn rpc(request: &str) -> (bool,Value) {
    let mut child=Command::new(env!("CARGO_BIN_EXE_cfgtool")).arg("rpc")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(request.as_bytes()).unwrap();
    let result=child.wait_with_output().unwrap();
    (result.status.success(),serde_json::from_slice(&result.stdout).unwrap())
}
#[test]
fn rpc_reads_writes_and_does_not_overwrite_by_default() {
    let dir=tempfile::tempdir().unwrap();
    let p=dir.path().join("app.cfg");
    let file=serde_json::to_string(&p.to_str().unwrap()).unwrap();
    let request=format!(r#"{{"op":"write","file":{file},"encrypted":true,"password":"fixture-password","data":{{"secret":"dummy"}}}}"#);
    let (success,out)=rpc(&request);
    assert!(success,"{out}");
    let (success,out)=rpc(&request);
    assert!(!success);
    assert_eq!(out["ok"],false);
    let (success,out)=rpc(&format!(r#"{{"op":"read","file":{file},"password":"fixture-password"}}"#));
    assert!(success,"{out}");
    assert_eq!(out["data"]["secret"],"dummy");
    let (success,_) = rpc(&format!(r#"{{"op":"read","file":{file},"password":"wrong"}}"#));
    assert!(!success);
}


#[test]
fn encrypted_json_xml_env_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let configurations = [
        (DataFormat::Json, json!({"flag": true, "nested": {"name": "demo"}})),
        (DataFormat::Xml, json!({"flag": true, "nested": {"name": "demo"}})),
        (DataFormat::Env, json!({"APP_NAME": "demo", "APP_MODE": "safe"})),
    ];
    for (format, data) in configurations {
        let file = dir.path().join(format!("{:?}.cfg", format));
        cfgtool::write(&file, &data, format, Some((Cipher::Aes256Gcm, Kdf::Argon2id, "test-passphrase")), false).unwrap();
        let restored = cfgtool::read(&file, Some("test-passphrase")).unwrap();
        assert_eq!(restored.data, data);
        assert_eq!(restored.format, format);
        assert_eq!(restored.origin, Origin::Encrypted);
    }
}

#[test]
fn incorrect_password_never_overwrites_existing_file() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("private.cfg");
    cfgtool::write(&file, &json!({"key":"value"}), DataFormat::Json,
        Some((Cipher::Aes256Gcm, Kdf::Argon2id, "correct")), false).unwrap();
    let original = fs::read(&file).unwrap();
    assert!(cfgtool::read(&file, Some("wrong")).is_err());
    assert_eq!(fs::read(&file).unwrap(), original);
}

#[test]
fn non_encrypted_object_with_format_or_cipher_fields_stays_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("fields.json");
    let data = json!({"format":"custom", "cipher":"example", "ciphertext":"data"});
    cfgtool::write(&file, &data, DataFormat::Json, None, false).unwrap();
    assert_eq!(cfgtool::read(&file, None).unwrap().data, data);
}

#[test]
fn invalid_nested_pointer_fails_without_data_loss() {
    let mut data = json!({"settings": {"flag": true}});
    assert!(cfgtool::set(&mut data, "/settings/flag/child", json!("x")).is_err());
    assert_eq!(data, json!({"settings": {"flag": true}}));
    assert!(cfgtool::remove(&mut data, "/settings/missing").is_err());
}

#[test]
fn independently_generated_pbkdf2_vectors() {
    let dir = tempfile::tempdir().unwrap();
    let cases = [
        ("aes-256-gcm.json", Cipher::Aes256Gcm),
        ("aes-256-cbc-hmac-sha256.json", Cipher::Aes256CbcHmac),
    ];
    for (name, cipher) in cases {
        let file = dir.path().join(name);
        let bytes: &[u8] = match name {
            "aes-256-gcm.json" => include_bytes!("fixtures/aes-256-gcm.json"),
            _ => include_bytes!("fixtures/aes-256-cbc-hmac-sha256.json"),
        };
        fs::write(&file, bytes).unwrap();
        let doc = cfgtool::read(&file, Some("fixture-password")).unwrap();
        assert_eq!(doc.cipher, Some(cipher));
        assert_eq!(doc.data, json!({"example":"synthetic","enabled":true,"number":42}));
        assert!(cfgtool::read(&file, Some("wrong-password")).is_err());
    }
}

#[test]
fn rpc_explicitly_blocks_plaintext_downgrade() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("secure.cfg");
    let file = serde_json::to_string(&p.to_str().unwrap()).unwrap();
    let initial = format!(r#"{{"op":"write","file":{file},"encrypted":true,"password":"passphrase","data":{{"item":"value"}}}}"#);
    let (ok, _) = rpc(&initial);
    assert!(ok);
    let attempt = format!(r#"{{"op":"write","file":{file},"overwrite":true,"data":{{"item":"value"}}}}"#);
    let (ok, response) = rpc(&attempt);
    assert!(!ok);
    assert_eq!(response["ok"], false);
    assert!(cfgtool::read(&p, Some("passphrase")).is_ok());
}

#[test]
fn cli_rekey_rotates_password_without_losing_values() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("rotate.cfg");
    cfgtool::write(&file, &json!({"setting":"kept"}), DataFormat::Json,
        Some((Cipher::Aes256Gcm, Kdf::Pbkdf2Sha256, "old-password")), false).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_cfgtool"))
        .arg("rekey").arg(&file).arg("--password-stdin")
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped())
        .spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"old-password\nnew-password\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(cfgtool::read(&file, Some("old-password")).is_err());
    assert_eq!(cfgtool::read(&file, Some("new-password")).unwrap().data["setting"], "kept");
}
