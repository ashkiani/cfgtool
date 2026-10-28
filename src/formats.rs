//! Strict, reversible typed XML mapping and deliberately small dotenv subset.
use crate::{invalid, DataFormat, Result};
use roxmltree::{Document, Node, ParsingOptions};
use serde_json::{Map, Number, Value};

const MAX_DEPTH: usize = 64;

pub fn validate_root(value: &Value) -> Result<()> {
    if !value.is_object() { return Err(invalid("configuration root must be an object of key/value pairs")); }
    validate_depth(value, 0)
}
fn validate_depth(value: &Value, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH { return Err(invalid("configuration nesting exceeds limit")); }
    match value {
        Value::Object(m) => for v in m.values() { validate_depth(v, depth+1)?; },
        Value::Array(a) => for v in a { validate_depth(v, depth+1)?; },
        _ => {}
    }
    Ok(())
}

pub fn parse(input: &str, format: DataFormat) -> Result<Value> {
    let value = match format {
        DataFormat::Json => serde_json::from_str(input)?,
        DataFormat::Xml => read_xml(input)?,
        DataFormat::Env => read_env(input)?,
    };
    validate_root(&value)?;
    Ok(value)
}
pub fn serialize(value: &Value, format: DataFormat) -> Result<Vec<u8>> {
    validate_root(value)?;
    let text = match format {
        DataFormat::Json => serde_json::to_string_pretty(value)? + "\n",
        DataFormat::Xml => write_xml(value)?,
        DataFormat::Env => write_env(value)?,
    };
    Ok(text.into_bytes())
}

// XML schema: <config version="1"><entry key="NAME" type="object|array|string|number|boolean|null">...</entry></config>
// Inside arrays, children are <item type="...">; object children use <entry key="...">.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&apos;")
}
fn xml_text_ok(s: &str) -> bool { s.chars().all(|c| matches!(c, '\t' | '\n' | '\r') || matches!(c as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)) }
fn write_element(out: &mut String, element: &str, key: Option<&str>, value: &Value, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH { return Err(invalid("XML nesting too deep")); }
    out.push('<'); out.push_str(element);
    if let Some(k) = key {
        if !xml_text_ok(k) { return Err(invalid("invalid XML key characters")); }
        out.push_str(" key=\""); out.push_str(&xml_escape(k)); out.push('"');
    }
    let kind = match value {
        Value::Object(_) => "object", Value::Array(_) => "array", Value::String(_) => "string",
        Value::Number(_) => "number", Value::Bool(_) => "boolean", Value::Null => "null",
    };
    out.push_str(" type=\""); out.push_str(kind); out.push_str("\">");
    match value {
        Value::Object(m) => for (k,v) in m { write_element(out, "entry", Some(k), v, depth+1)?; },
        Value::Array(a) => for v in a { write_element(out, "item", None, v, depth+1)?; },
        Value::String(s) => { if !xml_text_ok(s) { return Err(invalid("invalid XML value characters")); } out.push_str(&xml_escape(s)) },
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Null => {},
    }
    out.push_str("</"); out.push_str(element); out.push('>');
    Ok(())
}
fn write_xml(value: &Value) -> Result<String> {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<config version=\"1\">");
    let map = value.as_object().expect("validated");
    for (k,v) in map { write_element(&mut out, "entry", Some(k), v, 1)?; }
    out.push_str("</config>\n");
    Ok(out)
}
fn read_xml(text: &str) -> Result<Value> {
    let doc = Document::parse_with_options(text, ParsingOptions { allow_dtd: false, nodes_limit: 100_000, ..ParsingOptions::default() })
        .map_err(|e| invalid(format!("invalid XML: {e}")))?;
    let root = doc.root_element();
    if root.tag_name().name() != "config" || root.tag_name().namespace().is_some() || root.attribute("version") != Some("1") || root.attributes().len() != 1 {
        return Err(invalid("expected <config version=\"1\"> XML mapping"));
    }
    let mut map = Map::new();
    for child in root.children() {
        if child.is_element() {
            if child.tag_name().name() != "entry" { return Err(invalid("unexpected XML element")); }
            let key = child.attribute("key").ok_or_else(|| invalid("XML entry missing key"))?.to_owned();
            let val = read_element(child, 1)?;
            if map.insert(key, val).is_some() { return Err(invalid("duplicate XML key")); }
        } else if child.is_text() && !child.text().unwrap_or("").trim().is_empty() { return Err(invalid("unexpected XML text")); }
    }
    Ok(Value::Object(map))
}
fn read_element(node: Node<'_, '_>, depth: usize) -> Result<Value> {
    if depth > MAX_DEPTH { return Err(invalid("XML nesting too deep")); }
    if node.tag_name().namespace().is_some() { return Err(invalid("XML namespaces not supported")); }
    let tag = node.tag_name().name();
    if tag != "entry" && tag != "item" { return Err(invalid("unexpected XML element")); }
    let expected_attrs = if tag == "entry" { 2 } else { 1 };
    if node.attributes().len() != expected_attrs || (tag == "entry" && node.attribute("key").is_none()) { return Err(invalid("invalid XML entry attributes")); }
    let kind = node.attribute("type").ok_or_else(|| invalid("XML type missing"))?;
    let children: Vec<_> = node.children().filter(|x| x.is_element()).collect();
    let text: String = node.children().filter(|x| x.is_text()).filter_map(|x| x.text()).collect();
    match kind {
        "object" => {
            if !text.trim().is_empty() { return Err(invalid("unexpected text in XML object")); }
            let mut map = Map::new();
            for child in children {
                if child.tag_name().name() != "entry" { return Err(invalid("invalid child in XML object")); }
                let key = child.attribute("key").ok_or_else(|| invalid("XML entry missing key"))?.to_owned();
                let v = read_element(child, depth+1)?;
                if map.insert(key,v).is_some() { return Err(invalid("duplicate XML key")); }
            }
            Ok(Value::Object(map))
        }
        "array" => {
            if !text.trim().is_empty() { return Err(invalid("unexpected text in XML array")); }
            let mut values = Vec::new();
            for child in children {
                if child.tag_name().name() != "item" { return Err(invalid("invalid child in XML array")); }
                values.push(read_element(child,depth+1)?);
            }
            Ok(Value::Array(values))
        }
        "string" if children.is_empty() => Ok(Value::String(text)),
        "number" if children.is_empty() => {
            let num: Number = text.parse().map_err(|_| invalid("invalid XML number"))?;
            Ok(Value::Number(num))
        }
        "boolean" if children.is_empty() => match text.as_str() {
            "true" => Ok(Value::Bool(true)), "false" => Ok(Value::Bool(false)), _ => Err(invalid("invalid XML boolean"))
        },
        "null" if children.is_empty() && text.is_empty() => Ok(Value::Null),
        _ => Err(invalid("invalid or unsupported XML value")),
    }
}

fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_') &&
        chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}
fn read_env(input: &str) -> Result<Value> {
    let mut map = Map::new();
    for (line_no,line) in input.lines().enumerate() {
        let s = line.trim();
        if s.is_empty() || s.starts_with('#') { continue; }
        let s = s.strip_prefix("export ").unwrap_or(s);
        let (key, rhs) = s.split_once('=').ok_or_else(|| invalid(format!("dotenv line {} has no '='",line_no+1)))?;
        let key = key.trim();
        if !valid_env_key(key) { return Err(invalid(format!("invalid dotenv key on line {}",line_no+1))); }
        let rhs = rhs.trim_start();
        let value = if rhs.starts_with('"') {
            let mut escaped = false;
            let mut end = None;
            for (i,c) in rhs.char_indices().skip(1) {
                if escaped { escaped = false; continue; }
                if c == '\\' { escaped = true; continue; }
                if c == '"' { end = Some(i+1); break; }
            }
            let end = end.ok_or_else(|| invalid("unterminated dotenv double quote"))?;
            let tail = rhs[end..].trim();
            if !tail.is_empty() && !tail.starts_with('#') { return Err(invalid("unexpected trailing dotenv content")); }
            serde_json::from_str::<String>(&rhs[..end])?
        } else if let Some(rest) = rhs.strip_prefix('\'') {
            let end = rest.find('\'').ok_or_else(|| invalid("unterminated dotenv single quote"))?;
            let tail = rest[end+1..].trim();
            if !tail.is_empty() && !tail.starts_with('#') { return Err(invalid("unexpected trailing dotenv content")); }
            rest[..end].to_string()
        } else {
            let mut prev_space = false;
            let mut end = rhs.len();
            for (i,c) in rhs.char_indices() {
                if c == '#' && prev_space { end = i; break; }
                prev_space = c.is_whitespace();
            }
            rhs[..end].trim_end().to_owned()
        };
        if map.insert(key.to_owned(), Value::String(value)).is_some() { return Err(invalid("duplicate dotenv key")); }
    }
    Ok(Value::Object(map))
}
fn write_env(data: &Value) -> Result<String> {
    let mut out = String::new();
    for (key,value) in data.as_object().expect("validated") {
        if !valid_env_key(key) { return Err(invalid(format!("unsupported dotenv key: {key}"))); }
        let s = value.as_str().ok_or_else(|| invalid(format!("dotenv only supports flat string values (key: {key})")))?;
        out.push_str(key); out.push('='); out.push_str(&serde_json::to_string(s)?); out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_json_types_xml_round_trip() {
        let val = serde_json::json!({"empty":"","q\"<'&":"<>&'\"","n":12.5,"t":true,"z":null,"a":[1,false,{"hello":"world"}],"object":{}});
        let s = serialize(&val,DataFormat::Xml).unwrap();
        let parsed = parse(std::str::from_utf8(&s).unwrap(), DataFormat::Xml).unwrap();
        assert_eq!(parsed,val);
    }
    #[test]
    fn env_round_trip_and_invalid_types() {
        let val = serde_json::json!({"A":"hello # world","B":"quote\" and newline\n","C":"","D":"a=b"});
        let s = serialize(&val,DataFormat::Env).unwrap();
        assert_eq!(parse(std::str::from_utf8(&s).unwrap(),DataFormat::Env).unwrap(),val);
        assert!(serialize(&serde_json::json!({"FLAG":true}),DataFormat::Env).is_err());
    }
    #[test]
    fn reject_dtd_and_duplicates() {
        assert!(parse("<!DOCTYPE config [<!ENTITY a 'secret'>]><config version=\"1\"><entry key=\"x\" type=\"string\">&a;</entry></config>",DataFormat::Xml).is_err());
        assert!(parse("A=1\nA=2",DataFormat::Env).is_err());
    }
}
