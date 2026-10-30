//! Rust port of `windows_silent_chrome.py`.
//!
//! This is a *line-by-line* port: same protection seed, same HMAC inputs, same
//! JSON serialisation, same field order, same write sequence, same final
//! `_encrypted_hash` cleanup. Nothing here uses an "alternative" technique.
//!
//! Only two things are configurable (they were hardcoded in the Python file):
//!   * the unpacked extension directory  (`--extension-path`)
//!   * the profile directory that holds `Secure Preferences` (`--profile-dir`)
//!
//! Everything else follows the Python implementation exactly.

use std::env;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::Command;

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// Chrome's fixed Windows protection key ("seed"), byte-identical to the
/// `seed = b'\xe7H\xf3...'` literal in the Python script.
const SEED_HEX: &str = "E748F336D85EA5F9DCDF25D8F347A65B4CDF667600F02DF6724A2AF18A212D26B788A25086910CF3A90313696871F3DC05823730C91DF8BA5C4FD9C884B505A8";

fn seed_bytes() -> Vec<u8> {
    hex::decode(SEED_HEX).expect("valid hardcoded seed hex")
}

// ===========================================================================
// Python-compatible `json.dumps`
// ===========================================================================
//
// The Python script relies on three different json.dumps flavours:
//   * `json.dumps(v, separators=(',', ':'), ensure_ascii=False)`  -> calculateHMAC
//   * `json.dumps(v)`                                            -> calc_supermac
//   * `json.dump(v, f, indent=4)`                                -> clean_json_file
//
// They differ in separators and in ASCII escaping, and the HMACs depend on the
// exact bytes, so they are reproduced precisely here.

fn py_write_string(out: &mut String, s: &str, ensure_ascii: bool) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c => {
                let cp = c as u32;
                if cp < 0x20 {
                    out.push_str(&format!("\\u{cp:04x}"));
                } else if ensure_ascii && !(0x20..=0x7e).contains(&cp) {
                    if cp <= 0xFFFF {
                        out.push_str(&format!("\\u{cp:04x}"));
                    } else {
                        let v = cp - 0x10000;
                        let hi = 0xD800 + (v >> 10);
                        let lo = 0xDC00 + (v & 0x3FF);
                        out.push_str(&format!("\\u{hi:04x}\\u{lo:04x}"));
                    }
                } else {
                    out.push(c);
                }
            }
        }
    }
    out.push('"');
}

/// `repr(float)` the way CPython formats it (`mode 'r'`): shortest round-trip
/// digits, switch to exponential when the decimal point lands at `decpt <= -4`
/// or `decpt > 16`, and `.0` appended for integral values in fixed notation.
///
/// This matters because `json.dumps` writes floats via `float.__repr__`.
fn py_float_repr(v: f64) -> String {
    if v.is_nan() {
        return "NaN".to_string();
    }
    if v.is_infinite() {
        return if v.is_sign_negative() { "-Infinity" } else { "Infinity" }.to_string();
    }

    let negative = v.is_sign_negative();
    // Shortest round-trip exponential form, e.g. "1.2345e16", "1e-7", "0e0".
    let exp_form = format!("{:e}", v.abs());
    let (mantissa, exp_str) = exp_form.split_once('e').expect("exponential form");
    let exp: i32 = exp_str.parse().expect("exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let decpt = exp + 1;

    let mut out = String::new();
    if negative {
        out.push('-');
    }

    if decpt <= -4 || decpt > 16 {
        out.push_str(&digits[..1]);
        if digits.len() > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        out.push('e');
        out.push(if exp < 0 { '-' } else { '+' });
        let abs_exp = exp.abs();
        if abs_exp < 10 {
            out.push('0');
        }
        out.push_str(&abs_exp.to_string());
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..(-decpt) {
            out.push('0');
        }
        out.push_str(&digits);
    } else if decpt as usize >= digits.len() {
        out.push_str(&digits);
        for _ in 0..(decpt as usize - digits.len()) {
            out.push('0');
        }
        out.push_str(".0");
    } else {
        let point = decpt as usize;
        out.push_str(&digits[..point]);
        out.push('.');
        out.push_str(&digits[point..]);
    }

    out
}

fn py_write_number(out: &mut String, n: &serde_json::Number) {
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
    } else if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
    } else if let Some(f) = n.as_f64() {
        out.push_str(&py_float_repr(f));
    }
}

fn py_newline_indent(out: &mut String, indent: usize, level: usize) {
    out.push('\n');
    for _ in 0..indent * level {
        out.push(' ');
    }
}

fn py_write_value(
    out: &mut String,
    v: &Value,
    ensure_ascii: bool,
    compact: bool,
    indent: Option<usize>,
    level: usize,
) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => py_write_number(out, n),
        Value::String(s) => py_write_string(out, s, ensure_ascii),
        Value::Array(arr) => {
            if arr.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, item) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    match indent {
                        Some(n) => py_newline_indent(out, n, level + 1),
                        None => {
                            if !compact {
                                out.push(' ');
                            }
                        }
                    }
                } else if let Some(n) = indent {
                    py_newline_indent(out, n, level + 1);
                }
                py_write_value(out, item, ensure_ascii, compact, indent, level + 1);
            }
            if let Some(n) = indent {
                py_newline_indent(out, n, level);
            }
            out.push(']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (key, val)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                    match indent {
                        Some(n) => py_newline_indent(out, n, level + 1),
                        None => {
                            if !compact {
                                out.push(' ');
                            }
                        }
                    }
                } else if let Some(n) = indent {
                    py_newline_indent(out, n, level + 1);
                }
                py_write_string(out, key, ensure_ascii);
                out.push(':');
                if compact {
                    // separators=(',', ':')
                } else {
                    out.push(' ');
                }
                py_write_value(out, val, ensure_ascii, compact, indent, level + 1);
            }
            if let Some(n) = indent {
                py_newline_indent(out, n, level);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(v, separators=(',', ':'), ensure_ascii=False)`
fn py_dumps_compact(v: &Value) -> String {
    let mut out = String::new();
    py_write_value(&mut out, v, false, true, None, 0);
    out
}

/// `json.dumps(v)`  (default separators `(', ', ': ')`, `ensure_ascii=True`)
fn py_dumps_default(v: &Value) -> String {
    let mut out = String::new();
    py_write_value(&mut out, v, true, false, None, 0);
    out
}

/// `json.dump(v, f, indent=4)`  (default separators, `ensure_ascii=True`)
fn py_dumps_indent(v: &Value) -> String {
    let mut out = String::new();
    py_write_value(&mut out, v, true, false, Some(4), 0);
    out
}

// ===========================================================================
// Ports of the Python helpers
// ===========================================================================

fn hmac_hex(key: &[u8], msg: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(msg);
    hex::encode(mac.finalize().into_bytes())
}

fn hmac_hex_upper(key: &[u8], msg: &[u8]) -> String {
    hmac_hex(key, msg).to_uppercase()
}

fn is_empty_container(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

/// Python `removeEmpty` only deletes falsy scalars that are *not* `False`/`0`.
fn is_removable_scalar(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        // `False` and `0` are explicitly kept, everything else non-empty is truthy.
        _ => false,
    }
}

/// `removeEmpty`: recursively drops empty dicts, empty lists, empty strings and
/// `None`. Keeps `false` and `0`. Mutates in place, like the Python original
/// (the caller reuses the same object, so the file receives the cleaned dict).
fn remove_empty(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            let mut remove: Vec<String> = Vec::new();
            for key in keys {
                let val = map.get_mut(&key).expect("key exists");
                if val.is_object() || val.is_array() {
                    if is_empty_container(val) {
                        remove.push(key);
                        continue;
                    }
                    remove_empty(val);
                    if is_empty_container(val) {
                        remove.push(key);
                    }
                } else if is_removable_scalar(val) {
                    remove.push(key);
                }
            }
            if !remove.is_empty() {
                // Rebuild instead of `Map::remove` to keep insertion order.
                let cleaned: Map<String, Value> = std::mem::take(map)
                    .into_iter()
                    .filter(|(k, _)| !remove.contains(k))
                    .collect();
                *map = cleaned;
            }
        }
        Value::Array(arr) => {
            // Mirrors Python's `for x, y in enumerate(d)` + `del d[x]` behaviour.
            let mut i = 0;
            while i < arr.len() {
                if arr[i].is_object() || arr[i].is_array() {
                    if is_empty_container(&arr[i]) {
                        arr.remove(i);
                        continue;
                    }
                    remove_empty(&mut arr[i]);
                    if is_empty_container(&arr[i]) {
                        arr.remove(i);
                        continue;
                    }
                } else if is_removable_scalar(&arr[i]) {
                    arr.remove(i);
                    continue;
                }
                i += 1;
            }
        }
        _ => {}
    }
}

/// `calculateHMAC`: HMAC-SHA256 over `sid + path + json.dumps(cleaned value)`,
/// uppercased. Like the Python version this mutates `value` by calling
/// `removeEmpty` on it first.
fn calculate_hmac(value: &mut Value, path: &str, sid: &str, seed: &[u8]) -> String {
    if value.is_object() {
        remove_empty(value);
    }
    let message = format!(
        "{sid}{path}{}",
        py_dumps_compact(value)
            .replace('<', "\\u003C")
            .replace("\\u2122", "\u{2122}")
    );
    hmac_hex_upper(seed, message.as_bytes())
}

/// `calc_supermac`: HMAC-SHA256 over `sid + json.dumps(protection.macs)` with
/// every space removed, uppercased. `macs` keeps its on-disk key order.
fn supermac_from_value(data: &Value, sid: &str, seed: &[u8]) -> String {
    let macs = data
        .get("protection")
        .and_then(|p| p.get("macs"))
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    let message = format!("{sid}{}", py_dumps_default(&macs).replace(' ', ""));
    hmac_hex_upper(seed, message.as_bytes())
}

/// `calc_supermac(json_file, sid, seed)`: reads the file back from disk, exactly
/// like the Python version does before stamping `super_mac`.
fn calc_supermac(json_file: &Path, sid: &str, seed: &[u8]) -> Result<String, Box<dyn Error>> {
    let data = read_json_preserve_order(json_file)?;
    Ok(supermac_from_value(&data, sid, seed))
}

/// `get_extension_id`: first 32 hex chars of sha256(utf-16-le path), each hex
/// digit mapped to `a`..`p`.
fn get_extension_id(path: &str) -> String {
    let mut hasher = Sha256::new();
    for unit in path.encode_utf16() {
        hasher.update(unit.to_le_bytes());
    }
    let digest = hex::encode(hasher.finalize());
    digest
        .chars()
        .take(32)
        .map(|c| {
            let d = c.to_digit(16).expect("hex digit");
            (b'a' + d as u8) as char
        })
        .collect()
}

/// `calculate_chrome_dev_mac`: HMAC-SHA256 over `sid + pref_path + json(value)`.
/// Note: the Python version does **not** uppercase this digest.
fn calculate_chrome_dev_mac(seed: &[u8], sid: &str, pref_path: &str, pref_value: &Value) -> String {
    let serialized_value = py_dumps_compact(pref_value);
    let message = format!("{sid}{pref_path}{serialized_value}");
    hmac_hex(seed, message.as_bytes())
}

/// `encode_to_install_time`: microseconds since 1601-01-01, using the *local*
/// wall clock (`datetime.datetime.now()` in the Python script).
fn encode_to_install_time_now() -> u64 {
    let now_local = chrono::Local::now().naive_local();
    let micros = now_local.and_utc().timestamp_micros();
    (micros as u64) + 11_644_473_600_000_000
}

/// `remove_keys_containing`: recursively drops every object key that contains
/// `substring`, preserving the order of the surviving keys.
fn remove_keys_containing(v: &mut Value, substring: &str) {
    match v {
        Value::Object(map) => {
            for val in map.values_mut() {
                remove_keys_containing(val, substring);
            }
            let cleaned: Map<String, Value> = std::mem::take(map)
                .into_iter()
                .filter(|(k, _)| !k.contains(substring))
                .collect();
            *map = cleaned;
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                remove_keys_containing(item, substring);
            }
        }
        _ => {}
    }
}

/// `clean_json_file(input_path, output_path, substring)`: load, clean, write
/// back with `indent=4`.
fn clean_json_file(path: &Path, substring: &str) -> Result<(), Box<dyn Error>> {
    let mut data = read_json_preserve_order(path)?;
    remove_keys_containing(&mut data, substring);
    std::fs::write(path, py_dumps_indent(&data))?;
    Ok(())
}

// ===========================================================================
// Small helpers
// ===========================================================================

fn read_json_preserve_order(path: &Path) -> Result<Value, Box<dyn Error>> {
    let mut bytes = std::fs::read(path)?;
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        bytes.drain(0..3);
    }
    Ok(serde_json::from_slice(&bytes)?)
}

/// Insert `val` at the nested object path, creating intermediate objects as
/// needed (the Python script relies on the `KeyError` handlers for this).
fn set_nested(root: &mut Value, path: &[&str], val: Value) {
    if path.is_empty() {
        *root = val;
        return;
    }
    if !root.is_object() {
        *root = Value::Object(Map::new());
    }
    let obj = root.as_object_mut().expect("object");
    let (head, tail) = path.split_first().expect("non-empty path");
    if tail.is_empty() {
        obj.insert((*head).to_string(), val);
    } else {
        if !obj.contains_key(*head) {
            obj.insert((*head).to_string(), Value::Object(Map::new()));
        }
        let child = obj.get_mut(*head).expect("object");
        set_nested(child, tail, val);
    }
}

/// `win32api.GetUserName()` + `LookupAccountName` + `ConvertSidToStringSid`,
/// reduced to just the SID string. Done via PowerShell so that the binary has no
/// pywin32-style dependency.
fn current_user_sid() -> Result<String, String> {
    let out = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
        ])
        .output()
        .map_err(|e| format!("failed to launch powershell.exe: {e}"))?;

    if !out.status.success() {
        return Err(format!(
            "powershell.exe failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    let sid = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if sid.is_empty() {
        return Err("powershell.exe returned an empty SID".to_string());
    }
    Ok(sid)
}

/// The extension settings blob, in the exact key order of `extension_json` in
/// the Python script.
fn build_extension(extpath: &str, encoded_install_time: u64) -> Value {
    let install_time = encoded_install_time.to_string();
    let mut m = Map::new();
    m.insert("account_extension_type".into(), json!(0));
    m.insert(
        "active_permissions".into(),
        json!({
            "api": ["cookies", "storage", "tabs", "scripting"],
            "explicit_host": ["<all_urls>"],
            "manifest_permissions": [],
            "scriptable_host": []
        }),
    );
    m.insert("commands".into(), json!({}));
    m.insert("content_settings".into(), json!([]));
    m.insert("creation_flags".into(), json!(38));
    m.insert("first_install_time".into(), json!(install_time));
    m.insert("from_webstore".into(), json!(false));
    m.insert(
        "granted_permissions".into(),
        json!({
            "api": ["cookies", "downloads", "storage", "tabs"],
            "explicit_host": ["<all_urls>"],
            "manifest_permissions": [],
            "scriptable_host": []
        }),
    );
    m.insert("incognito".into(), json!(true));
    m.insert("incognito_content_settings".into(), json!([]));
    m.insert("incognito_preferences".into(), json!({}));
    m.insert("last_update_time".into(), json!(install_time));
    m.insert("location".into(), json!(4));
    m.insert("newAllowFileAccess".into(), json!(true));
    m.insert("path".into(), json!(extpath));
    m.insert("preferences".into(), json!({}));
    m.insert("regular_only_preferences".into(), json!({}));
    m.insert(
        "service_worker_registration_info".into(),
        json!({ "version": "1.0" }),
    );
    m.insert("serviceworkerevents".into(), json!(["tabs.onUpdated"]));
    m.insert("was_installed_by_default".into(), json!(false));
    m.insert("was_installed_by_oem".into(), json!(false));
    m.insert("withholding_permissions".into(), json!(false));
    Value::Object(m)
}

// ===========================================================================
// add_extension() — same statement order as the Python function
// ===========================================================================

fn add_extension(extpath: &str, profile_dir: &Path) -> Result<(), Box<dyn Error>> {
    let seed = seed_bytes();

    // --- SID: current user, final "-" section removed --------------------
    let sid_string = current_user_sid()?;
    println!("Current user SID: {sid_string}");
    let mut sid = String::new();
    let pieces: Vec<&str> = sid_string.split('-').collect();
    for (i, piece) in pieces.iter().enumerate() {
        if i != pieces.len() - 1 {
            sid.push_str(piece);
            sid.push('-');
        }
    }
    sid.pop(); // the Python code strips the trailing '-'
    println!("Sid is {sid}");

    // --- extension id ---------------------------------------------------
    let extensionid = get_extension_id(extpath);
    println!("Using ExtID: {extensionid}");

    // --- install time ---------------------------------------------------
    let encoded_install_time = encode_to_install_time_now();

    // --- dict_extension = json.loads(extension_json) --------------------
    let mut dict_extension = build_extension(extpath, encoded_install_time);
    {
        let obj = dict_extension.as_object_mut().expect("object");
        obj.insert("path".into(), json!(extpath));
    }

    // --- load the Secure Preferences file -------------------------------
    let filepath = profile_dir.join("Secure Preferences");
    let mut data = read_json_preserve_order(&filepath)?;

    // --- data["protection"]["macs"]["extensions"]["settings"][id] = macs -
    // Python inserts dict_extension first and then computes the MAC on that
    // same (mutated) object, so the file gets the cleaned dict.
    let path = format!("extensions.settings.{extensionid}");
    let macs = calculate_hmac(&mut dict_extension, &path, &sid, &seed);

    set_nested(
        &mut data,
        &["extensions", "settings", extensionid.as_str()],
        dict_extension,
    );
    set_nested(
        &mut data,
        &[
            "protection",
            "macs",
            "extensions",
            "settings",
            extensionid.as_str(),
        ],
        json!(macs),
    );

    // --- account_values.extensions.ui.developer_mode = True -------------
    println!("Checking if signed in account, setting developer mode to true if it is...");
    set_nested(
        &mut data,
        &["account_values", "extensions", "ui", "developer_mode"],
        json!(true),
    );

    // --- initial_mac for the account path (uppercased) ------------------
    let initial_pref_path = "account_values.extensions.ui.developer_mode";
    let initial_mac = calculate_chrome_dev_mac(&seed, &sid, initial_pref_path, &json!(true));
    set_nested(
        &mut data,
        &[
            "protection",
            "macs",
            "account_values",
            "extensions",
            "ui",
            "developer_mode",
        ],
        json!(initial_mac.to_uppercase()),
    );

    // --- extensions.ui.developer_mode = True ----------------------------
    set_nested(
        &mut data,
        &["extensions", "ui", "developer_mode"],
        json!(true),
    );

    let pref_path = "extensions.ui.developer_mode";
    let mac = calculate_chrome_dev_mac(&seed, &sid, pref_path, &json!(true));
    set_nested(
        &mut data,
        &["protection", "macs", "extensions", "ui", "developer_mode"],
        json!(mac),
    );

    // --- write, then recompute super_mac from the file, then write again -
    std::fs::write(&filepath, py_dumps_default(&data))?;

    let supermac = calc_supermac(&filepath, &sid, &seed)?;
    set_nested(&mut data, &["protection", "super_mac"], json!(supermac));
    std::fs::write(&filepath, py_dumps_default(&data))?;

    // --- clean_json_file(filepath, filepath, '_encrypted_hash') ---------
    clean_json_file(&filepath, "_encrypted_hash")?;

    Ok(())
}

// ===========================================================================
// CLI
// ===========================================================================

struct Args {
    extension_path: String,
    profile_dir: PathBuf,
}

fn parse_args() -> Result<Args, Box<dyn Error>> {
    let mut extension_path: Option<String> = None;
    let mut profile_dir: Option<PathBuf> = None;

    let mut it = env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            "-e" | "--extension-path" => {
                extension_path = Some(it.next().ok_or("missing value for --extension-path")?);
            }
            "-p" | "--profile-dir" => {
                profile_dir = Some(PathBuf::from(
                    it.next().ok_or("missing value for --profile-dir")?,
                ));
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    Ok(Args {
        extension_path: extension_path.ok_or("missing required --extension-path")?,
        profile_dir: profile_dir.ok_or("missing required --profile-dir")?,
    })
}

fn print_help() {
    println!("silent_chrome_rs — Rust port of windows_silent_chrome.py");
    println!();
    println!("USAGE:");
    println!("  silent_chrome_rs --extension-path <EXT_DIR> --profile-dir <PROFILE_DIR>");
    println!();
    println!("ARGS:");
    println!("  -e, --extension-path <PATH>  Path to the unpacked extension directory (no trailing slash).");
    println!("                               Replaces the hardcoded `extpath` in the Python script.");
    println!("  -p, --profile-dir <DIR>      Profile directory containing 'Secure Preferences'.");
    println!("                               Replaces the hardcoded ...\\Google\\Chrome\\User Data\\Default path.");
    println!("  -h, --help                   Show this help.");
}

fn run() -> Result<(), Box<dyn Error>> {
    let args = parse_args()?;
    add_extension(&args.extension_path, &args.profile_dir)?;
    println!("Extension added!");
    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

// ===========================================================================
// Tests — expected values produced by running windows_silent_chrome.py itself
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PATH: &str = r"C:\tmp\myext";
    const TEST_SID: &str = "S-1-5-21-123456789-1234567890-1234567890";
    const TEST_INSTALL_TIME: u64 = 13359596405266074;

    #[test]
    fn extension_id_matches_python() {
        assert_eq!(
            get_extension_id(TEST_PATH),
            "fidoccbgmgndpddneoipnmaablafjnld"
        );
    }

    /// `calculateHMAC(dict_extension, "extensions.settings.<id>", sid, seed)`
    #[test]
    fn extension_mac_matches_python() {
        let seed = seed_bytes();
        let extid = get_extension_id(TEST_PATH);
        let mut ext = build_extension(TEST_PATH, TEST_INSTALL_TIME);
        let mac_path = format!("extensions.settings.{extid}");
        let mac = calculate_hmac(&mut ext, &mac_path, TEST_SID, &seed);
        assert_eq!(
            mac,
            "6FA94D671CEA33177406F21499238D19C8B0E6914A0B2E9523882A60E8675D7B"
        );
    }

    /// After `calculateHMAC` the blob must have lost its empty containers.
    #[test]
    fn extension_blob_matches_python_remove_empty() {
        let seed = seed_bytes();
        let extid = get_extension_id(TEST_PATH);
        let mut ext = build_extension(TEST_PATH, TEST_INSTALL_TIME);
        calculate_hmac(
            &mut ext,
            &format!("extensions.settings.{extid}"),
            TEST_SID,
            &seed,
        );
        // Note: `<` is only escaped inside the HMAC message, not in the stored JSON.
        assert_eq!(
            py_dumps_compact(&ext),
            r#"{"account_extension_type":0,"active_permissions":{"api":["cookies","storage","tabs","scripting"],"explicit_host":["<all_urls>"]},"creation_flags":38,"first_install_time":"13359596405266074","from_webstore":false,"granted_permissions":{"api":["cookies","downloads","storage","tabs"],"explicit_host":["<all_urls>"]},"incognito":true,"last_update_time":"13359596405266074","location":4,"newAllowFileAccess":true,"path":"C:\\tmp\\myext","service_worker_registration_info":{"version":"1.0"},"serviceworkerevents":["tabs.onUpdated"],"was_installed_by_default":false,"was_installed_by_oem":false,"withholding_permissions":false}"#
        );
    }

    /// `calculate_chrome_dev_mac(...)` — account variant is uppercased by the
    /// caller, the `extensions.ui` variant stays lowercase.
    #[test]
    fn dev_macs_match_python() {
        let seed = seed_bytes();
        let dev = calculate_chrome_dev_mac(
            &seed,
            TEST_SID,
            "extensions.ui.developer_mode",
            &json!(true),
        );
        assert_eq!(
            dev,
            "00f383e1064ddd3a3b4d25c28cd4e2a7c09e6531cabeca2958ed1275482d1039"
        );

        let account = calculate_chrome_dev_mac(
            &seed,
            TEST_SID,
            "account_values.extensions.ui.developer_mode",
            &json!(true),
        )
        .to_uppercase();
        assert_eq!(
            account,
            "DEF66AE6CF55970C05BE5A319AF27DDA23840AF06883FFD75856D38E01600338"
        );
    }

    /// `calc_supermac` — `sid + json.dumps(macs).replace(" ", "")`, uppercased.
    #[test]
    fn super_mac_matches_python() {
        let seed = seed_bytes();
        let mut data = json!({
            "protection": { "macs": {}, "super_mac": "" }
        });
        set_nested(
            &mut data,
            &["protection", "macs", "extensions", "settings"],
            json!({}),
        );
        set_nested(
            &mut data,
            &["protection", "macs", "extensions", "settings", "fidoccbgmgndpddneoipnmaablafjnld"],
            json!("6FA94D671CEA33177406F21499238D19C8B0E6914A0B2E9523882A60E8675D7B"),
        );
        set_nested(
            &mut data,
            &["protection", "macs", "extensions", "ui", "developer_mode"],
            json!("00f383e1064ddd3a3b4d25c28cd4e2a7c09e6531cabeca2958ed1275482d1039"),
        );
        set_nested(
            &mut data,
            &[
                "protection",
                "macs",
                "account_values",
                "extensions",
                "ui",
                "developer_mode",
            ],
            json!("DEF66AE6CF55970C05BE5A319AF27DDA23840AF06883FFD75856D38E01600338"),
        );

        assert_eq!(
            supermac_from_value(&data, TEST_SID, &seed),
            "5FBD448CBF40974C1E95A351AEE9C66D91A82872F7F3BADB6FC84F0EE41EEA5F"
        );
    }

    /// The three `json.dumps` flavours must byte-match Python's output.
    #[test]
    fn json_flavours_match_python() {
        let v: Value = serde_json::from_str(r#"{"b":1,"a":[1,{}],"c":""}"#).unwrap();
        assert_eq!(py_dumps_compact(&v), r#"{"b":1,"a":[1,{}],"c":""}"#);
        assert_eq!(py_dumps_default(&v), r#"{"b": 1, "a": [1, {}], "c": ""}"#);
        assert_eq!(
            py_dumps_indent(&v),
            "{\n    \"b\": 1,\n    \"a\": [\n        1,\n        {}\n    ],\n    \"c\": \"\"\n}"
        );
    }

    /// Regression test for the float-formatting bug the parity checker found:
    /// Rust's `{}` prints `1e20` as `100000000000000000000`, Python as `1e+20`.
    /// Expected strings below are `json.dumps(x)` from CPython.
    #[test]
    fn float_formatting_matches_python() {
        let cases: &[(f64, &str)] = &[
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (0.5, "0.5"),
            (1.0, "1.0"),
            (3.141592653589793, "3.141592653589793"),
            (1e-7, "1e-07"),
            (1e-4, "0.0001"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1e20, "1e+20"),
            (1.5e20, "1.5e+20"),
            (1e300, "1e+300"),
            (1e-300, "1e-300"),
            (12345678901234567.0, "1.2345678901234568e+16"),
            (-2.5, "-2.5"),
        ];
        for (value, expected) in cases {
            assert_eq!(&py_float_repr(*value), expected, "value: {value}");
        }
    }
}
