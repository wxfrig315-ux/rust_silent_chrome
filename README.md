# rust_silent_chrome

A Rust port of [`windows_silent_chrome.py`](https://github.com/asaurusrex/Silent_Chrome)
that silently installs an unpacked Chromium extension on Windows by patching the
browser's `Secure Preferences` file.

It inserts the extension entry, computes the HMAC-SHA256 protection values Chrome
expects, enables developer mode, recomputes the `super_mac`, and strips the
`*_encrypted_hash` authenticators — all without touching the browser UI.

The extension directory and the profile directory are command-line arguments;
nothing is hardcoded.

## Build

```sh
cargo build --release
```

Produces `target/release/silent_chrome_rs.exe`.

## Usage

```sh
silent_chrome_rs --extension-path <EXT_DIR> --profile-dir <PROFILE_DIR>
```

| Flag | Description |
| --- | --- |
| `-e, --extension-path <PATH>` | Path to the unpacked extension directory (no trailing slash). |
| `-p, --profile-dir <DIR>` | Profile directory that contains `Secure Preferences`. |
| `-h, --help` | Show help. |

Example (Google Chrome):

```powershell
.\target\release\silent_chrome_rs.exe `
  --extension-path "C:\path\to\my-extension" `
  --profile-dir    "C:\Users\<you>\AppData\Local\Google\Chrome\User Data\Default"
```

The browser must be **closed** while this runs — otherwise it rewrites
`Secure Preferences` from memory on exit and the change is lost.

Expected output:

```
Current user SID: S-1-5-21-...-1001
Sid is S-1-5-21-...
Using ExtID: gkcmbgloaoijmdbgfgaamdmjoaiknmfp
Checking if signed in account, setting developer mode to true if it is...
Extension added!
```

## How it works

1. **Extension ID** — first 32 hex chars of `sha256(utf16le(ext_path))`, each
   nibble mapped to `a`..`p` (Chromium's unpacked-extension ID scheme).
2. **Extension blob** — a fixed settings object (`location: 4` = unpacked,
   `creation_flags: 38`, install/update timestamps as microseconds since
   1601-01-01) pruned of empty containers, exactly like the reference script.
3. **Per-preference MAC** — `HMAC-SHA256(seed, sid + path + canonical_json(value))`.
4. **Developer mode MAC** — `HMAC-SHA256(seed, sid + "extensions.ui.developer_mode" + "true")`.
5. **super_mac** — `HMAC-SHA256(seed, sid + json(protection.macs))` with spaces removed.
6. **Cleanup** — every key containing `_encrypted_hash` is removed and the file
   is rewritten with `indent=4`.

The protection seed is Google Chrome's fixed 64-byte Windows key.

## Scope / limitations

- **Chrome only.** The hardcoded seed is Chrome's. Microsoft Edge, Brave, Chromium
  and Opera validate preferences with a different (empty) key, so they reject
  entries signed this way — they will drop the extension on next launch.
- The browser must be closed during the write.
- Requires a Windows user profile whose `Secure Preferences` already contains a
  `protection.macs` node (i.e. the browser has been run at least once).
- The current user's SID is resolved through PowerShell
  (`WindowsIdentity::GetCurrent().User.Value`), so no native `pywin32` equivalent
  is needed.

## Tests

```sh
cargo test
```

Covers the extension-ID derivation, the per-preference and developer-mode MACs,
the `super_mac` computation, the empty-container pruning order, and the
Python-compatible JSON serialisation (including float formatting).

## Credits

Algorithm and original Python implementation:
[`asaurusrex/Silent_Chrome`](https://github.com/asaurusrex/Silent_Chrome),
which in turn credits Nicholas Murray and Colby Morgan.
