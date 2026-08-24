# Changelog

## 0.3.1 (2026-08-24)

- **Fix**: read and write the inner-header Binary field using the KeePass/KeePassXC
  standard layout `[flags(1)][data...]` (field length covers everything, no embedded
  length). 0.3.0 misread the first four attachment bytes as an embedded length and
  rejected real KeePass/KeePassXC databases containing attachments with
  "Database file is corrupted"; exports also carried a phantom length that other
  readers would treat as attachment data. Verified against the KeePassXC
  reader/writer implementation.

## 0.3.0 (2026-08-24)

- **Fix**: publish `kdbx_wasm_bg.js` in the npm package — the bundler entry re-exported it, breaking bundler builds
- **Fix**: write `<Expires>` inside `<Times>` per the KDBX spec; expiry set in KeePass/KeePassXC is now parsed (and preserved) correctly
- **Fix**: inner-header binary flag `0x01` now treated as "protect in memory" (was wrongly gzip-decompressed, corrupting protected attachments)
- **Fix**: entry `<Binary>` references are parsed and re-emitted, so attachments stay linked to their entries after a round-trip
- **Fix**: empty `Password` values no longer leak into `customFields["Password"]`
- **Fix**: reject malformed header/KDF/data-stream lengths before allocating (no more panics or oversized allocations on corrupt files); cap decompressed size and group nesting depth
- **Security**: every export now regenerates master seed, KDF salt, encryption IV, and inner stream key instead of reusing the parsed file's values
- **Added**: KeePass-style XML key files (v1.00/v2.0) and 64-char hex key files are supported
- **Added**: deleting the root group is rejected
- **Changed**: `getEntries`/`getGroups`/`getChildGroups` return stable, sorted order
- **Changed**: `getFileInfo` only reads the file header (no full copy); reported version uses the real header version (4.0/4.1)
- **Changed**: `engines.node` raised to `>=19` (WASM randomness requires the global `crypto`)
- **Changed**: moved test fixture to `tests/fixtures/`, enabled fixture-based integration tests, added Node smoke tests
- **Chore**: commit `Cargo.lock` for reproducible WASM builds; drop unused dependencies (`tracing`, `serde_json`, `web-sys`)

### Breaking: unified ESM-only package layout

- The npm package is now ESM-only (`"type": "module"`); `require('kdbx-wasm')` no longer works — use `import` (Node 19+)
- Removed the `web/` and `nodejs/` subpath targets and the separate bundler entry; a single `kdbx_wasm.js` binding (fetch-based `init()`) serves browsers and bundlers, and a small Node ESM entry (`index.js`) loads the same module synchronously via `initSync` + `fs.readFileSync` — no init call needed on Node
- Only one copy of the WASM binary is shipped (was three identical copies); unpacked package size roughly halved
- Old `initKdbxWasm()`/`start()` exports are gone; browser users call the default export `init()` once

## 0.2.1

- Fixed repository URL format in package metadata

## 0.1.6

- Fixed WASM serialization bugs

## 0.2.0

- Rebuilt WASM binaries to fix Custom Fields parsing
- Added entry/group/metadata mutations (`createEntry`, `deleteEntry`, `setEntryCustomField`, `createGroup`, etc.)
- Added advanced search (`searchEntriesAdvanced`) and child group queries (`getChildGroups`)
- Verified with real-world KDBX database (38 entries / 8 groups / 22 entries with custom fields)

## 0.1.5

- Restructured project into Cargo workspace:
  - `crates/kdbx-core` — core KDBX parser library
  - `crates/kdbx-wasm` — wasm-bindgen bindings
  - `packages/kdbx-wasm` — npm package
- Removed server-side REST API code to focus on WASM/JS library
- Rebuilt WASM binaries to fix Custom Fields parsing
- Added entry/group/metadata mutations (`createEntry`, `deleteEntry`, `setEntryCustomField`, `createGroup`, etc.)
- Added advanced search (`searchEntriesAdvanced`) and child group queries (`getChildGroups`)
- Verified with real-world KDBX database (38 entries / 8 groups / 22 entries with custom fields)

## 0.1.1

- Initial release
- KDBX 4 parse and export
- AES-256 / ChaCha20 encryption
- Argon2 / AES-KDF key derivation
