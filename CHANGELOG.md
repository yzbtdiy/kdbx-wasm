# Changelog

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
